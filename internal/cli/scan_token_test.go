package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenEndpointNotJSONRisk(t *testing.T) {
	server := newTokenHeuristicServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "error=invalid_grant")
	})
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "TOKEN_RESPONSE_NOT_JSON_RISK") {
		t.Fatalf("expected TOKEN_RESPONSE_NOT_JSON_RISK finding")
	}
	if hasFinding(report.Findings, "TOKEN_HTTP200_ERROR_PAYLOAD_RISK") {
		t.Fatalf("did not expect TOKEN_HTTP200_ERROR_PAYLOAD_RISK finding")
	}
	if step := findStep(report.Steps, 5); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 5 to fail, got %+v", step)
	}
}

func TestTokenEndpointHTTP200ErrorPayloadRisk(t *testing.T) {
	server := newTokenHeuristicServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	})
	defer server.Close()

	report := runScanForServer(t, server.URL+"/mcp")

	if !hasFinding(report.Findings, "TOKEN_HTTP200_ERROR_PAYLOAD_RISK") {
		t.Fatalf("expected TOKEN_HTTP200_ERROR_PAYLOAD_RISK finding")
	}
	if hasFinding(report.Findings, "TOKEN_RESPONSE_NOT_JSON_RISK") {
		t.Fatalf("did not expect TOKEN_RESPONSE_NOT_JSON_RISK finding")
	}
	if step := findStep(report.Steps, 5); step == nil || step.Status != "FAIL" {
		t.Fatalf("expected step 5 to fail, got %+v", step)
	}
}

func newTokenHeuristicServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	baseURL := server.URL

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, baseURL))
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              baseURL + "/mcp",
			"authorization_servers": []string{baseURL + "/issuer"},
		})
	})
	mux.HandleFunc("/issuer/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL + "/issuer",
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
		})
	})
	mux.HandleFunc("/token", tokenHandler)

	return server
}

func runScanForServer(t *testing.T, target string) scanReport {
	t.Helper()
	var stdout bytes.Buffer
	report, _, err := runScanFunnel(scanConfig{
		Target:              target,
		Profile:             "generic",
		Timeout:             5 * time.Second,
		RFC9728Mode:         "best-effort",
		AllowPrivateIssuers: true,
	}, &stdout)
	if err != nil {
		t.Fatalf("runScanFunnel error: %v", err)
	}
	if report.PrimaryFinding.Code == "" {
		t.Fatalf("expected a primary finding, got none")
	}
	return report
}

func hasFinding(findings []finding, code string) bool {
	for _, item := range findings {
		if item.Code == code {
			return true
		}
	}
	return false
}

func findStep(steps []scanStep, id int) *scanStep {
	for i := range steps {
		if steps[i].ID == id {
			return &steps[i]
		}
	}
	return nil
}
