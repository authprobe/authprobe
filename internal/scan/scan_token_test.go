package scan

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
		t.Fatalf("expected TOKEN_RESPONSE_NOT_JSON_RISK Finding")
	}
	if hasFinding(report.Findings, "TOKEN_HTTP200_ERROR_PAYLOAD_RISK") {
		t.Fatalf("did not expect TOKEN_HTTP200_ERROR_PAYLOAD_RISK Finding")
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
		t.Fatalf("expected TOKEN_HTTP200_ERROR_PAYLOAD_RISK Finding")
	}
	if hasFinding(report.Findings, "TOKEN_RESPONSE_NOT_JSON_RISK") {
		t.Fatalf("did not expect TOKEN_RESPONSE_NOT_JSON_RISK Finding")
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
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
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

func runScanForServer(t *testing.T, target string) ScanReport {
	t.Helper()
	var stdout bytes.Buffer
	var verbose bytes.Buffer
	report, _, err := RunScanFunnel(ScanConfig{
		Target:              target,
		Timeout:             5 * time.Second,
		MCPMode:             "best-effort",
		RFCMode:             "best-effort",
		AllowPrivateIssuers: true,
		Insecure:            true,
	}, &stdout, &verbose)
	if err != nil {
		t.Fatalf("RunScanFunnel error: %v", err)
	}
	return report
}

func hasFinding(findings []Finding, code string) bool {
	for _, item := range findings {
		if item.Code == code {
			return true
		}
	}
	return false
}

func findFinding(findings []Finding, code string) *Finding {
	for i := range findings {
		if findings[i].Code == code {
			return &findings[i]
		}
	}
	return nil
}

func findStep(steps []ScanStep, id int) *ScanStep {
	for i := range steps {
		if steps[i].ID == id {
			return &steps[i]
		}
	}
	return nil
}
