package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNegotiateMCPVersion_RetriesWithHighestCompatibleVersion(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		params, _ := req["params"].(map[string]any)
		gotVersion, _ := params["protocolVersion"].(string)

		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"error": map[string]any{
					"code":    -32602,
					"message": "Unsupported protocol version. Supported versions: 2025-02-14, 2025-06-18",
					"data": map[string]any{
						"supportedVersions": []string{"2025-02-14", "2025-06-18"},
					},
				},
			})
			return
		}

		if gotVersion != "2025-06-18" {
			t.Fatalf("expected retry with 2025-06-18, got %q", gotVersion)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  map[string]any{"protocolVersion": "2025-06-18"},
		})
	}))
	defer server.Close()

	version, err := NegotiateMCPVersion(&Client{HTTPClient: server.Client()}, server.URL)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if version != "2025-06-18" {
		t.Fatalf("expected negotiated version 2025-06-18, got %q", version)
	}
	if calls != 2 {
		t.Fatalf("expected 2 initialize calls, got %d", calls)
	}
}

func TestNegotiateMCPVersion_NoCompatibleVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"error": map[string]any{
				"code":    -32602,
				"message": "Unsupported protocol version. Supported versions: 2026-01-01",
				"data": map[string]any{
					"supportedVersions": []string{"2026-01-01"},
				},
			},
		})
	}))
	defer server.Close()

	_, err := NegotiateMCPVersion(&Client{HTTPClient: server.Client()}, server.URL)
	if err == nil {
		t.Fatal("expected incompatible-version error, got nil")
	}
}
