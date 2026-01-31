package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeMCPAuthRequiredWithResourceMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if accept := r.Header.Get("Accept"); accept != "text/event-stream" {
			t.Errorf("expected Accept header to be text/event-stream, got %q", accept)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	trace := []traceEntry{}
	resourceMetadata, resolvedTarget, findings, evidence, authRequired, err := probeMCP(&http.Client{}, scanConfig{Target: server.URL}, &trace, &stdout)
	if err != nil {
		t.Fatalf("probeMCP returned error: %v", err)
	}
	if resourceMetadata != "https://example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("expected resource metadata, got %q", resourceMetadata)
	}
	if resolvedTarget != server.URL {
		t.Fatalf("expected resolved target %q, got %q", server.URL, resolvedTarget)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
	if evidence != "401 with resource_metadata" {
		t.Fatalf("expected evidence for 401 with resource_metadata, got %q", evidence)
	}
	if !authRequired {
		t.Fatalf("expected authRequired true")
	}
	if len(trace) != 1 {
		t.Fatalf("expected trace to include probe request, got %d entries", len(trace))
	}
}

func TestProbeMCPAuthNotRequiredSkipsAuthChecks(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if accept := r.Header.Get("Accept"); accept != "text/event-stream" {
			t.Errorf("expected Accept header to be text/event-stream, got %q", accept)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	trace := []traceEntry{}
	resourceMetadata, resolvedTarget, findings, evidence, authRequired, err := probeMCP(&http.Client{}, scanConfig{Target: server.URL}, &trace, &stdout)
	if err != nil {
		t.Fatalf("probeMCP returned error: %v", err)
	}
	if resourceMetadata != "" {
		t.Fatalf("expected empty resource metadata, got %q", resourceMetadata)
	}
	if resolvedTarget != server.URL {
		t.Fatalf("expected resolved target %q, got %q", server.URL, resolvedTarget)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
	if evidence != "auth not required" {
		t.Fatalf("expected evidence to indicate auth not required, got %q", evidence)
	}
	if authRequired {
		t.Fatalf("expected authRequired false")
	}
	if len(trace) != 1 {
		t.Fatalf("expected trace to include probe request, got %d entries", len(trace))
	}
}
