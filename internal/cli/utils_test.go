package cli

import (
	"errors"
	"net/url"
	"testing"
)

func TestBuildPRMCandidates(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		resourceMetadata string
		wantCandidates   []prmCandidate
		wantHasPath      bool
		wantErr          bool
	}{
		{
			name:             "simple host without path",
			target:           "https://api.example.com",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
			},
			wantHasPath: false,
			wantErr:     false,
		},
		{
			name:             "host with trailing slash",
			target:           "https://api.example.com/",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
			},
			wantHasPath: false,
			wantErr:     false,
		},
		{
			name:             "host with path",
			target:           "https://api.example.com/mcp",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "host with nested path",
			target:           "https://api.example.com/v1/mcp/endpoint",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp/endpoint", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "host with path and trailing slash",
			target:           "https://api.example.com/mcp/",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "with resource_metadata absolute URL",
			target:           "https://api.example.com/mcp",
			resourceMetadata: "https://auth.example.com/.well-known/oauth-protected-resource",
			wantCandidates: []prmCandidate{
				{URL: "https://auth.example.com/.well-known/oauth-protected-resource", Source: "resource_metadata"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "with resource_metadata relative URL",
			target:           "https://api.example.com/mcp",
			resourceMetadata: "/.well-known/oauth-protected-resource/mcp",
			// Note: path-suffix is still added even if it matches resource_metadata
			// because the duplicate check only compares against rootURL
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "resource_metadata"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "with query string in target",
			target:           "https://api.example.com/mcp?foo=bar",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "with port number",
			target:           "https://api.example.com:8443/mcp",
			resourceMetadata: "",
			wantCandidates: []prmCandidate{
				{URL: "https://api.example.com:8443/.well-known/oauth-protected-resource", Source: "root"},
				{URL: "https://api.example.com:8443/.well-known/oauth-protected-resource/mcp", Source: "path-suffix"},
			},
			wantHasPath: true,
			wantErr:     false,
		},
		{
			name:             "invalid URL",
			target:           "://invalid",
			resourceMetadata: "",
			wantCandidates:   nil,
			wantHasPath:      false,
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates, hasPath, err := buildPRMCandidates(tt.target, tt.resourceMetadata)

			if tt.wantErr {
				if err == nil {
					t.Errorf("buildPRMCandidates() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("buildPRMCandidates() unexpected error: %v", err)
				return
			}

			if hasPath != tt.wantHasPath {
				t.Errorf("buildPRMCandidates() hasPath = %v, want %v", hasPath, tt.wantHasPath)
			}

			if len(candidates) != len(tt.wantCandidates) {
				t.Errorf("buildPRMCandidates() got %d candidates, want %d", len(candidates), len(tt.wantCandidates))
				for i, c := range candidates {
					t.Logf("  got[%d]: %s (%s)", i, c.URL, c.Source)
				}
				for i, c := range tt.wantCandidates {
					t.Logf("  want[%d]: %s (%s)", i, c.URL, c.Source)
				}
				return
			}

			for i, want := range tt.wantCandidates {
				got := candidates[i]
				if got.URL != want.URL {
					t.Errorf("candidate[%d].URL = %q, want %q", i, got.URL, want.URL)
				}
				if got.Source != want.Source {
					t.Errorf("candidate[%d].Source = %q, want %q", i, got.Source, want.Source)
				}
			}
		})
	}
}

func TestBuildPathSuffixCandidate(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		wantURL     string
		wantHasPath bool
	}{
		{
			name:        "no path",
			target:      "https://api.example.com",
			wantURL:     "",
			wantHasPath: false,
		},
		{
			name:        "root path only",
			target:      "https://api.example.com/",
			wantURL:     "",
			wantHasPath: false,
		},
		{
			name:        "simple path",
			target:      "https://api.example.com/mcp",
			wantURL:     "https://api.example.com/.well-known/oauth-protected-resource/mcp",
			wantHasPath: true,
		},
		{
			name:        "path with trailing slash",
			target:      "https://api.example.com/mcp/",
			wantURL:     "https://api.example.com/.well-known/oauth-protected-resource/mcp",
			wantHasPath: true,
		},
		{
			name:        "nested path",
			target:      "https://api.example.com/v1/services/mcp",
			wantURL:     "https://api.example.com/.well-known/oauth-protected-resource/v1/services/mcp",
			wantHasPath: true,
		},
		{
			name:        "path with query string",
			target:      "https://api.example.com/mcp?version=1",
			wantURL:     "https://api.example.com/.well-known/oauth-protected-resource/mcp",
			wantHasPath: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.target)
			if err != nil {
				t.Fatalf("failed to parse target URL: %v", err)
			}

			gotURL, gotHasPath := buildPathSuffixCandidate(parsed)

			if gotHasPath != tt.wantHasPath {
				t.Errorf("buildPathSuffixCandidate() hasPath = %v, want %v", gotHasPath, tt.wantHasPath)
			}

			if gotURL != tt.wantURL {
				t.Errorf("buildPathSuffixCandidate() URL = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestBuildRFC8414DiscoveryURL(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{
			name:   "issuer with path",
			issuer: "https://github.com/login/oauth",
			want:   "https://github.com/.well-known/oauth-authorization-server/login/oauth",
		},
		{
			name:   "issuer without path",
			issuer: "https://as.example.com",
			want:   "https://as.example.com/.well-known/oauth-authorization-server",
		},
		{
			name:   "issuer with trailing slash",
			issuer: "https://github.com/login/oauth/",
			want:   "https://github.com/.well-known/oauth-authorization-server/login/oauth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildRFC8414DiscoveryURL(tt.issuer)
			if err != nil {
				t.Fatalf("buildRFC8414DiscoveryURL() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("buildRFC8414DiscoveryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildRFC8414DiscoveryURLErrorOnQuery(t *testing.T) {
	_, err := buildRFC8414DiscoveryURL("https://example.com/issuer?foo=bar")
	if !errors.Is(err, errIssuerQueryFragment) {
		t.Fatalf("expected errIssuerQueryFragment, got %v", err)
	}
}
