package cli

import (
	"errors"
	"testing"
)

func TestIssuerIdentifierComparison(t *testing.T) {
	cases := []struct {
		name      string
		expected  string
		actual    string
		wantEqual bool
	}{
		{
			name:      "google-root-slash-equivalence",
			expected:  "https://accounts.google.com/",
			actual:    "https://accounts.google.com",
			wantEqual: true,
		},
		{
			name:      "non-root-path-strict",
			expected:  "https://accounts.google.com",
			actual:    "https://accounts.google.com/tenant",
			wantEqual: false,
		},
		{
			name:      "non-root-trailing-slash-strict",
			expected:  "https://example.com/tenant",
			actual:    "https://example.com/tenant/",
			wantEqual: false,
		},
		{
			name:      "scheme-mismatch",
			expected:  "https://accounts.google.com",
			actual:    "http://accounts.google.com",
			wantEqual: false,
		},
		{
			name:      "host-mismatch",
			expected:  "https://accounts.google.com",
			actual:    "https://evil.com",
			wantEqual: false,
		},
		{
			name:      "default-port-https",
			expected:  "https://example.com",
			actual:    "https://example.com:443",
			wantEqual: true,
		},
		{
			name:      "default-port-http",
			expected:  "http://example.com",
			actual:    "http://example.com:80",
			wantEqual: true,
		},
		{
			name:      "non-default-port",
			expected:  "https://example.com",
			actual:    "https://example.com:444",
			wantEqual: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectedCanonical, err := canonicalizeIssuerIdentifier(tc.expected)
			if err != nil {
				t.Fatalf("expected issuer canonicalization failed: %v", err)
			}
			actualCanonical, err := canonicalizeIssuerIdentifier(tc.actual)
			if err != nil {
				t.Fatalf("actual issuer canonicalization failed: %v", err)
			}
			if (expectedCanonical == actualCanonical) != tc.wantEqual {
				t.Fatalf("comparison = %v, want %v (expected=%q actual=%q)", expectedCanonical == actualCanonical, tc.wantEqual, expectedCanonical, actualCanonical)
			}
		})
	}
}

func TestCanonicalizeIssuerIdentifierRejectsQueryFragment(t *testing.T) {
	cases := []string{
		"https://accounts.google.com?query=1",
		"https://accounts.google.com#fragment",
		"https://accounts.google.com/path?query=1",
		"https://accounts.google.com/path#fragment",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := canonicalizeIssuerIdentifier(raw)
			if err == nil {
				t.Fatalf("expected error for %q", raw)
			}
			if !errors.Is(err, errIssuerQueryFragment) {
				t.Fatalf("expected errIssuerQueryFragment for %q, got %v", raw, err)
			}
		})
	}
}
