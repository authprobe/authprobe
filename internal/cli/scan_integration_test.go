package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanComputeMCPVerbose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network scan in short mode")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "https://compute.googleapis.com/mcp", "--verbose", "--fail-on", "none"}, &stdout, &stderr)

	if code != 0 {
		if isNetworkBlocked(stderr.String()) {
			t.Skipf("scan blocked by network policy: %s", strings.TrimSpace(stderr.String()))
		}
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Funnel") {
		t.Fatalf("expected scan output to include funnel summary, got: %s", output)
	}
}

func isNetworkBlocked(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "proxyconnect") ||
		strings.Contains(lower, "connect tunnel failed")
}
