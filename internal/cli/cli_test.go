package cli

import (
	"bytes"
	"testing"
)

func TestScanHelpMatchesPRD(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}

	if stdout.String() != scanHelp {
		t.Fatalf("scan help output mismatch\nexpected:\n%s\n\nactual:\n%s", scanHelp, stdout.String())
	}
}
