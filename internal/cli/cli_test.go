package cli

import (
	"bytes"
	"flag"
	"io"
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

// TestScanFlagParsing tests that all scan command flags are correctly parsed.
func TestScanFlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		validate func(t *testing.T, fs *flag.FlagSet)
	}{
		{
			name: "default values",
			args: []string{"https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("timeout").Value.String(); v != "8" {
					t.Errorf("timeout: got %q, want %q", v, "8")
				}
				if v := fs.Lookup("mcp").Value.String(); v != "best-effort" {
					t.Errorf("mcp: got %q, want %q", v, "best-effort")
				}
				if v := fs.Lookup("rfc").Value.String(); v != "best-effort" {
					t.Errorf("rfc: got %q, want %q", v, "best-effort")
				}
				if v := fs.Lookup("fail-on").Value.String(); v != "high" {
					t.Errorf("fail-on: got %q, want %q", v, "high")
				}
				if v := fs.Lookup("verbose").Value.String(); v != "false" {
					t.Errorf("verbose: got %q, want %q", v, "false")
				}
			},
		},
		{
			name: "timeout flag",
			args: []string{"--timeout", "30", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("timeout").Value.String(); v != "30" {
					t.Errorf("timeout: got %q, want %q", v, "30")
				}
			},
		},
		{
			name: "mcp mode strict",
			args: []string{"--mcp", "strict", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("mcp").Value.String(); v != "strict" {
					t.Errorf("mcp: got %q, want %q", v, "strict")
				}
			},
		},
		{
			name: "rfc mode off",
			args: []string{"--rfc", "off", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("rfc").Value.String(); v != "off" {
					t.Errorf("rfc: got %q, want %q", v, "off")
				}
			},
		},
		{
			name: "verbose long flag",
			args: []string{"--verbose", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("verbose").Value.String(); v != "true" {
					t.Errorf("verbose: got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "verbose short flag -v",
			args: []string{"-v", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("v").Value.String(); v != "true" {
					t.Errorf("-v: got %q, want %q", v, "true")
				}
				// -v and --verbose should be the same variable
				if v := fs.Lookup("verbose").Value.String(); v != "true" {
					t.Errorf("verbose (via -v): got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "explain long flag",
			args: []string{"--explain", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("explain").Value.String(); v != "true" {
					t.Errorf("explain: got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "explain short flag -e",
			args: []string{"-e", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("e").Value.String(); v != "true" {
					t.Errorf("-e: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("explain").Value.String(); v != "true" {
					t.Errorf("explain (via -e): got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "tool-list long flag",
			args: []string{"--tool-list", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("tool-list").Value.String(); v != "true" {
					t.Errorf("tool-list: got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "tool-list short flag -l",
			args: []string{"-l", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("l").Value.String(); v != "true" {
					t.Errorf("-l: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("tool-list").Value.String(); v != "true" {
					t.Errorf("tool-list (via -l): got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "tool-detail long flag",
			args: []string{"--tool-detail", "my-tool", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("tool-detail").Value.String(); v != "my-tool" {
					t.Errorf("tool-detail: got %q, want %q", v, "my-tool")
				}
			},
		},
		{
			name: "tool-detail short flag -d",
			args: []string{"-d", "another-tool", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("d").Value.String(); v != "another-tool" {
					t.Errorf("-d: got %q, want %q", v, "another-tool")
				}
				if v := fs.Lookup("tool-detail").Value.String(); v != "another-tool" {
					t.Errorf("tool-detail (via -d): got %q, want %q", v, "another-tool")
				}
			},
		},
		{
			name: "header short flag -H",
			args: []string{"-H", "X-Custom: value", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("H").Value.String(); v != "[X-Custom: value]" {
					t.Errorf("-H: got %q, want %q", v, "[X-Custom: value]")
				}
			},
		},
		{
			name: "header long flag",
			args: []string{"--header", "Authorization: Bearer token", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("header").Value.String(); v != "[Authorization: Bearer token]" {
					t.Errorf("--header: got %q, want %q", v, "[Authorization: Bearer token]")
				}
			},
		},
		{
			name: "multiple headers",
			args: []string{"-H", "X-First: 1", "-H", "X-Second: 2", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("H").Value.String(); v != "[X-First: 1 X-Second: 2]" {
					t.Errorf("-H multiple: got %q, want %q", v, "[X-First: 1 X-Second: 2]")
				}
			},
		},
		{
			name: "boolean flags",
			args: []string{"--allow-private-issuers", "--insecure", "--no-follow-redirects", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("allow-private-issuers").Value.String(); v != "true" {
					t.Errorf("allow-private-issuers: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("insecure").Value.String(); v != "true" {
					t.Errorf("insecure: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("no-follow-redirects").Value.String(); v != "true" {
					t.Errorf("no-follow-redirects: got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "output flags",
			args: []string{"--json", "out.json", "--md", "out.md", "--bundle", "out.zip", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("json").Value.String(); v != "out.json" {
					t.Errorf("json: got %q, want %q", v, "out.json")
				}
				if v := fs.Lookup("md").Value.String(); v != "out.md" {
					t.Errorf("md: got %q, want %q", v, "out.md")
				}
				if v := fs.Lookup("bundle").Value.String(); v != "out.zip" {
					t.Errorf("bundle: got %q, want %q", v, "out.zip")
				}
			},
		},
		{
			name: "output-dir flag",
			args: []string{"--output-dir", "/tmp/reports", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("output-dir").Value.String(); v != "/tmp/reports" {
					t.Errorf("output-dir: got %q, want %q", v, "/tmp/reports")
				}
			},
		},
		{
			name: "fail-on medium",
			args: []string{"--fail-on", "medium", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("fail-on").Value.String(); v != "medium" {
					t.Errorf("fail-on: got %q, want %q", v, "medium")
				}
			},
		},
		{
			name: "combined short flags",
			args: []string{"-v", "-e", "-l", "https://example.com/mcp"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("verbose").Value.String(); v != "true" {
					t.Errorf("verbose: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("explain").Value.String(); v != "true" {
					t.Errorf("explain: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("tool-list").Value.String(); v != "true" {
					t.Errorf("tool-list: got %q, want %q", v, "true")
				}
			},
		},
		{
			name: "flags after positional (normalized)",
			args: []string{"https://example.com/mcp", "--verbose", "--timeout", "15"},
			validate: func(t *testing.T, fs *flag.FlagSet) {
				if v := fs.Lookup("verbose").Value.String(); v != "true" {
					t.Errorf("verbose: got %q, want %q", v, "true")
				}
				if v := fs.Lookup("timeout").Value.String(); v != "15" {
					t.Errorf("timeout: got %q, want %q", v, "15")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("scan", flag.ContinueOnError)
			fs.SetOutput(io.Discard)

			// Define all flags matching cli.go
			var headers stringSlice
			fs.Var(&headers, "header", "")
			fs.Var(&headers, "H", "")
			fs.Int("timeout", 8, "")
			fs.String("mcp", "best-effort", "")
			fs.String("rfc", "best-effort", "")
			fs.Bool("allow-private-issuers", false, "")
			fs.Bool("insecure", false, "")
			fs.Bool("no-follow-redirects", false, "")
			fs.String("fail-on", "high", "")
			fs.String("json", "", "")
			fs.String("md", "", "")
			fs.String("bundle", "", "")
			fs.String("output-dir", "", "")
			verbose := fs.Bool("verbose", false, "")
			fs.BoolVar(verbose, "v", false, "")
			explain := fs.Bool("explain", false, "")
			fs.BoolVar(explain, "e", false, "")
			fs.String("openai-api-key", "", "")
			fs.String("anthropic-api-key", "", "")
			toolList := fs.Bool("tool-list", false, "")
			fs.BoolVar(toolList, "l", false, "")
			toolDetail := fs.String("tool-detail", "", "")
			fs.StringVar(toolDetail, "d", "", "")

			// Normalize args (same as in runScan)
			args := normalizeScanArgs(tt.args)
			err := fs.Parse(args)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, fs)
			}
		})
	}
}

// TestScanMissingURL tests that scan command requires a URL.
func TestScanMissingURL(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan"}, &stdout, &stderr)

	if code != 3 {
		t.Errorf("expected exit code 3, got %d", code)
	}

	if !bytes.Contains(stderr.Bytes(), []byte("<mcp_url> is required")) {
		t.Errorf("expected error about missing URL, got %q", stderr.String())
	}
}

// TestScanInvalidFlag tests that invalid flags are rejected.
func TestScanInvalidFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"scan", "--invalid-flag", "https://example.com/mcp"}, &stdout, &stderr)

	if code != 3 {
		t.Errorf("expected exit code 3, got %d", code)
	}
}
