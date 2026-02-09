package cli

import (
	"reflect"
	"testing"
)

func TestNormalizeScanArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "flags already before positional",
			args: []string{"--verbose", "https://example.com"},
			want: []string{"--verbose", "https://example.com"},
		},
		{
			name: "flags after positional",
			args: []string{"https://example.com", "--verbose"},
			want: []string{"--verbose", "https://example.com"},
		},
		{
			name: "value flag after positional",
			args: []string{"https://example.com", "--timeout", "30"},
			want: []string{"--timeout", "30", "https://example.com"},
		},
		{
			name: "multiple flags after positional",
			args: []string{"https://example.com", "--verbose", "--timeout", "30", "--explain"},
			want: []string{"--verbose", "--timeout", "30", "--explain", "https://example.com"},
		},
		{
			name: "header flag with value",
			args: []string{"https://example.com", "-H", "Authorization: Bearer token"},
			want: []string{"-H", "Authorization: Bearer token", "https://example.com"},
		},
		{
			name: "multiple header flags",
			args: []string{"https://example.com", "-H", "X-First: 1", "-H", "X-Second: 2"},
			want: []string{"-H", "X-First: 1", "-H", "X-Second: 2", "https://example.com"},
		},
		{
			name: "long header flag",
			args: []string{"https://example.com", "--header", "X-Custom: value"},
			want: []string{"--header", "X-Custom: value", "https://example.com"},
		},
		{
			name: "value flag with equals syntax",
			args: []string{"https://example.com", "--timeout=30"},
			want: []string{"--timeout=30", "https://example.com"},
		},
		{
			name: "mixed flags before and after",
			args: []string{"--verbose", "https://example.com", "--timeout", "30"},
			want: []string{"--verbose", "--timeout", "30", "https://example.com"},
		},
		{
			name: "tool-detail flag short form",
			args: []string{"https://example.com", "-d", "my-tool"},
			want: []string{"-d", "my-tool", "https://example.com"},
		},
		{
			name: "tool-detail flag long form",
			args: []string{"https://example.com", "--tool-detail", "my-tool"},
			want: []string{"--tool-detail", "my-tool", "https://example.com"},
		},
		{
			name: "output flags",
			args: []string{"https://example.com", "--json", "out.json", "--md", "out.md"},
			want: []string{"--json", "out.json", "--md", "out.md", "https://example.com"},
		},
		{
			name: "bundle and output-dir flags",
			args: []string{"https://example.com", "--bundle", "evidence.zip", "--output-dir", "/tmp"},
			want: []string{"--bundle", "evidence.zip", "--output-dir", "/tmp", "https://example.com"},
		},
		{
			name: "mcp and rfc flags",
			args: []string{"https://example.com", "--mcp", "strict", "--rfc", "off"},
			want: []string{"--mcp", "strict", "--rfc", "off", "https://example.com"},
		},
		{
			name: "fail-on flag",
			args: []string{"https://example.com", "--fail-on", "medium"},
			want: []string{"--fail-on", "medium", "https://example.com"},
		},
		{
			name: "boolean flags only",
			args: []string{"https://example.com", "--verbose", "--explain", "--tool-list"},
			want: []string{"--verbose", "--explain", "--tool-list", "https://example.com"},
		},
		{
			name: "short boolean flags",
			args: []string{"https://example.com", "-v", "-e", "-l"},
			want: []string{"-v", "-e", "-l", "https://example.com"},
		},
		{
			name: "empty args",
			args: []string{},
			want: []string{},
		},
		{
			name: "only positional",
			args: []string{"https://example.com"},
			want: []string{"https://example.com"},
		},
		{
			name: "only flags",
			args: []string{"--verbose", "--timeout", "30"},
			want: []string{"--verbose", "--timeout", "30"},
		},
		{
			name: "complex real-world example",
			args: []string{
				"https://mcp.example.com/mcp",
				"-H", "Host: internal.example.com",
				"--timeout", "15",
				"--mcp", "strict",
				"--fail-on", "medium",
				"-v",
				"--json", "report.json",
			},
			want: []string{
				"-H", "Host: internal.example.com",
				"--timeout", "15",
				"--mcp", "strict",
				"--fail-on", "medium",
				"-v",
				"--json", "report.json",
				"https://mcp.example.com/mcp",
			},
		},
		{
			name: "value flag at end without value",
			args: []string{"https://example.com", "--timeout"},
			want: []string{"--timeout", "https://example.com"},
		},
		{
			name: "unknown flag treated as boolean",
			args: []string{"https://example.com", "--unknown-flag"},
			want: []string{"--unknown-flag", "https://example.com"},
		},
		{
			name: "unknown flag does not consume next arg",
			args: []string{"https://example.com", "--unknown", "value"},
			// Unknown flags are treated as boolean, so "value" becomes a positional
			want: []string{"--unknown", "https://example.com", "value"},
		},
		{
			name: "insecure and no-follow-redirects flags",
			args: []string{"https://example.com", "--insecure", "--no-follow-redirects"},
			want: []string{"--insecure", "--no-follow-redirects", "https://example.com"},
		},
		{
			name: "allow-private-issuers flag",
			args: []string{"https://example.com", "--allow-private-issuers"},
			want: []string{"--allow-private-issuers", "https://example.com"},
		},
		{
			name: "value flag before URL does not consume URL",
			args: []string{"https://example.com", "--md"},
			want: []string{"--md", "https://example.com"},
		},
		{
			name: "value flag with proper value before URL",
			args: []string{"https://example.com", "--md", "report.md"},
			want: []string{"--md", "report.md", "https://example.com"},
		},
		{
			name: "single-dash long value flag with trailing verbose",
			args: []string{"-md", "report.md", "https://example.com", "--verbose"},
			want: []string{"--md", "report.md", "--verbose", "https://example.com"},
		},
		{
			name: "value flag with dash value before URL",
			args: []string{"https://example.com", "--md", "-"},
			want: []string{"--md", "-", "https://example.com"},
		},
		{
			name: "json flag before URL does not consume URL",
			args: []string{"https://example.com", "--json"},
			want: []string{"--json", "https://example.com"},
		},
		{
			name: "json flag with dash value before URL",
			args: []string{"https://example.com", "--json", "-"},
			want: []string{"--json", "-", "https://example.com"},
		},
		{
			name: "bundle flag before URL does not consume URL",
			args: []string{"https://example.com", "--bundle"},
			want: []string{"--bundle", "https://example.com"},
		},
		{
			name: "output-dir flag before URL does not consume URL",
			args: []string{"https://example.com", "--output-dir"},
			want: []string{"--output-dir", "https://example.com"},
		},
		{
			name: "multiple value flags without values before URL",
			args: []string{"https://example.com", "--md", "--json", "--verbose"},
			want: []string{"--md", "--json", "--verbose", "https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeScanArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeScanArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeScanArgs_PreservesOrder(t *testing.T) {
	// Test that the relative order of flags is preserved
	args := []string{"--verbose", "https://example.com", "-H", "X: 1", "--explain", "-H", "Y: 2"}
	got := normalizeScanArgs(args)

	// All flags should come before the URL
	urlIndex := -1
	for i, arg := range got {
		if arg == "https://example.com" {
			urlIndex = i
			break
		}
	}

	if urlIndex == -1 {
		t.Fatal("URL not found in result")
	}

	// Verify URL is last
	if urlIndex != len(got)-1 {
		t.Errorf("URL should be last, but found at index %d of %d", urlIndex, len(got)-1)
	}

	// Verify flags maintain their relative order
	expectedFlags := []string{"--verbose", "-H", "X: 1", "--explain", "-H", "Y: 2"}
	gotFlags := got[:urlIndex]
	if !reflect.DeepEqual(gotFlags, expectedFlags) {
		t.Errorf("flags order = %v, want %v", gotFlags, expectedFlags)
	}
}
