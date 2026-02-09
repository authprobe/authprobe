package scan

import (
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ShouldFail (was 0% coverage)
// ---------------------------------------------------------------------------

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		failOn  string
		want    bool
	}{
		{"high finding with fail-on=high", Finding{Code: "X", Severity: "high"}, "high", true},
		{"medium finding with fail-on=high", Finding{Code: "X", Severity: "medium"}, "high", false},
		{"high finding with fail-on=medium", Finding{Code: "X", Severity: "high"}, "medium", true},
		{"medium finding with fail-on=medium", Finding{Code: "X", Severity: "medium"}, "medium", true},
		{"low finding with fail-on=medium", Finding{Code: "X", Severity: "low"}, "medium", false},
		{"low finding with fail-on=low", Finding{Code: "X", Severity: "low"}, "low", true},
		{"high finding with fail-on=none", Finding{Code: "X", Severity: "high"}, "none", false},
		{"empty finding code", Finding{}, "high", false},
		{"empty fail-on", Finding{Code: "X", Severity: "high"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldFail(tt.finding, tt.failOn)
			if got != tt.want {
				t.Errorf("ShouldFail(%+v, %q) = %v, want %v", tt.finding, tt.failOn, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isMCPStrictUpgrade (was 0% coverage)
// ---------------------------------------------------------------------------

func TestIsMCPStrictUpgrade(t *testing.T) {
	upgradeCodes := []string{
		"MCP_NOTIFICATION_STATUS_INVALID",
		"MCP_NOTIFICATION_BODY_PRESENT",
		"MCP_ORIGIN_NOT_VALIDATED",
		"MCP_PROTOCOL_VERSION_MISMATCH",
		"MCP_PROTOCOL_VERSION_REJECTION_MISSING",
		"MCP_SESSION_ID_REJECTION_MISSING",
		"MCP_PING_INVALID_RESPONSE",
		"MCP_ICON_UNSAFE_SCHEME",
		"MCP_TASKS_METHOD_MISSING",
		"MCP_INITIALIZE_RESULT_INVALID",
		"MCP_CAPABILITIES_INVALID",
		"MCP_TOOLS_LIST_INVALID",
	}
	for _, code := range upgradeCodes {
		if !isMCPStrictUpgrade(code) {
			t.Errorf("expected isMCPStrictUpgrade(%q) = true", code)
		}
	}
	// Non-upgrade codes
	nonUpgradeCodes := []string{"AUTH_REQUIRED", "PRM_RESOURCE_MISMATCH", "SOME_OTHER_CODE", ""}
	for _, code := range nonUpgradeCodes {
		if isMCPStrictUpgrade(code) {
			t.Errorf("expected isMCPStrictUpgrade(%q) = false", code)
		}
	}
}

// ---------------------------------------------------------------------------
// buildMetadataURL (was 0% coverage)
// ---------------------------------------------------------------------------

func TestBuildMetadataURL(t *testing.T) {
	tests := []struct {
		issuer string
		want   string
	}{
		{"https://example.com", "https://example.com/.well-known/oauth-authorization-server"},
		{"https://example.com/path", "https://example.com/.well-known/oauth-authorization-server/path"},
		// Invalid URL falls back to issuer itself
		{"://invalid", "://invalid"},
	}
	for _, tt := range tests {
		got := buildMetadataURL(tt.issuer)
		if got != tt.want {
			t.Errorf("buildMetadataURL(%q) = %q, want %q", tt.issuer, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// buildLLMPrompt (test coverage for the prompt builder)
// ---------------------------------------------------------------------------

func TestBuildLLMPrompt(t *testing.T) {
	report := ScanReport{
		Target:  "https://example.com/mcp",
		MCPMode: "best-effort",
		RFCMode: "best-effort",
		Steps: []ScanStep{
			{ID: 1, Name: "MCP probe", Status: "PASS", Detail: "401 + PRM"},
			{ID: 3, Name: "PRM fetch", Status: "FAIL", Detail: "PRM not found"},
		},
		Findings: []Finding{
			{Code: "DISCOVERY_ROOT_WELLKNOWN_404", Severity: "high", Confidence: 1.0, Evidence: []string{"root PRM 404"}},
			{Code: "PRM_WELLKNOWN_PATH_SUFFIX_MISSING", Severity: "low", Confidence: 0.8},
		},
		PrimaryFinding: Finding{Code: "DISCOVERY_ROOT_WELLKNOWN_404", Severity: "high", Confidence: 1.0, Evidence: []string{"root PRM 404"}},
	}

	prompt := buildLLMPrompt(ScanConfig{}, report)

	// Check key sections exist
	if !strings.Contains(prompt, "https://example.com/mcp") {
		t.Error("prompt should include target")
	}
	if !strings.Contains(prompt, "DISCOVERY_ROOT_WELLKNOWN_404") {
		t.Error("prompt should include finding code")
	}
	if !strings.Contains(prompt, "Failed steps") {
		t.Error("prompt should include failed steps section")
	}
	if !strings.Contains(prompt, "Primary Finding") {
		t.Error("prompt should include primary finding")
	}
	if !strings.Contains(prompt, "root PRM 404") {
		t.Error("prompt should include evidence")
	}
	if !strings.Contains(prompt, "MCP mode: best-effort") {
		t.Error("prompt should include MCP mode")
	}

	// Test with no findings
	emptyReport := ScanReport{
		Target:  "https://example.com/mcp",
		MCPMode: "best-effort",
		RFCMode: "best-effort",
		Steps:   []ScanStep{{ID: 1, Name: "probe", Status: "PASS"}},
	}
	emptyPrompt := buildLLMPrompt(ScanConfig{}, emptyReport)
	if strings.Contains(emptyPrompt, "Findings:") {
		t.Error("empty report should not have Findings section")
	}
	if strings.Contains(emptyPrompt, "Failed steps") {
		t.Error("all-pass report should not have Failed steps section")
	}
}

// ---------------------------------------------------------------------------
// ParseHeader (edge cases)
// ---------------------------------------------------------------------------

func TestParseHeader(t *testing.T) {
	tests := []struct {
		raw     string
		wantKey string
		wantVal string
		wantErr bool
	}{
		{"Authorization: Bearer token", "Authorization", "Bearer token", false},
		{"X-Custom: value with : colons", "X-Custom", "value with : colons", false},
		{" Key : Value ", "Key", "Value", false},
		{"no-colon", "", "", true},
		{": empty-key", "", "", true},
	}
	for _, tt := range tests {
		key, val, err := ParseHeader(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseHeader(%q) expected error", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseHeader(%q) unexpected error: %v", tt.raw, err)
			continue
		}
		if key != tt.wantKey || val != tt.wantVal {
			t.Errorf("ParseHeader(%q) = (%q, %q), want (%q, %q)", tt.raw, key, val, tt.wantKey, tt.wantVal)
		}
	}
}

// ---------------------------------------------------------------------------
// AppendVerboseMarkdown
// ---------------------------------------------------------------------------

func TestAppendVerboseMarkdown(t *testing.T) {
	// Non-empty verbose output
	md := AppendVerboseMarkdown("# Report\n\nContent", "== Step 1 ==\n> GET /mcp")
	if !strings.Contains(md, "## Verbose output") {
		t.Error("expected verbose section header")
	}
	if !strings.Contains(md, "GET /mcp") {
		t.Error("expected verbose content")
	}

	// Empty verbose output
	md2 := AppendVerboseMarkdown("# Report", "   \n  ")
	if strings.Contains(md2, "Verbose") {
		t.Error("empty verbose should not append section")
	}
}

// ---------------------------------------------------------------------------
// validateFetchTarget (SSRF blocking)
// ---------------------------------------------------------------------------

func TestValidateFetchTargetSSRF(t *testing.T) {
	config := ScanConfig{
		AllowPrivateIssuers: false,
		RFCMode:             "best-effort",
	}

	// Localhost should be blocked
	err := validateFetchTarget(config, "http://localhost/metadata")
	if err == nil {
		t.Error("expected localhost to be blocked")
	}

	// .local domain should be blocked
	err = validateFetchTarget(config, "http://myhost.local/metadata")
	if err == nil {
		t.Error("expected .local domain to be blocked")
	}

	// AllowPrivateIssuers bypasses check
	configAllow := ScanConfig{
		AllowPrivateIssuers: true,
		RFCMode:             "best-effort",
	}
	err = validateFetchTarget(configAllow, "http://localhost/metadata")
	if err != nil {
		t.Errorf("AllowPrivateIssuers should bypass check: %v", err)
	}

	// RFC mode off bypasses check
	configOff := ScanConfig{
		AllowPrivateIssuers: false,
		RFCMode:             "off",
	}
	err = validateFetchTarget(configOff, "http://localhost/metadata")
	if err != nil {
		t.Errorf("RFC mode off should bypass check: %v", err)
	}
}

// ---------------------------------------------------------------------------
// newMCPFinding with strict mode upgrade
// ---------------------------------------------------------------------------

func TestNewMCPFindingStrictUpgrade(t *testing.T) {
	config := ScanConfig{MCPMode: "strict"}
	f := newMCPFinding(config, "MCP_NOTIFICATION_STATUS_INVALID", "test evidence")

	if f.Severity != "high" {
		t.Errorf("strict mode should upgrade severity to high, got %q", f.Severity)
	}

	// Non-strict mode should use default severity
	configBE := ScanConfig{MCPMode: "best-effort"}
	f2 := newMCPFinding(configBE, "MCP_NOTIFICATION_STATUS_INVALID", "test evidence")
	if f2.Severity == "high" {
		t.Error("best-effort mode should not upgrade to high")
	}
}

// ---------------------------------------------------------------------------
// findingRFCExplanation (coverage for more finding codes)
// ---------------------------------------------------------------------------

func TestFindingRFCExplanation(t *testing.T) {
	codes := []string{
		"AUTH_REQUIRED_BUT_NOT_ADVERTISED",
		"DISCOVERY_ROOT_WELLKNOWN_404",
		"PRM_RESOURCE_MISMATCH",
		"AUTH_SERVER_ISSUER_MISMATCH",
		"MCP_INITIALIZE_FAILED",
		"DCR_ENDPOINT_OPEN",
		"DCR_HTTP_REDIRECT_ACCEPTED",
		"TOKEN_RESPONSE_NOT_JSON_RISK",
	}
	for _, code := range codes {
		explanation := findingRFCExplanation(code)
		if explanation == "" {
			t.Errorf("findingRFCExplanation(%q) returned empty string", code)
		}
	}

	// Unknown code returns empty
	if findingRFCExplanation("NO_SUCH_CODE") != "" {
		t.Error("unknown code should return empty explanation")
	}
}

// ---------------------------------------------------------------------------
// severityRank
// ---------------------------------------------------------------------------

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"low", 1},
		{"medium", 2},
		{"high", 3},
		{"", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.severity)
		if got != tt.want {
			t.Errorf("severityRank(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// choosePrimaryFinding
// ---------------------------------------------------------------------------

func TestChoosePrimaryFinding(t *testing.T) {
	// Empty list
	primary := choosePrimaryFinding(nil)
	if primary.Code != "" {
		t.Error("empty list should return empty finding")
	}

	// Only low/medium findings → no primary (requires high severity)
	findings := []Finding{{Code: "A", Severity: "medium", Confidence: 0.8}}
	primary = choosePrimaryFinding(findings)
	if primary.Code != "" {
		t.Errorf("medium-only findings should return empty primary, got %q", primary.Code)
	}

	// Single high finding → becomes primary
	findings = []Finding{{Code: "A", Severity: "high", Confidence: 0.9}}
	primary = choosePrimaryFinding(findings)
	if primary.Code != "A" {
		t.Errorf("single high finding should be primary, got %q", primary.Code)
	}

	// Multiple findings — highest severity high finding wins
	findings = []Finding{
		{Code: "LOW", Severity: "low", Confidence: 1.0},
		{Code: "HIGH", Severity: "high", Confidence: 0.8},
		{Code: "MED", Severity: "medium", Confidence: 0.9},
	}
	primary = choosePrimaryFinding(findings)
	if primary.Code != "HIGH" {
		t.Errorf("expected HIGH as primary, got %q", primary.Code)
	}

	// Multiple high findings — higher confidence wins
	findings = []Finding{
		{Code: "H1", Severity: "high", Confidence: 0.7},
		{Code: "H2", Severity: "high", Confidence: 0.95},
	}
	primary = choosePrimaryFinding(findings)
	if primary.Code != "H2" {
		t.Errorf("expected H2 (higher confidence) as primary, got %q", primary.Code)
	}
}

// ---------------------------------------------------------------------------
// isSSEContentType and isJSONContentType
// ---------------------------------------------------------------------------

func TestIsSSEContentType(t *testing.T) {
	if !isSSEContentType("text/event-stream") {
		t.Error("text/event-stream should be SSE")
	}
	if !isSSEContentType("text/event-stream; charset=utf-8") {
		t.Error("text/event-stream with params should be SSE")
	}
	if isSSEContentType("application/json") {
		t.Error("application/json should not be SSE")
	}
}

func TestIsJSONContentType(t *testing.T) {
	if !isJSONContentType("application/json") {
		t.Error("application/json should be JSON")
	}
	if !isJSONContentType("application/json; charset=utf-8") {
		t.Error("application/json with params should be JSON")
	}
	if isJSONContentType("text/plain") {
		t.Error("text/plain should not be JSON")
	}
}

// ---------------------------------------------------------------------------
// Mode check helpers
// ---------------------------------------------------------------------------

func TestMCPModeEnabled(t *testing.T) {
	if !mcpModeEnabled("best-effort") {
		t.Error("best-effort should be enabled")
	}
	if !mcpModeEnabled("strict") {
		t.Error("strict should be enabled")
	}
	if mcpModeEnabled("off") {
		t.Error("off should not be enabled")
	}
}

func TestRFCModeEnabled(t *testing.T) {
	if !rfcModeEnabled("best-effort") {
		t.Error("best-effort should be enabled")
	}
	if !rfcModeEnabled("strict") {
		t.Error("strict should be enabled")
	}
	if rfcModeEnabled("off") {
		t.Error("off should not be enabled")
	}
}

// ---------------------------------------------------------------------------
// isHTTPSURL
// ---------------------------------------------------------------------------

func TestIsHTTPSURL(t *testing.T) {
	parse := func(raw string) *url.URL {
		u, _ := url.Parse(raw)
		return u
	}
	if !isHTTPSURL(parse("https://example.com")) {
		t.Error("https should be HTTPS")
	}
	if isHTTPSURL(parse("http://example.com")) {
		t.Error("http should not be HTTPS")
	}
	if isHTTPSURL(parse("ftp://example.com")) {
		t.Error("ftp should not be HTTPS")
	}
	if isHTTPSURL(nil) {
		t.Error("nil should not be HTTPS")
	}
}

// ---------------------------------------------------------------------------
// containsString
// ---------------------------------------------------------------------------

func TestContainsString(t *testing.T) {
	items := []any{"apple", "banana", "cherry"}
	if !containsString(items, "banana") {
		t.Error("should contain banana")
	}
	if containsString(items, "grape") {
		t.Error("should not contain grape")
	}
	if containsString(nil, "x") {
		t.Error("nil slice should not contain anything")
	}
	// Non-string entries should be skipped
	mixed := []any{"hello", 42, true}
	if !containsString(mixed, "hello") {
		t.Error("should find string in mixed slice")
	}
	if containsString(mixed, "42") {
		t.Error("should not match non-string entry")
	}
}
