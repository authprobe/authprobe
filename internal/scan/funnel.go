package scan

// funnel.go - Scan funnel orchestration and step execution
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Orchestration                       │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ RunScanFunnel                       │ Main entry point: run complete scan funnel                 │
// │ newFunnel                           │ Create new funnel instance with configuration              │
// │ (f) run                             │ Execute all funnel steps in sequence                       │
// │ (f) getSteps                        │ Get ordered list of scan step definitions                  │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Skip Conditions                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ (f) skipIfMCPDisabled               │ Skip if MCP mode is off                                    │
// │ (f) skipIfNoAuthServers             │ Skip if no authorization servers found                     │
// │ (f) skipIfNoTokenEndpoints          │ Skip if no token endpoints found                           │
// │ (f) skipIfNoRegistrationEndpoints   │ Skip if no registration endpoints found                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Step Execution                      │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ (f) runMCPProbe                     │ Step 1: Probe MCP endpoint for 401                         │
// │ (f) runMCPInitialize                │ Step 2: MCP initialize + tools/list                        │
// │ (f) runPRMFetch                     │ Step 3: Fetch Protected Resource Metadata                  │
// │ (f) runAuthServerMetadata           │ Step 4: Fetch authorization server metadata                │
// │ (f) runTokenEndpoint                │ Step 5: Probe token endpoint readiness                     │
// │ (f) runDCRProbe                     │ Step 6: Probe DCR endpoint (RFC 7591)                      │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Result Building                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ (f) buildReport                     │ Construct final scan report                                │
// │ (f) buildScanSummary                │ Construct scan summary with optional explanation           │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// funnel orchestrates the scan steps and holds shared state.
type funnel struct {
	client        *http.Client
	config        ScanConfig
	trace         []TraceEntry // HTTP request/response log for evidence collection and debugging
	stdout        io.Writer
	verboseOutput io.Writer
	failedTestLog string

	// Results accumulated from steps
	findings           []Finding
	steps              []ScanStep
	resourceMetadata   string
	resolvedTarget     string
	authRequired       bool
	prmResult          prmResult
	prmOK              bool
	oauthDiscoveryOK   bool
	authMetadata       authServerMetadataResult
	authzMetadataOK    bool
	mcpAuthObservation *mcpAuthObservation
	mcpProtocol        mcpProtocolVersions
}

// newFunnel creates a new funnel instance with the given configuration.
func newFunnel(config ScanConfig, stdout, verboseOutput io.Writer) *funnel {
	client := &http.Client{Timeout: config.Timeout}
	if config.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	if config.NoFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &funnel{
		client:        client,
		config:        config,
		trace:         []TraceEntry{},
		stdout:        stdout,
		verboseOutput: verboseOutput,
		findings:      []Finding{},
		steps:         []ScanStep{},
	}
}

// stepDef defines a single step in the scan funnel.
type stepDef struct {
	ID   int
	Name string
	Desc string // One-line description for comments/docs
	Skip func(f *funnel) (bool, string)
	Run  func(f *funnel) (string, string, []Finding, error)
}

// getSteps returns the ordered list of scan steps.
func (f *funnel) getSteps() []stepDef {
	return []stepDef{
		{
			ID:   1,
			Name: "MCP probe (401 + WWW-Authenticate)",
			Desc: "Probe the MCP endpoint with GET to check for 401 + WWW-Authenticate with resource_metadata",
			Skip: nil, // Always runs
			Run:  (*funnel).runMCPProbe,
		},
		{
			ID:   2,
			Name: "MCP initialize + tools/list",
			Desc: "Perform MCP JSON-RPC initialize handshake and tools/list to verify protocol conformance",
			Skip: (*funnel).skipIfMCPDisabled,
			Run:  (*funnel).runMCPInitialize,
		},
		{
			ID:   3,
			Name: "PRM fetch matrix",
			Desc: "Fetch OAuth Protected Resource Metadata (RFC 9728) from .well-known endpoints",
			Skip: nil, // Always runs - PRM result determines if auth is configured
			Run:  (*funnel).runPRMFetch,
		},
		{
			ID:   4,
			Name: "Auth server metadata",
			Desc: "Fetch Authorization Server Metadata (RFC 8414 + OIDC discovery) for each authorization_server in PRM",
			Skip: (*funnel).skipIfNoAuthServers,
			Run:  (*funnel).runAuthServerMetadata,
		},
		{
			ID:   5,
			Name: "Token endpoint readiness (heuristics)",
			Desc: "Probe token endpoints with empty POST to verify they respond (heuristic readiness check)",
			Skip: (*funnel).skipIfNoTokenEndpoints,
			Run:  (*funnel).runTokenEndpoint,
		},
		{
			ID:   6,
			Name: "Dynamic client registration (RFC 7591)",
			Desc: "Probe DCR endpoint for security posture and input validation",
			Skip: (*funnel).skipIfNoRegistrationEndpoints,
			Run:  (*funnel).runDCRProbe,
		},
	}
}

// Skip condition methods

func (f *funnel) skipIfMCPDisabled() (bool, string) {
	if !mcpModeEnabled(f.config.MCPMode) {
		return true, "mcp checks disabled"
	}
	return false, ""
}

// skipIfNoAuthServers skips Step 4 if no authorization_servers were found in PRM.
func (f *funnel) skipIfNoAuthServers() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.prmResult.AuthorizationServers) == 0 {
		return true, "no authorization_servers in PRM"
	}
	return false, ""
}

// skipIfNoTokenEndpoints skips Step 5 if no token_endpoint was found in auth server metadata.
func (f *funnel) skipIfNoTokenEndpoints() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.authMetadata.TokenEndpoints) == 0 {
		return true, "no token_endpoint in metadata"
	}
	return false, ""
}

// skipIfNoRegistrationEndpoints skips Step 6 if no registration_endpoint was found in auth server metadata.
func (f *funnel) skipIfNoRegistrationEndpoints() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.authMetadata.RegistrationEndpoints) == 0 {
		return true, "no registration_endpoint in metadata"
	}
	return false, ""
}

// updateProbeDetailForAuth updates Step 1's detail when Step 2 reveals auth is actually required.
func (f *funnel) updateProbeDetailForAuth() {
	for i := range f.steps {
		if f.steps[i].ID == 1 && strings.Contains(f.steps[i].Detail, "auth not required") {
			f.steps[i].Detail = "auth appears required (initialize returned 401/403)"
		}
	}
}

// Step execution methods

// runMCPProbe probes the MCP endpoint with GET to check for 401 + WWW-Authenticate - Step 1.
//
// Inputs (from funnel state):
//   - f.config.Target: MCP endpoint URL to probe
//   - f.config.Headers: Custom headers to include in request
//
// Outputs:
//   - status: "PASS"/"FAIL"/"SKIP" based on findings and auth status
//   - detail: Human-readable summary (e.g., "401 with resource_metadata", "probe returned 405")
//   - findings: MCP compliance issues (MCP_GET_NOT_SSE, DISCOVERY_NO_WWW_AUTHENTICATE, etc.)
//   - error: Non-nil only for fatal errors (network failure, invalid URL)
//
// Side effects (funnel fields set):
//   - f.resourceMetadata: URL from WWW-Authenticate resource_metadata param (for Step 3)
//   - f.resolvedTarget: Final URL after redirects (for constructing PRM URLs)
//   - f.authRequired: true if 401 received, false if 405/200 (may be updated by Step 2/3)
func (f *funnel) runMCPProbe() (string, string, []Finding, error) {
	resourceMetadata, resolvedTarget, findings, evidence, authRequired, err := probeMCP(f.client, f.config, &f.trace, f.verboseOutput)
	if err != nil {
		return "", "", nil, err
	}
	f.resourceMetadata = resourceMetadata
	f.resolvedTarget = resolvedTarget
	f.authRequired = authRequired
	status := statusFromFindings(findings, authRequired)
	return status, evidence, findings, nil
}

// runMCPInitialize performs MCP JSON-RPC initialize handshake and tools/list - Step 2.
//
// Inputs (from funnel state):
//   - f.config.Target: MCP endpoint URL for POST requests
//   - f.authRequired: Current auth status from Step 1 (affects ordering check)
//
// Outputs:
//   - status: "PASS" if initialize succeeds, "FAIL" on errors, "SKIP" if auth blocks
//   - detail: Evidence summary (initialize -> 200, tools/list -> 200, tool names)
//   - findings: MCP compliance issues (MCP_INITIALIZE_ORDERING_NOT_ENFORCED, etc.)
//   - error: Non-nil only for fatal errors
//
// Side effects (funnel fields set):
//   - f.authRequired: Updated to true if POST returns 401/403 (late auth discovery)
//   - f.mcpAuthObservation: Stored if 401 received without WWW-Authenticate header
//   - f.steps[0].Detail: Updated via updateProbeDetailForAuth() if auth discovered late
func (f *funnel) runMCPInitialize() (string, string, []Finding, error) {
	status, detail, findings, authObservation := mcpInitializeAndListTools(f.client, f.config, &f.trace, f.verboseOutput, f.authRequired, &f.mcpProtocol)
	// Handle late auth discovery: Step 1 may return 405 (method not allowed) but Step 2
	// reveals auth is required when initialize/tools_list gets 401/403.
	// This updates authRequired so subsequent steps (PRM, auth server) proceed correctly.
	// If 401 was received without WWW-Authenticate header, store the observation to generate
	// DISCOVERY_NO_WWW_AUTHENTICATE finding and update Step 1's detail to reflect auth status.
	if authObservation != nil && (authObservation.Status == http.StatusUnauthorized || authObservation.Status == http.StatusForbidden) {
		f.authRequired = true
		if !authObservation.WWWAuthenticatePresent {
			f.mcpAuthObservation = authObservation
		}
		f.updateProbeDetailForAuth()
	}
	return status, detail, findings, nil
}

// runPRMFetch fetches OAuth Protected Resource Metadata (RFC 9728) - Step 3.
//
// Inputs (from funnel state):
//   - f.resourceMetadata: URL from WWW-Authenticate resource_metadata (may be empty)
//   - f.resolvedTarget: Target URL after redirects from Step 1
//   - f.authRequired: Current auth status from Steps 1-2
//
// Outputs:
//   - status: "PASS" if PRM found, step status based on findings otherwise
//   - detail: Evidence summary (URLs probed and HTTP status codes)
//   - findings: RFC compliance issues (PRM_RESOURCE_MISMATCH, etc.)
//   - error: Non-nil only for fatal errors
//
// Side effects:
//   - Sets f.prmResult with authorization_servers for Step 4
//   - Sets f.authRequired = true if valid PRM found (enables OAuth discovery)
//   - Sets f.prmOK and f.oauthDiscoveryOK for status tracking
func (f *funnel) runPRMFetch() (string, string, []Finding, error) {
	result, findings, evidence, err := fetchPRMMatrix(f.client, f.config, f.resourceMetadata, f.resolvedTarget, &f.trace, f.verboseOutput, f.authRequired)
	if err != nil {
		return "", "", nil, err
	}
	f.prmResult = result
	f.prmOK = result.PRMOK
	f.oauthDiscoveryOK = result.OAuthDiscovery

	prmSummary := ""
	if len(result.AuthorizationServers) == 0 {
		if result.MetadataFound {
			prmSummary = "PRM reachable but no OAuth configuration found"
		} else {
			prmSummary = "PRM unreachable or unusable; OAuth discovery unavailable"
		}
	}
	if prmSummary != "" {
		if evidence != "" {
			evidence = evidence + "\n" + prmSummary
		} else {
			evidence = prmSummary
		}
	}
	if result.RootWellKnown404 && result.PRMOK {
		warn := "WARN: root PRM endpoint 404; resource-specific PRM available; some simplistic clients may fail."
		if evidence != "" {
			evidence = evidence + "\n" + warn
		} else {
			evidence = warn
		}
	}
	rootRequired := !result.HasPathSuffix
	for i := range findings {
		if findings[i].Code == "DISCOVERY_ROOT_WELLKNOWN_404" && !(rootRequired && !result.PRMOK) {
			findings[i].Severity = "low"
		}
	}
	if f.authRequired && !result.MetadataFound {
		findings = append(findings, newFinding("OAUTH_DISCOVERY_UNAVAILABLE", "no usable PRM endpoints returned valid metadata"))
	}
	if f.authRequired && f.resourceMetadata == "" {
		if f.oauthDiscoveryOK {
			findings = append(findings, newFindingWithSeverity("DISCOVERY_NO_WWW_AUTHENTICATE", "missing WWW-Authenticate/resource_metadata; discovery still possible via RFC 9728 inserted-path PRM", "low"))
		} else if f.mcpAuthObservation != nil && !f.mcpAuthObservation.WWWAuthenticatePresent {
			findings = append(findings, buildAuthDiscoveryUnavailableFinding(*f.mcpAuthObservation, evidence))
		} else {
			findings = append(findings, newFindingWithEvidence("AUTH_REQUIRED_BUT_NOT_ADVERTISED", []string{
				"401/403 without WWW-Authenticate/resource_metadata",
				"no PRM endpoints returned valid metadata",
			}))
		}
	}

	// If valid PRM found (has authorization_servers), OAuth is configured
	if len(result.AuthorizationServers) > 0 {
		f.authRequired = true
		status := statusFromFindings(findings, true)
		if !hasSeverityAtLeast(findings, "medium") {
			status = "PASS"
		}
		return status, evidence, findings, nil
	}

	// No valid PRM found and auth isn't required: this is expected for public/no-auth servers.
	if !f.authRequired {
		if result.MetadataFound {
			return "PASS", evidence, nil, nil
		}
		if evidence != "" {
			evidence = evidence + "\nPRM not required for public/no-auth MCP servers"
		} else {
			evidence = "PRM not required for public/no-auth MCP servers"
		}
		return "SKIP", evidence, nil, nil
	}

	// Auth was required (401) but no valid PRM - this is a real failure
	status := statusFromFindings(findings, true)
	if !hasSeverityAtLeast(findings, "medium") {
		status = "PASS"
	}
	return status, evidence, findings, nil
}

// runAuthServerMetadata fetches Authorization Server Metadata (RFC 8414) - Step 4.
//
// Inputs (from funnel state):
//   - f.prmResult.AuthorizationServers: Issuer URLs from Step 3 PRM
//
// Outputs:
//   - status: "PASS" if metadata valid, "FAIL" on RFC violations
//   - detail: Evidence summary (metadata URLs and HTTP status codes)
//   - findings: RFC 8414 issues (AUTH_SERVER_ISSUER_MISMATCH, AUTH_SERVER_PKCE_S256_MISSING, etc.)
//   - error: Always nil (errors are captured as findings)
//
// Side effects (funnel fields set):
//   - f.authMetadata: Contains TokenEndpoints and RegistrationEndpoints for Steps 5-6
//   - f.authzMetadataOK: true if at least one auth server metadata was successfully fetched
func (f *funnel) runAuthServerMetadata() (string, string, []Finding, error) {
	findings, evidence, metadata, ok := fetchAuthServerMetadata(f.client, f.config, f.prmResult, &f.trace, f.verboseOutput)
	f.authMetadata = metadata
	f.authzMetadataOK = ok
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// runTokenEndpoint probes token endpoints with empty POST - Step 5.
//
// Inputs (from funnel state):
//   - f.authMetadata.TokenEndpoints: Token endpoint URLs from Step 4
//
// Outputs:
//   - status: "PASS" if endpoints respond, "FAIL" on errors
//   - detail: Evidence summary (endpoint URLs and HTTP status codes)
//   - findings: Token endpoint issues (TOKEN_RESPONSE_NOT_JSON_RISK, TOKEN_HTTP200_ERROR_PAYLOAD_RISK)
//   - error: Always nil (errors are captured as findings)
//
// Side effects: None (read-only probe)
func (f *funnel) runTokenEndpoint() (string, string, []Finding, error) {
	findings, evidence := probeTokenEndpointReadiness(f.client, f.config, f.authMetadata.TokenEndpoints, &f.trace, f.verboseOutput)
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// runDCRProbe probes Dynamic Client Registration endpoints (RFC 7591) - Step 6.
//
// Inputs (from funnel state):
//   - f.authMetadata.RegistrationEndpoints: DCR endpoint URLs from Step 4
//
// Outputs:
//   - status: "PASS" if endpoints are protected, "FAIL" if security issues found
//   - detail: Evidence summary (endpoint URLs, HTTP status, open/protected status)
//   - findings: DCR security issues (DCR_ENDPOINT_OPEN, DCR_HTTP_REDIRECT_ACCEPTED, etc.)
//   - error: Always nil (errors are captured as findings)
//
// Side effects: None (read-only probe, does not actually register clients)
func (f *funnel) runDCRProbe() (string, string, []Finding, error) {
	findings, evidence := probeDCREndpoints(f.client, f.config, f.authMetadata.RegistrationEndpoints, &f.trace, f.verboseOutput)
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// run executes all funnel steps and returns the completed report.
func (f *funnel) run() error {
	for _, stepDef := range f.getSteps() {
		step := ScanStep{ID: stepDef.ID, Name: stepDef.Name}

		// Check if step should be skipped
		if stepDef.Skip != nil {
			if shouldSkip, skipReason := stepDef.Skip(f); shouldSkip {
				step.Status = "SKIP"
				step.Detail = skipReason
				f.steps = append(f.steps, step)
				continue
			}
		}

		// Run the step
		status, detail, findings, err := stepDef.Run(f)
		if err != nil {
			return err
		}

		step.Status = status
		step.Detail = detail
		if step.Status == "FAIL" {
			f.captureFailedTestVerbose(stepDef)
		}
		f.findings = append(f.findings, findings...)
		f.steps = append(f.steps, step)
	}
	return nil
}

// buildReport constructs the final scan report.
func (f *funnel) buildReport() ScanReport {
	return ScanReport{
		Command:         f.config.Command,
		Target:          f.config.Target,
		MCPMode:         f.config.MCPMode,
		RFCMode:         f.config.RFCMode,
		AuthRequired:    f.authRequired,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Github:          githubURL,
		PRMOK:           f.prmOK,
		OAuthDiscovery:  f.oauthDiscoveryOK,
		AuthzMetadataOK: f.authzMetadataOK,
		Steps:           f.steps,
		Findings:        f.findings,
		PrimaryFinding:  choosePrimaryFinding(f.findings),
	}
}

// sectionHeading returns a formatted heading block for stdout sections.
func sectionHeading(title string) string {
	upper := strings.ToUpper(title)
	pad := 60 - 4 - len(upper) // 4 = len("┤ ") + len(" ├")
	if pad < 2 {
		pad = 2
	}
	left := pad / 2
	right := pad - left
	return "┌" + strings.Repeat("─", left) + "┤ " + upper + " ├" + strings.Repeat("─", right) + "┐"
}

// buildScanSummary constructs the scan summary with optional explanation.
func (f *funnel) buildScanSummary(report ScanReport) ScanSummary {
	summary := buildSummary(report)
	if f.config.Explain {
		explanation := buildScanExplanation(f.config, f.resourceMetadata, f.prmResult, f.authRequired, report.Findings)
		if explanation != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + sectionHeading("RFC Rationale") + "\n" + explanation + "\n"
		}
	}
	traceASCII := buildTraceASCII(f.trace)
	if traceASCII != "" {
		summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + sectionHeading("Call Trace") + "\n" + traceASCII + "\n"
	}
	if f.config.TraceFailure && strings.TrimSpace(f.failedTestLog) != "" {
		trimmed := strings.TrimSpace(f.failedTestLog)
		summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + sectionHeading("Failed Test Verbose Output") + "\n" + trimmed + "\n"
		summary.MD = strings.TrimSpace(summary.MD) + "\n\n## Failed Test Verbose Output\n\n```\n" + trimmed + "\n```\n"
	}
	if f.config.LLMExplain {
		explanation, err := buildLLMExplanation(f.config, report)
		if err != nil {
			message := fmt.Sprintf("Root-cause analysis unavailable: %v", err)
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + sectionHeading("Root-Cause Analysis") + "\n" + message + "\n"
			summary.MD = strings.TrimSpace(summary.MD) + "\n\n## Root-Cause Analysis\n\n" + message + "\n"
		} else if explanation != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + sectionHeading("Root-Cause Analysis") + "\n" + explanation + "\n"
			summary.MD = strings.TrimSpace(summary.MD) + "\n\n## Root-Cause Analysis\n\n" + explanation + "\n"
		}
	}
	summary.Trace = f.trace
	return summary
}

func (f *funnel) captureFailedTestVerbose(stepDef stepDef) {
	var buffer strings.Builder
	verboseFunnel := f.cloneForVerbose(&buffer)
	_, _, _, err := stepDef.Run(verboseFunnel)
	if err != nil {
		fmt.Fprintf(&buffer, "\nFailed to rerun step for verbose output: %v\n", err)
	}
	trimmed := strings.TrimSpace(buffer.String())
	if trimmed == "" {
		return
	}
	if f.failedTestLog != "" {
		f.failedTestLog += "\n\n"
	}
	f.failedTestLog += trimmed
}

func (f *funnel) cloneForVerbose(output io.Writer) *funnel {
	config := f.config
	config.Verbose = true
	return &funnel{
		client:             f.client,
		config:             config,
		trace:              []TraceEntry{},
		stdout:             f.stdout,
		verboseOutput:      output,
		findings:           []Finding{},
		steps:              []ScanStep{},
		resourceMetadata:   f.resourceMetadata,
		resolvedTarget:     f.resolvedTarget,
		authRequired:       f.authRequired,
		prmResult:          f.prmResult,
		prmOK:              f.prmOK,
		oauthDiscoveryOK:   f.oauthDiscoveryOK,
		authMetadata:       f.authMetadata,
		authzMetadataOK:    f.authzMetadataOK,
		mcpAuthObservation: f.mcpAuthObservation,
		mcpProtocol:        f.mcpProtocol,
	}
}

// RunScanFunnel is the main entry point for running the scan funnel.
func RunScanFunnel(config ScanConfig, stdout io.Writer, verboseOutput io.Writer) (ScanReport, ScanSummary, error) {
	f := newFunnel(config, stdout, verboseOutput)

	if err := f.run(); err != nil {
		return ScanReport{}, ScanSummary{}, err
	}

	report := f.buildReport()
	summary := f.buildScanSummary(report)

	if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
		return report, ScanSummary{}, err
	}

	return report, summary, nil
}
