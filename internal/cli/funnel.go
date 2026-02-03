package cli

// funnel.go - Scan funnel orchestration and step execution
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Orchestration                       │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ runScanFunnel                       │ Main entry point: run complete scan funnel                 │
// │ newFunnel                           │ Create new funnel instance with configuration              │
// │ (f) run                             │ Execute all funnel steps in sequence                       │
// │ (f) getSteps                        │ Get ordered list of scan step definitions                  │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Skip Conditions                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ (f) skipIfMCPDisabled               │ Skip if MCP mode is off                                    │
// │ (f) skipIfAuthNotRequired           │ Skip if auth not required (no 401)                         │
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
	config        scanConfig
	trace         []traceEntry
	stdout        io.Writer
	verboseOutput io.Writer

	// Results accumulated from steps
	findings         []finding
	steps            []scanStep
	resourceMetadata string
	resolvedTarget   string
	authRequired     bool
	prmResult        prmResult
	authMetadata     authServerMetadataResult
}

// newFunnel creates a new funnel instance with the given configuration.
func newFunnel(config scanConfig, stdout, verboseOutput io.Writer) *funnel {
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
		trace:         []traceEntry{},
		stdout:        stdout,
		verboseOutput: verboseOutput,
		findings:      []finding{},
		steps:         []scanStep{},
	}
}

// stepDef defines a single step in the scan funnel.
type stepDef struct {
	ID   int
	Name string
	Desc string // One-line description for comments/docs
	Skip func(f *funnel) (bool, string)
	Run  func(f *funnel) (string, string, []finding, error)
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
			Desc: "Fetch Authorization Server Metadata (RFC 8414) for each authorization_server in PRM",
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

func (f *funnel) skipIfAuthNotRequired() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	return false, ""
}

func (f *funnel) skipIfNoAuthServers() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.prmResult.AuthorizationServers) == 0 {
		return true, "no authorization_servers in PRM"
	}
	return false, ""
}

func (f *funnel) skipIfNoTokenEndpoints() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.authMetadata.TokenEndpoints) == 0 {
		return true, "no token_endpoint in metadata"
	}
	return false, ""
}

func (f *funnel) skipIfNoRegistrationEndpoints() (bool, string) {
	if !f.authRequired {
		return true, "auth not required"
	}
	if len(f.authMetadata.RegistrationEndpoints) == 0 {
		return true, "no registration_endpoint in metadata"
	}
	return false, ""
}

// Step execution methods

// runMCPProbe probes the MCP endpoint with GET to check for 401 + WWW-Authenticate with resource_metadata.
func (f *funnel) runMCPProbe() (string, string, []finding, error) {
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

// runMCPInitialize performs MCP JSON-RPC initialize handshake and tools/list.
func (f *funnel) runMCPInitialize() (string, string, []finding, error) {
	status, detail, findings := mcpInitializeAndListTools(f.client, f.config, &f.trace, f.verboseOutput, f.authRequired)
	return status, detail, findings, nil
}

// runPRMFetch fetches OAuth Protected Resource Metadata (RFC 9728).
// If valid PRM is found (has authorization_servers), sets authRequired = true.
// This allows OAuth discovery to continue even if Step 1 returned 405.
func (f *funnel) runPRMFetch() (string, string, []finding, error) {
	result, findings, evidence, err := fetchPRMMatrix(f.client, f.config, f.resourceMetadata, f.resolvedTarget, &f.trace, f.verboseOutput, f.authRequired)
	if err != nil {
		return "", "", nil, err
	}
	f.prmResult = result

	// If valid PRM found (has authorization_servers), OAuth is configured
	if len(result.AuthorizationServers) > 0 {
		f.authRequired = true
		status := statusFromFindings(findings, true)
		return status, evidence, findings, nil
	}

	// No valid PRM found - if we came from 405, this is expected (no OAuth configured)
	// Don't treat as failure, just note no OAuth is configured
	if !f.authRequired {
		return "PASS", evidence + "\nno OAuth configuration found", nil, nil
	}

	// Auth was required (401) but no valid PRM - this is a real failure
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// runAuthServerMetadata fetches Authorization Server Metadata (RFC 8414).
func (f *funnel) runAuthServerMetadata() (string, string, []finding, error) {
	findings, evidence, metadata := fetchAuthServerMetadata(f.client, f.config, f.prmResult, &f.trace, f.verboseOutput)
	f.authMetadata = metadata
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// runTokenEndpoint probes token endpoints with empty POST.
func (f *funnel) runTokenEndpoint() (string, string, []finding, error) {
	findings, evidence := probeTokenEndpointReadiness(f.client, f.config, f.authMetadata.TokenEndpoints, &f.trace, f.verboseOutput)
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// runDCRProbe probes Dynamic Client Registration endpoints (RFC 7591).
func (f *funnel) runDCRProbe() (string, string, []finding, error) {
	findings, evidence := probeDCREndpoints(f.client, f.config, f.authMetadata.RegistrationEndpoints, &f.trace, f.verboseOutput)
	status := statusFromFindings(findings, true)
	return status, evidence, findings, nil
}

// run executes all funnel steps and returns the completed report.
func (f *funnel) run() error {
	for _, stepDef := range f.getSteps() {
		step := scanStep{ID: stepDef.ID, Name: stepDef.Name}

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
		f.findings = append(f.findings, findings...)
		f.steps = append(f.steps, step)
	}
	return nil
}

// buildReport constructs the final scan report.
func (f *funnel) buildReport() scanReport {
	return scanReport{
		Command:        f.config.Command,
		Target:         f.config.Target,
		MCPMode:        f.config.MCPMode,
		RFCMode:        f.config.RFCMode,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Steps:          f.steps,
		Findings:       f.findings,
		PrimaryFinding: choosePrimaryFinding(f.findings),
	}
}

// buildScanSummary constructs the scan summary with optional explanation.
func (f *funnel) buildScanSummary(report scanReport) scanSummary {
	summary := buildSummary(report)
	if f.config.Explain {
		explanation := buildScanExplanation(f.config, f.resourceMetadata, f.prmResult, f.authRequired)
		if explanation != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + explanation + "\n"
		}
	}
	if f.config.LLMExplain {
		explanation, err := buildLLMExplanation(f.config, report)
		if err != nil {
			message := fmt.Sprintf("LLM explanation unavailable: %v", err)
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\n" + message + "\n"
			summary.MD = strings.TrimSpace(summary.MD) + "\n\n## LLM explanation\n\n" + message + "\n"
		} else if explanation != "" {
			summary.Stdout = strings.TrimSpace(summary.Stdout) + "\n\nLLM explanation\n" + explanation + "\n"
			summary.MD = strings.TrimSpace(summary.MD) + "\n\n## LLM explanation\n\n" + explanation + "\n"
		}
	}
	summary.Trace = f.trace
	return summary
}

// runScanFunnel is the main entry point for running the scan funnel.
func runScanFunnel(config scanConfig, stdout io.Writer, verboseOutput io.Writer) (scanReport, scanSummary, error) {
	f := newFunnel(config, stdout, verboseOutput)

	if err := f.run(); err != nil {
		return scanReport{}, scanSummary{}, err
	}

	report := f.buildReport()
	summary := f.buildScanSummary(report)

	if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
		return report, scanSummary{}, err
	}

	return report, summary, nil
}
