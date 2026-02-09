package scan

// llm.go - LLM selection for scan explanations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ buildLLMExplanation                 │ Dispatch explanation generation to configured provider     │
// │ buildLLMPrompt                      │ Construct the prompt for LLM responses                     │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"fmt"
	"strings"
)

const llmSystemPrompt = "You are a compliance analyst for MCP OAuth servers. " +
	"Provide a detailed, spec-grounded explanation of the scan outcome. " +
	"Use MCP 2025-11-25, RFC 9728, RFC 8414, RFC 3986, RFC 8707, RFC 7636, " +
	"RFC 7591, and JSON-RPC 2.0 as applicable, and call out which " +
	"requirements apply in this case."

// buildLLMExplanation generates a spec-grounded explanation of scan results using an LLM.
//
// Inputs:
//   - config.OpenAIAPIKey: OpenAI API key (uses OpenAI if set)
//   - config.AnthropicAPIKey: Anthropic API key (uses Anthropic if OpenAI not set)
//   - config.LLMMaxTokens: Maximum output tokens for the response (default: 700)
//   - report: The scan report containing findings and evidence to explain
//
// Outputs:
//   - string: LLM-generated explanation text
//   - error: Non-nil if no API key provided or API call fails
func buildLLMExplanation(config ScanConfig, report ScanReport) (string, error) {
	// Use default max tokens if not set
	if config.LLMMaxTokens <= 0 {
		config.LLMMaxTokens = 700
	}
	if config.OpenAIAPIKey != "" {
		return buildOpenAIExplanation(config, report)
	}
	if config.AnthropicAPIKey != "" {
		return buildAnthropicExplanation(config, report)
	}
	return "", fmt.Errorf("missing LLM API key (provide --openai-api-key or --anthropic-api-key)")
}

// buildLLMPrompt constructs the prompt sent to the LLM for scan explanation.
//
// The prompt is structured to give the LLM full context about the scan:
//
//  1. Instructions: Asks the LLM to analyze results and explain failures with
//     spec references (MCP 2025-11-25, RFC 9728, RFC 8414, JSON-RPC 2.0).
//
//  2. Scan context: Includes target URL, MCP mode, and RFC mode from the report
//     so the LLM understands what strictness level was applied.
//
//  3. All steps: Lists every scan step with ID, name, status (PASS/FAIL/SKIP),
//     and detail. This shows the full funnel progression.
//
//  4. Failed steps (if any): Repeats only the failed steps for emphasis,
//     making it easy for the LLM to focus on what went wrong.
//
//  5. All findings: Lists each finding with its code, severity, confidence,
//     and all evidence lines. This provides the diagnostic details.
//
//  6. Primary Finding: Highlights the highest-priority finding separately.
//     When multiple findings exist, the LLM is instructed to focus on this one.
//
// Inputs:
//   - _: Scan configuration (unused, reserved for future context)
//   - report: The scan report containing target, steps, findings, and primary finding
//
// Outputs:
//   - string: Formatted prompt text ready to send to the LLM
func buildLLMPrompt(_ ScanConfig, report ScanReport) string {
	var out strings.Builder
	fmt.Fprintln(&out, "Analyze the AuthProbe scan results and explain why the failure is valid and justified, or if not, what should be changed.")
	fmt.Fprintln(&out, "Include spec references (MCP 2025-11-25, RFC 9728, RFC 8414, JSON-RPC 2.0) and describe correct server behavior.")
	if len(report.Findings) > 1 && report.PrimaryFinding.Code != "" {
		fmt.Fprintf(&out, "There are %d findings; only explain the highest priority failure (the primary finding below).\n", len(report.Findings))
	}
	fmt.Fprintln(&out, "")
	fmt.Fprintf(&out, "Target: %s\n", report.Target)
	fmt.Fprintf(&out, "MCP mode: %s\n", report.MCPMode)
	fmt.Fprintf(&out, "RFC mode: %s\n", report.RFCMode)
	fmt.Fprintln(&out, "")
	fmt.Fprintln(&out, "Steps:")
	for _, step := range report.Steps {
		line := fmt.Sprintf("- [%d] %s: %s", step.ID, step.Name, step.Status)
		if strings.TrimSpace(step.Detail) != "" {
			line = fmt.Sprintf("%s (%s)", line, strings.TrimSpace(step.Detail))
		}
		fmt.Fprintln(&out, line)
	}
	failedCount := 0
	for _, step := range report.Steps {
		if step.Status == "FAIL" {
			failedCount++
		}
	}
	if failedCount > 0 {
		fmt.Fprintln(&out, "")
		fmt.Fprintln(&out, "Failed steps:")
		for _, step := range report.Steps {
			if step.Status != "FAIL" {
				continue
			}
			line := fmt.Sprintf("- [%d] %s", step.ID, step.Name)
			if strings.TrimSpace(step.Detail) != "" {
				line = fmt.Sprintf("%s: %s", line, strings.TrimSpace(step.Detail))
			}
			fmt.Fprintln(&out, line)
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintln(&out, "")
		fmt.Fprintln(&out, "Findings:")
		for _, f := range report.Findings {
			fmt.Fprintf(&out, "- %s (%s, confidence %.2f)\n", f.Code, f.Severity, f.Confidence)
			for _, evidence := range f.Evidence {
				fmt.Fprintf(&out, "  - Evidence: %s\n", evidence)
			}
		}
	}
	if report.PrimaryFinding.Code != "" {
		fmt.Fprintln(&out, "")
		fmt.Fprintf(&out, "Primary Finding: %s (%s, confidence %.2f)\n", report.PrimaryFinding.Code, report.PrimaryFinding.Severity, report.PrimaryFinding.Confidence)
		for _, evidence := range report.PrimaryFinding.Evidence {
			fmt.Fprintf(&out, "- Evidence: %s\n", evidence)
		}
	}
	return strings.TrimSpace(out.String())
}
