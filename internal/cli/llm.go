package cli

// llm.go - LLM selection for scan explanations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ buildLLMExplanation                 │ Dispatch explanation generation to configured provider     │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"fmt"
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
func buildLLMExplanation(config scanConfig, report scanReport) (string, error) {
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
