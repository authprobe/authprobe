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

const llmSystemPrompt = "You are a compliance analyst for MCP OAuth servers. Provide a detailed, spec-grounded explanation of the scan outcome. Use MCP 2025-11-25, RFC 9728, RFC 8414, RFC 3986, RFC 8707, RFC 7636, RFC 7591, and JSON-RPC 2.0 as applicable, and call out which requirements apply in this case."

func buildLLMExplanation(config scanConfig, report scanReport) (string, error) {
	if config.OpenAIAPIKey != "" {
		return buildOpenAIExplanation(config, report)
	}
	if config.AnthropicAPIKey != "" {
		return buildAnthropicExplanation(config, report)
	}
	return "", fmt.Errorf("missing LLM API key (provide --openai-api-key or --anthropic-api-key)")
}
