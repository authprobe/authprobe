package llm

// llm.go - LLM provider dispatch for scan explanations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ BuildExplanation                    │ Dispatch explanation generation to configured provider     │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import "fmt"

// Request contains the parameters needed to generate an LLM explanation.
// It is intentionally decoupled from scan types to avoid import cycles.
type Request struct {
	OpenAIAPIKey    string
	AnthropicAPIKey string
	MaxTokens       int
	SystemPrompt    string
	Prompt          string
}

// BuildExplanation generates a spec-grounded explanation by dispatching to
// the configured LLM provider (OpenAI or Anthropic).
//
// Inputs:
//   - req.OpenAIAPIKey: OpenAI API key (uses OpenAI if set)
//   - req.AnthropicAPIKey: Anthropic API key (uses Anthropic if OpenAI not set)
//   - req.MaxTokens: Maximum output tokens for the response
//   - req.SystemPrompt: System prompt providing the LLM's role and context
//   - req.Prompt: User prompt with scan results to explain
//
// Outputs:
//   - string: LLM-generated explanation text
//   - error: Non-nil if no API key provided or API call fails
func BuildExplanation(req Request) (string, error) {
	if req.MaxTokens <= 0 {
		req.MaxTokens = 700
	}
	if req.OpenAIAPIKey != "" {
		return buildOpenAIExplanation(req)
	}
	if req.AnthropicAPIKey != "" {
		return buildAnthropicExplanation(req)
	}
	return "", fmt.Errorf("missing LLM API key (provide --openai-api-key or --anthropic-api-key)")
}
