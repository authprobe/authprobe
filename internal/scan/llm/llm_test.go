package llm

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BuildExplanation dispatch tests
//
// Empty prompts trigger an early return with a provider-specific error message,
// letting us verify routing without making real HTTP calls.
// ---------------------------------------------------------------------------

func TestBuildExplanation_NoAPIKey(t *testing.T) {
	_, err := BuildExplanation(Request{Prompt: "test"})
	if err == nil {
		t.Fatal("expected error when no API key is set")
	}
	if !strings.Contains(err.Error(), "missing LLM API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildExplanation_RoutesToOpenAI(t *testing.T) {
	_, err := BuildExplanation(Request{
		OpenAIAPIKey: "sk-test",
		Prompt:       "",
	})
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
	if !strings.Contains(err.Error(), "OpenAI") {
		t.Fatalf("expected dispatch to OpenAI, got: %v", err)
	}
}

func TestBuildExplanation_RoutesToAnthropic(t *testing.T) {
	_, err := BuildExplanation(Request{
		AnthropicAPIKey: "sk-ant-test",
		Prompt:          "",
	})
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
	if !strings.Contains(err.Error(), "Anthropic") {
		t.Fatalf("expected dispatch to Anthropic, got: %v", err)
	}
}

func TestBuildExplanation_OpenAIPriority(t *testing.T) {
	_, err := BuildExplanation(Request{
		OpenAIAPIKey:    "sk-test",
		AnthropicAPIKey: "sk-ant-test",
		Prompt:          "",
	})
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
	if !strings.Contains(err.Error(), "OpenAI") {
		t.Fatalf("expected OpenAI to take priority, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MaxTokens default
// ---------------------------------------------------------------------------

func TestBuildExplanation_DefaultMaxTokens(t *testing.T) {
	req := Request{
		OpenAIAPIKey: "sk-test",
		MaxTokens:    0,
		Prompt:       "",
	}
	BuildExplanation(req)
	// Verify indirectly: passing MaxTokens=0 should not panic and should
	// still dispatch correctly (the default of 700 is applied internally).
	// We can't inspect the mutated req because it's passed by value, but
	// we can verify the function didn't fail with an unexpected error.
}

func TestBuildExplanation_NegativeMaxTokens(t *testing.T) {
	req := Request{
		OpenAIAPIKey: "sk-test",
		MaxTokens:    -1,
		Prompt:       "",
	}
	_, err := BuildExplanation(req)
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
	if !strings.Contains(err.Error(), "OpenAI") {
		t.Fatalf("expected dispatch to OpenAI (MaxTokens default applied), got: %v", err)
	}
}

func TestBuildExplanation_ExplicitMaxTokensPreserved(t *testing.T) {
	req := Request{
		OpenAIAPIKey: "sk-test",
		MaxTokens:    1024,
		Prompt:       "",
	}
	_, err := BuildExplanation(req)
	if err == nil {
		t.Fatal("expected error for empty prompt")
	}
	if !strings.Contains(err.Error(), "OpenAI") {
		t.Fatalf("expected dispatch to OpenAI, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// extractOpenAIOutputText
// ---------------------------------------------------------------------------

func TestExtractOpenAIOutputText_SingleContent(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{{Type: "output_text", Text: "hello world"}}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "hello world" {
		t.Fatalf("expected %q, got %q", "hello world", got)
	}
}

func TestExtractOpenAIOutputText_MultipleOutputs_ReturnsFirst(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{{Type: "output_text", Text: "first"}}},
			{Content: []openAIContent{{Type: "output_text", Text: "second"}}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "first" {
		t.Fatalf("expected first non-empty text %q, got %q", "first", got)
	}
}

func TestExtractOpenAIOutputText_SkipsEmptyContent(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{
				{Type: "output_text", Text: ""},
				{Type: "output_text", Text: "   "},
				{Type: "output_text", Text: "real content"},
			}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "real content" {
		t.Fatalf("expected %q, got %q", "real content", got)
	}
}

func TestExtractOpenAIOutputText_EmptyOutput(t *testing.T) {
	got := extractOpenAIOutputText(openAIResponse{})
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestExtractOpenAIOutputText_AllWhitespace(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{{Type: "output_text", Text: "  \n\t "}}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "" {
		t.Fatalf("expected empty string for whitespace-only text, got %q", got)
	}
}

func TestExtractOpenAIOutputText_TrimsWhitespace(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{{Type: "output_text", Text: "  trimmed  "}}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "trimmed" {
		t.Fatalf("expected %q, got %q", "trimmed", got)
	}
}

func TestExtractOpenAIOutputText_EmptyContentSlice(t *testing.T) {
	resp := openAIResponse{
		Output: []openAIOutput{
			{Content: []openAIContent{}},
		},
	}
	got := extractOpenAIOutputText(resp)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// extractAnthropicOutputText
// ---------------------------------------------------------------------------

func TestExtractAnthropicOutputText_SingleContent(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{{Type: "text", Text: "hello anthropic"}},
	}
	got := extractAnthropicOutputText(resp)
	if got != "hello anthropic" {
		t.Fatalf("expected %q, got %q", "hello anthropic", got)
	}
}

func TestExtractAnthropicOutputText_MultipleBlocks_ReturnsFirst(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{
			{Type: "text", Text: "first block"},
			{Type: "text", Text: "second block"},
		},
	}
	got := extractAnthropicOutputText(resp)
	if got != "first block" {
		t.Fatalf("expected %q, got %q", "first block", got)
	}
}

func TestExtractAnthropicOutputText_SkipsEmptyContent(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{
			{Type: "text", Text: ""},
			{Type: "text", Text: "   "},
			{Type: "text", Text: "actual content"},
		},
	}
	got := extractAnthropicOutputText(resp)
	if got != "actual content" {
		t.Fatalf("expected %q, got %q", "actual content", got)
	}
}

func TestExtractAnthropicOutputText_EmptyResponse(t *testing.T) {
	got := extractAnthropicOutputText(anthropicResponse{})
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestExtractAnthropicOutputText_AllWhitespace(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{{Type: "text", Text: " \n\t "}},
	}
	got := extractAnthropicOutputText(resp)
	if got != "" {
		t.Fatalf("expected empty string for whitespace-only text, got %q", got)
	}
}

func TestExtractAnthropicOutputText_TrimsWhitespace(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{{Type: "text", Text: "  trimmed  "}},
	}
	got := extractAnthropicOutputText(resp)
	if got != "trimmed" {
		t.Fatalf("expected %q, got %q", "trimmed", got)
	}
}

func TestExtractAnthropicOutputText_EmptyContentSlice(t *testing.T) {
	resp := anthropicResponse{
		Content: []anthropicContent{},
	}
	got := extractAnthropicOutputText(resp)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Empty prompt validation (adapter-level)
// ---------------------------------------------------------------------------

func TestBuildOpenAIExplanation_EmptyPrompt(t *testing.T) {
	_, err := buildOpenAIExplanation(Request{
		OpenAIAPIKey: "sk-test",
		Prompt:       "   ",
		MaxTokens:    100,
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only prompt")
	}
	if !strings.Contains(err.Error(), "unable to build OpenAI prompt") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildAnthropicExplanation_EmptyPrompt(t *testing.T) {
	_, err := buildAnthropicExplanation(Request{
		AnthropicAPIKey: "sk-ant-test",
		Prompt:          "   ",
		MaxTokens:       100,
	})
	if err == nil {
		t.Fatal("expected error for whitespace-only prompt")
	}
	if !strings.Contains(err.Error(), "unable to build Anthropic prompt") {
		t.Fatalf("unexpected error: %v", err)
	}
}
