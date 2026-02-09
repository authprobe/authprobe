package cli

// openai.go - OpenAI API integration for scan explanations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ buildOpenAIExplanation              │ Generate a detailed, spec-focused explanation via OpenAI   │
// │ extractOpenAIOutputText             │ Extract text from OpenAI responses payload                 │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const openAIResponsesURL = "https://api.openai.com/v1/responses"
const openAIModel = "gpt-4.1-mini"

type openAIRequest struct {
	Model           string          `json:"model"`
	Input           []openAIMessage `json:"input"`
	MaxOutputTokens int             `json:"max_output_tokens,omitempty"`
}

type openAIMessage struct {
	Role    string          `json:"role"`
	Content []openAIContent `json:"content"`
}

type openAIContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type openAIResponse struct {
	Output []openAIOutput `json:"output"`
}

type openAIOutput struct {
	Content []openAIContent `json:"content"`
}

func buildOpenAIExplanation(config scanConfig, report scanReport) (string, error) {
	prompt := buildLLMPrompt(config, report)
	if strings.TrimSpace(prompt) == "" {
		return "", errors.New("unable to build OpenAI prompt")
	}

	payload := openAIRequest{
		Model: openAIModel,
		Input: []openAIMessage{
			{
				Role: "system",
				Content: []openAIContent{
					{
						Type: "input_text",
						Text: llmSystemPrompt,
					},
				},
			},
			{
				Role: "user",
				Content: []openAIContent{
					{
						Type: "input_text",
						Text: prompt,
					},
				},
			},
		},
		MaxOutputTokens: config.LLMMaxTokens,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, openAIResponsesURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+config.OpenAIAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("openai api status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded openAIResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	explanation := extractOpenAIOutputText(decoded)
	if explanation == "" {
		return "", errors.New("openai response missing text output")
	}
	return explanation, nil
}

func extractOpenAIOutputText(resp openAIResponse) string {
	for _, output := range resp.Output {
		for _, content := range output.Content {
			if strings.TrimSpace(content.Text) != "" {
				return strings.TrimSpace(content.Text)
			}
		}
	}
	return ""
}
