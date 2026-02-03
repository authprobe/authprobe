package cli

// anthropic.go - Anthropic API integration for scan explanations
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ buildAnthropicExplanation           │ Generate a detailed, spec-focused explanation via Anthropic│
// │ extractAnthropicOutputText          │ Extract text from Anthropic responses payload              │
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

const anthropicMessagesURL = "https://api.anthropic.com/v1/messages"
const anthropicModel = "claude-sonnet-4-5-20250929"

type anthropicRequest struct {
	Model     string             `json:"model"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
	MaxTokens int                `json:"max_tokens"`
}

type anthropicMessage struct {
	Role    string             `json:"role"`
	Content []anthropicContent `json:"content"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
}

func buildAnthropicExplanation(config scanConfig, report scanReport) (string, error) {
	prompt := buildLLMPrompt(config, report)
	if strings.TrimSpace(prompt) == "" {
		return "", errors.New("unable to build Anthropic prompt")
	}

	payload := anthropicRequest{
		Model:  anthropicModel,
		System: llmSystemPrompt,
		Messages: []anthropicMessage{
			{
				Role: "user",
				Content: []anthropicContent{
					{
						Type: "text",
						Text: prompt,
					},
				},
			},
		},
		MaxTokens: 700,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, anthropicMessagesURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("x-api-key", config.AnthropicAPIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

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
		return "", fmt.Errorf("anthropic api status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var decoded anthropicResponse
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	explanation := extractAnthropicOutputText(decoded)
	if explanation == "" {
		return "", errors.New("anthropic response missing text output")
	}
	return explanation, nil
}

func extractAnthropicOutputText(resp anthropicResponse) string {
	for _, content := range resp.Content {
		if strings.TrimSpace(content.Text) != "" {
			return strings.TrimSpace(content.Text)
		}
	}
	return ""
}
