package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Client is a minimal HTTP JSON-RPC client used for MCP version negotiation.
type Client struct {
	HTTPClient *http.Client
}

// Do executes an HTTP request using the configured underlying HTTP client.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil {
		return nil, fmt.Errorf("nil client")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}
	return c.HTTPClient.Do(req)
}

// NegotiateMCPVersion initializes an MCP connection and negotiates a compatible protocol version.
func NegotiateMCPVersion(client *Client, endpoint string) (string, error) {
	const requestedVersion = mcpProtocolVersion

	type rpcEnvelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id,omitempty"`
		Method  string          `json:"method,omitempty"`
		Params  any             `json:"params,omitempty"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data,omitempty"`
		} `json:"error,omitempty"`
	}

	sendInitialize := func(version string) (*rpcEnvelope, error) {
		reqBody := rpcEnvelope{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "initialize",
			Params: map[string]any{
				"protocolVersion": version,
				"capabilities":    map[string]any{},
				"clientInfo": map[string]any{
					"name":    "authprobe",
					"version": "0.1",
				},
			},
		}

		payload, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal initialize request: %w", err)
		}

		httpReq, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("build initialize request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json, text/event-stream")
		httpReq.Header.Set("MCP-Protocol-Version", version)

		httpResp, err := client.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("send initialize request: %w", err)
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, fmt.Errorf("read initialize response: %w", err)
		}

		resp := &rpcEnvelope{}
		if err := json.Unmarshal(body, resp); err != nil {
			return nil, fmt.Errorf("decode initialize response: %w", err)
		}
		return resp, nil
	}

	extractSupportedVersions := func(errResp *rpcEnvelope) []string {
		if errResp == nil || errResp.Error == nil {
			return nil
		}
		versions := map[string]struct{}{}

		if len(errResp.Error.Data) > 0 {
			var dataMap map[string]any
			if err := json.Unmarshal(errResp.Error.Data, &dataMap); err == nil {
				if raw, ok := dataMap["supportedVersions"]; ok {
					switch v := raw.(type) {
					case []any:
						for _, item := range v {
							if s, ok := item.(string); ok {
								versions[strings.TrimSpace(s)] = struct{}{}
							}
						}
					case string:
						for _, part := range strings.Split(v, ",") {
							trimmed := strings.TrimSpace(part)
							if trimmed != "" {
								versions[trimmed] = struct{}{}
							}
						}
					}
				}
			}
		}

		dateVersionRE := regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
		for _, match := range dateVersionRE.FindAllString(errResp.Error.Message, -1) {
			versions[match] = struct{}{}
		}

		result := make([]string, 0, len(versions))
		for v := range versions {
			if v != "" {
				result = append(result, v)
			}
		}
		sort.Strings(result)
		return result
	}

	pickHighestCompatible := func(requested string, supported []string) string {
		best := ""
		for _, candidate := range supported {
			if candidate <= requested && candidate > best {
				best = candidate
			}
		}
		return best
	}

	initialResp, err := sendInitialize(requestedVersion)
	if err != nil {
		return "", err
	}
	if initialResp.Error == nil {
		var result struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(initialResp.Result, &result); err == nil && strings.TrimSpace(result.ProtocolVersion) != "" {
			return strings.TrimSpace(result.ProtocolVersion), nil
		}
		return requestedVersion, nil
	}

	if !strings.Contains(strings.ToLower(initialResp.Error.Message), "unsupported protocol version") {
		return "", fmt.Errorf("initialize failed: %s", initialResp.Error.Message)
	}

	supported := extractSupportedVersions(initialResp)
	if len(supported) == 0 {
		return "", fmt.Errorf("unsupported protocol version %q and no supported versions advertised", requestedVersion)
	}

	retryVersion := pickHighestCompatible(requestedVersion, supported)
	if retryVersion == "" {
		return "", fmt.Errorf("unsupported protocol version %q; server supports %v but none are compatible", requestedVersion, supported)
	}

	retryResp, err := sendInitialize(retryVersion)
	if err != nil {
		return "", err
	}
	if retryResp.Error != nil {
		return "", fmt.Errorf("initialize retry with %q failed: %s", retryVersion, retryResp.Error.Message)
	}

	var retryResult struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(retryResp.Result, &retryResult); err == nil && strings.TrimSpace(retryResult.ProtocolVersion) != "" {
		return strings.TrimSpace(retryResult.ProtocolVersion), nil
	}
	return retryVersion, nil
}
