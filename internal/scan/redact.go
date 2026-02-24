package scan

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func redactHeaderValue(key, value string, redact bool) string {
	if redact && isSensitiveHeader(key) {
		return "[redacted]"
	}
	return value
}

func sanitizeHeadersForTrace(headers http.Header, redact bool) map[string]string {
	redacted := map[string]string{}
	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		redacted[key] = redactHeaderValue(key, value, redact)
	}
	return redacted
}

func isSensitiveField(key string) bool {
	lower := strings.ToLower(key)
	switch lower {
	case "access_token", "refresh_token", "id_token", "client_secret", "client_assertion", "assertion", "password", "token":
		return true
	default:
		return strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password")
	}
}

func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if isSensitiveField(key) {
				typed[key] = "[redacted]"
				continue
			}
			typed[key] = redactJSONValue(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = redactJSONValue(item)
		}
		return typed
	default:
		return value
	}
}

func redactBody(contentType string, body []byte, redact bool) []byte {
	if len(body) == 0 || !redact {
		return body
	}
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "application/json") || strings.Contains(lower, "+json") {
		var payload any
		if err := json.Unmarshal(body, &payload); err != nil {
			return body
		}
		payload = redactJSONValue(payload)
		redacted, err := json.Marshal(payload)
		if err != nil {
			return body
		}
		return redacted
	}
	if strings.Contains(lower, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return body
		}
		for key := range values {
			if isSensitiveField(key) {
				values.Set(key, "[redacted]")
			}
		}
		return []byte(values.Encode())
	}
	return body
}
