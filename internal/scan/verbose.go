package scan

// verbose.go - HTTP request/response verbose output helpers
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ ParseHeader                         │ Parse "Key: Value" header string                           │
// │ writeVerboseHeading                 │ Write section heading for verbose output                   │
// │ writeVerboseRequest                 │ Write HTTP request details for verbose output              │
// │ writeVerboseResponse                │ Write HTTP response details for verbose output             │
// │ drainBody                           │ Read and restore HTTP response body                        │
// │ writeHeaders                        │ Write HTTP headers with prefix                             │
// │ writeBody                           │ Write HTTP body with prefix                                │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// ParseHeader parses a raw "Key: Value" header string into key and value parts.
func ParseHeader(raw string) (string, string, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format %q", raw)
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", fmt.Errorf("invalid header format %q", raw)
	}
	return key, value, nil
}

func writeVerboseHeading(w io.Writer, title string) {
	if title == "" {
		return
	}
	fmt.Fprintf(w, "\n== %s ==\n", title)
}

func writeVerboseRequest(w io.Writer, req *http.Request, redact bool) error {
	body, err := drainBody(&req.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}

	target := req.URL.RequestURI()
	if target == "" {
		target = req.URL.String()
	}

	fmt.Fprintf(w, "> %s %s %s\n", req.Method, target, req.Proto)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host != "" {
		fmt.Fprintf(w, "> Host: %s\n", host)
	}
	writeHeaders(w, req.Header, ">", redact)
	contentType := req.Header.Get("Content-Type")
	writeBody(w, redactBody(contentType, body, redact), ">")
	return nil
}

func writeVerboseResponse(w io.Writer, resp *http.Response, redact bool) error {
	body, err := drainBody(&resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	fmt.Fprintf(w, "< %s %s\n", resp.Proto, resp.Status)
	writeHeaders(w, resp.Header, "<", redact)
	contentType := resp.Header.Get("Content-Type")
	writeBody(w, redactBody(contentType, body, redact), "<")
	return nil
}

func drainBody(body *io.ReadCloser) ([]byte, error) {
	if body == nil || *body == nil {
		return nil, nil
	}
	payload, err := io.ReadAll(*body)
	if err != nil {
		return nil, err
	}
	*body = io.NopCloser(bytes.NewReader(payload))
	return payload, nil
}

func writeHeaders(w io.Writer, headers http.Header, prefix string, redact bool) {
	if len(headers) == 0 {
		return
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range headers[key] {
			fmt.Fprintf(w, "%s %s: %s\n", prefix, key, redactHeaderValue(key, value, redact))
		}
	}
}

func writeBody(w io.Writer, body []byte, prefix string) {
	fmt.Fprintf(w, "%s\n", prefix)
	if len(body) == 0 {
		fmt.Fprintf(w, "%s (empty body)\n", prefix)
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		fmt.Fprintf(w, "%s %s\n", prefix, line)
	}
}
