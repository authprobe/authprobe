package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type stringSlice []string

func (s *stringSlice) String() string {
	return fmt.Sprintf("%v", []string(*s))
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, rootHelp)
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "matrix":
		return runMatrix(args[1:], stdout, stderr)
	case "fix":
		return runFix(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		fmt.Fprint(stderr, rootHelp)
		return 3
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	if hasHelp(args) {
		fmt.Fprint(stdout, scanHelp)
		return 0
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var headers stringSlice
	profile := fs.String("profile", "generic", "")
	fs.StringVar(profile, "p", "generic", "")
	fs.Var(&headers, "header", "")
	fs.Var(&headers, "H", "")
	fs.String("proxy", "", "")
	timeout := fs.Int("timeout", 60, "")
	fs.Int("connect-timeout", 10, "")
	fs.Int("retries", 1, "")
	fs.Bool("insecure", false, "")
	fs.Bool("no-follow-redirects", false, "")
	fs.String("fail-on", "high", "")
	fs.String("json", "", "")
	fs.String("md", "", "")
	fs.String("sarif", "", "")
	fs.String("bundle", "", "")
	fs.String("output-dir", "", "")
	verbose := fs.Bool("verbose", false, "")
	fs.Bool("no-redact", false, "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	wellKnownURLs, err := buildWellKnownURLs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	for _, wellKnownURL := range wellKnownURLs {
		req, err := http.NewRequest(http.MethodGet, wellKnownURL, nil)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 3
		}

		for _, header := range headers {
			key, value, err := parseHeader(header)
			if err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 3
			}
			req.Header.Add(key, value)
		}

		if *verbose {
			if err := writeVerboseRequest(stdout, req); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 3
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 3
		}
		_ = profile

		if *verbose {
			if err := writeVerboseResponse(stdout, resp); err != nil {
				resp.Body.Close()
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 3
			}
		}

		statusNote := ""
		if resp.StatusCode == http.StatusNotFound {
			parsedURL, err := url.Parse(wellKnownURL)
			if err == nil && strings.HasSuffix(parsedURL.Path, "/.well-known/oauth-protected-resource") {
				statusNote = " (https://datatracker.ietf.org/doc/html/rfc9728#section-3.1)"
			}
		}
		fmt.Fprintf(stdout, "GET %s -> %s%s\n", wellKnownURL, resp.Status, statusNote)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			break
		}
	}
	return 0
}

func runMatrix(args []string, stdout, stderr io.Writer) int {
	if hasHelp(args) {
		fmt.Fprint(stdout, matrixHelp)
		return 0
	}

	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("format", "table", "")
	fs.String("fail-on", "high", "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	fmt.Fprintln(stdout, "matrix functionality not implemented in v0.1 stub")
	return 0
}

func runFix(args []string, stdout, stderr io.Writer) int {
	if hasHelp(args) {
		fmt.Fprint(stdout, fixHelp)
		return 0
	}

	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("target", "", "")
	fs.Bool("explain", false, "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <FINDING_CODE> is required")
		return 3
	}

	fmt.Fprintln(stdout, "fix functionality not implemented in v0.1 stub")
	return 0
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if isHelp(arg) {
			return true
		}
	}
	return false
}

func isHelp(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func buildWellKnownURLs(mcpURL string) ([]string, error) {
	parsed, err := url.Parse(mcpURL)
	if err != nil {
		return nil, fmt.Errorf("invalid mcp url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid mcp url: %q", mcpURL)
	}
	return []string{parsed.String()}, nil
}

func parseHeader(raw string) (string, string, error) {
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

func writeVerboseRequest(w io.Writer, req *http.Request) error {
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
	writeHeaders(w, req.Header, ">")
	writeBody(w, body, ">")
	return nil
}

func writeVerboseResponse(w io.Writer, resp *http.Response) error {
	body, err := drainBody(&resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	fmt.Fprintf(w, "< %s %s\n", resp.Proto, resp.Status)
	writeHeaders(w, resp.Header, "<")
	writeBody(w, body, "<")
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

func writeHeaders(w io.Writer, headers http.Header, prefix string) {
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
			fmt.Fprintf(w, "%s %s: %s\n", prefix, key, value)
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
