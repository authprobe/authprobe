package cli

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	fs.Bool("verbose", false, "")
	fs.Bool("no-redact", false, "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	wellKnownURL, err := buildWellKnownURL(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
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

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}
	defer resp.Body.Close()

	_ = profile

	fmt.Fprintf(stdout, "GET %s -> %s\n", wellKnownURL, resp.Status)
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

func buildWellKnownURL(mcpURL string) (string, error) {
	parsed, err := url.Parse(mcpURL)
	if err != nil {
		return "", fmt.Errorf("invalid mcp url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid mcp url: %q", mcpURL)
	}
	return (&url.URL{
		Scheme: parsed.Scheme,
		Host:   parsed.Host,
		Path:   "/.well-known/oauth-protected-resource",
	}).String(), nil
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
