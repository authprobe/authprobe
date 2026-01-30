package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	timeout := fs.Int("timeout", 8, "")
	fs.Int("connect-timeout", 10, "")
	fs.Int("retries", 1, "")
	fs.String("rfc9728", "best-effort", "")
	fs.String("rfc3986", "best-effort", "")
	fs.String("rfc8414", "best-effort", "")
	fs.String("rfc8707", "best-effort", "")
	fs.String("rfc9207", "best-effort", "")
	fs.String("rfc6750", "best-effort", "")
	fs.String("rfc7517", "best-effort", "")
	fs.String("rfc7519", "best-effort", "")
	fs.String("rfc7636", "best-effort", "")
	fs.String("rfc6749", "best-effort", "")
	fs.String("rfc1918", "best-effort", "")
	fs.String("rfc6890", "best-effort", "")
	fs.String("rfc9110", "best-effort", "")
	fs.Bool("allow-private-issuers", false, "")
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
	explain := fs.Bool("explain", false, "")
	showTrace := fs.Bool("show-trace", false, "")
	toolList := fs.Bool("tool-list", false, "")
	toolDetail := fs.String("tool-detail", "", "")

	args = normalizeScanArgs(args)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	config := scanConfig{
		Target:              fs.Arg(0),
		Profile:             *profile,
		Headers:             headers,
		Timeout:             time.Duration(*timeout) * time.Second,
		Verbose:             *verbose,
		Explain:             *explain,
		ShowTrace:           *showTrace,
		FailOn:              fs.Lookup("fail-on").Value.String(),
		RFC9728Mode:         fs.Lookup("rfc9728").Value.String(),
		RFC3986Mode:         fs.Lookup("rfc3986").Value.String(),
		RFC8414Mode:         fs.Lookup("rfc8414").Value.String(),
		RFC8707Mode:         fs.Lookup("rfc8707").Value.String(),
		RFC9207Mode:         fs.Lookup("rfc9207").Value.String(),
		RFC6750Mode:         fs.Lookup("rfc6750").Value.String(),
		RFC7517Mode:         fs.Lookup("rfc7517").Value.String(),
		RFC7519Mode:         fs.Lookup("rfc7519").Value.String(),
		RFC7636Mode:         fs.Lookup("rfc7636").Value.String(),
		RFC6749Mode:         fs.Lookup("rfc6749").Value.String(),
		RFC1918Mode:         fs.Lookup("rfc1918").Value.String(),
		RFC6890Mode:         fs.Lookup("rfc6890").Value.String(),
		RFC9110Mode:         fs.Lookup("rfc9110").Value.String(),
		AllowPrivateIssuers: fs.Lookup("allow-private-issuers").Value.String() == "true",
		NoFollowRedirects:   fs.Lookup("no-follow-redirects").Value.String() == "true",
		JSONPath:            fs.Lookup("json").Value.String(),
		MDPath:              fs.Lookup("md").Value.String(),
		BundlePath:          fs.Lookup("bundle").Value.String(),
		OutputDir:           fs.Lookup("output-dir").Value.String(),
	}

	if *toolList && *toolDetail != "" {
		fmt.Fprintln(stderr, "error: --tool-list and --tool-detail cannot be used together")
		return 3
	}
	if *toolList || *toolDetail != "" {
		client := &http.Client{Timeout: config.Timeout}
		if config.NoFollowRedirects {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
		trace := []traceEntry{}
		tools, err := fetchMCPTools(client, config, &trace, stdout)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 3
		}
		if *toolList {
			sort.Slice(tools, func(i, j int) bool {
				return tools[i].Name < tools[j].Name
			})
			maxName := 0
			for _, tool := range tools {
				if len(tool.Name) > maxName {
					maxName = len(tool.Name)
				}
			}
			for _, tool := range tools {
				title := toolTitle(tool)
				if title == "" {
					title = "-"
				}
				fmt.Fprintf(stdout, "%-*s  %s\n", maxName, tool.Name, title)
			}
			return 0
		}
		for _, tool := range tools {
			if tool.Name == *toolDetail {
				payload, err := json.MarshalIndent(tool, "", "  ")
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 3
				}
				fmt.Fprintln(stdout, string(payload))
				return 0
			}
		}
		fmt.Fprintf(stderr, "error: tool %q not found\n", *toolDetail)
		return 3
	}

	scanStdout := stdout
	if isStdoutPath(config.JSONPath) {
		scanStdout = io.Discard
	}
	verboseWriter := scanStdout
	var verboseBuffer strings.Builder
	shouldCaptureVerbose := config.Verbose && (config.MDPath != "" || config.BundlePath != "")
	if shouldCaptureVerbose {
		verboseWriter = io.MultiWriter(scanStdout, &verboseBuffer)
	}

	report, summary, err := runScanFunnel(config, scanStdout, verboseWriter)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}
	if shouldCaptureVerbose && verboseBuffer.Len() > 0 {
		summary.MD = appendVerboseMarkdown(summary.MD, verboseBuffer.String())
	}

	if err := writeOutputs(report, summary, config); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if shouldFail(report.PrimaryFinding, config.FailOn) {
		return 2
	}
	return 0
}

func isStdoutPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	return trimmed == "-" || trimmed == "/dev/stdout"
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

func toolTitle(tool mcpToolDetail) string {
	if tool.Annotations == nil {
		return ""
	}
	title, ok := tool.Annotations["title"]
	if !ok {
		return ""
	}
	if titleStr, ok := title.(string); ok {
		return titleStr
	}
	return ""
}

func writeVerboseHeading(w io.Writer, title string) {
	if title == "" {
		return
	}
	fmt.Fprintf(w, "\n== %s ==\n", title)
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
