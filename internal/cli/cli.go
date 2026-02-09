package cli

// cli.go - Command-line interface entry points and flag parsing
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Run                                 │ Main entry point: routes to scan/help commands             │
// │ runScan                             │ Execute scan command with parsed flags                     │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ isStdoutPath                        │ Check if output path is "-" (stdout)                       │
// │ hasHelp                             │ Check if args contain help flag                            │
// │ isHelp                              │ Check if single arg is help flag                           │
// │ toolTitle                           │ Format MCP tool name with description                      │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"authprobe/internal/scan"
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
	fs.Var(&headers, "header", "")
	fs.Var(&headers, "H", "")
	timeout := fs.Int("timeout", 8, "")
	fs.String("mcp", "best-effort", "")
	fs.String("rfc", "best-effort", "")
	fs.Bool("allow-private-issuers", false, "")
	// Skip TLS certificate verification; useful for dev/testing with self-signed certs
	fs.Bool("insecure", false, "")
	// Disable automatic HTTP redirect following; useful for debugging redirect chains
	// and analyzing redirect behavior without following to final destination
	fs.Bool("no-follow-redirects", false, "")
	// Exit code control for CI: exit 2 if primary finding severity >= threshold.
	// Options: none (never fail), low, medium, high (default).
	fs.String("fail-on", "high", "")
	fs.String("json", "", "")
	fs.String("md", "", "")
	fs.String("trace-ascii", "", "")
	fs.String("bundle", "", "")
	fs.String("output-dir", "", "")
	noRedact := fs.Bool("no-redact", false, "")
	traceFailure := fs.Bool("trace-failure", false, "")
	verbose := fs.Bool("verbose", false, "")
	fs.BoolVar(verbose, "v", false, "")
	explain := fs.Bool("explain", false, "")
	fs.BoolVar(explain, "e", false, "")
	toolList := fs.Bool("tool-list", false, "")
	fs.BoolVar(toolList, "l", false, "")
	toolDetail := fs.String("tool-detail", "", "")
	fs.StringVar(toolDetail, "d", "", "")
	openAIAPIKey := fs.String("openai-api-key", "", "")
	anthropicAPIKey := fs.String("anthropic-api-key", "", "")
	llmMaxTokens := fs.Int("llm-max-tokens", 700, "")

	args = normalizeScanArgs(args)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	config := scan.ScanConfig{
		Target:              fs.Arg(0),
		Command:             "authprobe scan " + strings.Join(args, " "),
		Headers:             headers,
		Timeout:             time.Duration(*timeout) * time.Second,
		Verbose:             *verbose,
		Explain:             *explain,
		OpenAIAPIKey:        strings.TrimSpace(*openAIAPIKey),
		AnthropicAPIKey:     strings.TrimSpace(*anthropicAPIKey),
		LLMMaxTokens:        *llmMaxTokens,
		FailOn:              fs.Lookup("fail-on").Value.String(),
		MCPMode:             fs.Lookup("mcp").Value.String(),
		RFCMode:             fs.Lookup("rfc").Value.String(),
		AllowPrivateIssuers: fs.Lookup("allow-private-issuers").Value.String() == "true",
		Insecure:            fs.Lookup("insecure").Value.String() == "true",
		NoFollowRedirects:   fs.Lookup("no-follow-redirects").Value.String() == "true",
		Redact:              !*noRedact,
		TraceFailure:        *traceFailure,
		JSONPath:            fs.Lookup("json").Value.String(),
		MDPath:              fs.Lookup("md").Value.String(),
		TraceASCIIPath:      fs.Lookup("trace-ascii").Value.String(),
		BundlePath:          fs.Lookup("bundle").Value.String(),
		OutputDir:           fs.Lookup("output-dir").Value.String(),
	}
	if config.OpenAIAPIKey == "" {
		config.OpenAIAPIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if config.AnthropicAPIKey == "" {
		config.AnthropicAPIKey = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	}
	config.LLMExplain = config.OpenAIAPIKey != "" || config.AnthropicAPIKey != ""

	if *toolList && *toolDetail != "" {
		fmt.Fprintln(stderr, "error: --tool-list and --tool-detail cannot be used together")
		return 3
	}
	if *toolList || *toolDetail != "" {
		client := &http.Client{Timeout: config.Timeout}
		if config.Insecure {
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		if config.NoFollowRedirects {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
		trace := []scan.TraceEntry{}
		tools, err := scan.FetchMCPTools(client, config, &trace, stdout)
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
	if isStdoutPath(config.JSONPath) || isStdoutPath(config.MDPath) || isStdoutPath(config.TraceASCIIPath) {
		scanStdout = io.Discard
	}
	verboseWriter := scanStdout
	var verboseBuffer strings.Builder
	shouldCaptureVerbose := config.Verbose && (config.MDPath != "" || config.BundlePath != "")
	if shouldCaptureVerbose {
		verboseWriter = io.MultiWriter(scanStdout, &verboseBuffer)
	}

	report, summary, err := scan.RunScanFunnel(config, scanStdout, verboseWriter)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}
	if shouldCaptureVerbose && verboseBuffer.Len() > 0 {
		summary.MD = scan.AppendVerboseMarkdown(summary.MD, verboseBuffer.String())
	}

	if err := scan.WriteOutputs(report, summary, config); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if scan.ShouldFail(report.PrimaryFinding, config.FailOn) {
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

func toolTitle(tool scan.MCPToolDetail) string {
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
