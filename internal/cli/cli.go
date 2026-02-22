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
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"authprobe/internal/scan"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

var versionInfo = VersionInfo{
	Version: "dev",
	Commit:  "none",
	Date:    "unknown",
}

// SetVersionInfo updates runtime version metadata used by --version output.
// Inputs: VersionInfo values from build-time ldflags.
// Outputs: none (mutates package-level versionInfo).
func SetVersionInfo(info VersionInfo) {
	if info.Version != "" {
		versionInfo.Version = info.Version
	}
	if info.Commit != "" {
		versionInfo.Commit = info.Commit
	}
	if info.Date != "" {
		versionInfo.Date = info.Date
	}
}

// VersionString returns the formatted version banner for CLI output.
// Inputs: none.
// Outputs: single-line version string.
func VersionString() string {
	return fmt.Sprintf("authprobe %s (commit %s, built %s)", versionInfo.Version, versionInfo.Commit, versionInfo.Date)
}

type stringSlice []string

// String renders the header flag accumulator for debugging and flag package output.
// Inputs: receiver state.
// Outputs: formatted slice string.
func (s *stringSlice) String() string {
	return fmt.Sprintf("%v", []string(*s))
}

// Set appends a header flag value to the accumulator.
// Inputs: one header string value.
// Outputs: nil error for flag.Value compatibility.
func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Run dispatches top-level CLI commands and returns process exit code.
// Inputs: argv-like args slice, stdout writer, stderr writer.
// Outputs: integer exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Fprint(stdout, rootHelp)
		return 0
	}

	switch args[0] {
	case "--version", "version":
		fmt.Fprintln(stdout, VersionString())
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "mcp":
		return runMCP(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		fmt.Fprint(stderr, rootHelp)
		return 3
	}
}

// runScan parses scan flags, executes probes, and writes reports/output.
// Inputs: scan args, stdout writer, stderr writer.
// Outputs: integer exit code.
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
	stdioCommand := fs.String("stdio-command", "", "")

	args = normalizeScanArgs(args)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if *stdioCommand == "" && fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required unless --stdio-command is provided")
		return 3
	}
	if *stdioCommand != "" && fs.NArg() > 1 {
		fmt.Fprintln(stderr, "error: provide at most one <mcp_url> when using --stdio-command")
		return 3
	}
	target := ""
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	}

	config := scan.NewBaseConfig(scan.BaseConfigInput{
		Target:              target,
		Command:             "authprobe scan " + strings.Join(args, " "),
		Headers:             headers,
		Timeout:             time.Duration(*timeout) * time.Second,
		MCPProbeTimeout:     2 * time.Second,
		MCPMode:             fs.Lookup("mcp").Value.String(),
		MCPProtocolVersion:  scan.SupportedMCPProtocolVersion,
		RFCMode:             fs.Lookup("rfc").Value.String(),
		AllowPrivateIssuers: fs.Lookup("allow-private-issuers").Value.String() == "true",
		Insecure:            fs.Lookup("insecure").Value.String() == "true",
		NoFollowRedirects:   fs.Lookup("no-follow-redirects").Value.String() == "true",
		TraceFailure:        *traceFailure,
		Redact:              !*noRedact,
	})
	config.Verbose = *verbose
	config.Explain = *explain
	config.OpenAIAPIKey = strings.TrimSpace(*openAIAPIKey)
	config.AnthropicAPIKey = strings.TrimSpace(*anthropicAPIKey)
	config.LLMMaxTokens = *llmMaxTokens
	config.FailOn = fs.Lookup("fail-on").Value.String()
	config.JSONPath = fs.Lookup("json").Value.String()
	config.MDPath = fs.Lookup("md").Value.String()
	config.TraceASCIIPath = fs.Lookup("trace-ascii").Value.String()
	config.BundlePath = fs.Lookup("bundle").Value.String()
	config.OutputDir = fs.Lookup("output-dir").Value.String()
	if config.OpenAIAPIKey == "" {
		config.OpenAIAPIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if config.AnthropicAPIKey == "" {
		config.AnthropicAPIKey = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	}
	config.LLMExplain = config.OpenAIAPIKey != "" || config.AnthropicAPIKey != ""

	if strings.TrimSpace(*stdioCommand) != "" {
		gatewayPath, err := gatewayPathFromTarget(target)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 3
		}
		gatewayTarget, cleanup, err := scan.StartStdioGateway(*stdioCommand, gatewayPath, config.Timeout)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 3
		}
		defer cleanup()
		config.Target = gatewayTarget
		if target == "" {
			config.Command = "authprobe scan --stdio-command " + *stdioCommand
		}
	}

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

// isStdoutPath checks whether a destination path is stdout shorthand.
// Inputs: path string.
// Outputs: true when path is "-".
func isStdoutPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	return trimmed == "-" || trimmed == "/dev/stdout"
}

// hasHelp returns true when args contain any recognized help flag.
// Inputs: argument list.
// Outputs: boolean help indicator.
func hasHelp(args []string) bool {
	for _, arg := range args {
		if isHelp(arg) {
			return true
		}
	}
	return false
}

// isHelp determines whether a single token is a help token.
// Inputs: one argument token.
// Outputs: boolean help indicator.
func isHelp(arg string) bool {
	return arg == "-h" || arg == "--help"
}

// toolTitle extracts a human-friendly tool title from MCP tool metadata.
// Inputs: tool detail structure.
// Outputs: preferred title string or empty string.
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

// gatewayPathFromTarget derives the HTTP path for stdio bridge mode.
// Inputs: optional target URL.
// Outputs: normalized path or error.
func gatewayPathFromTarget(target string) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "/", nil
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed, nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid stdio target URL: %w", err)
	}
	if parsed.Path == "" {
		return "/", nil
	}
	return parsed.Path, nil
}
