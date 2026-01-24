package cli

import (
	"flag"
	"fmt"
	"io"
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
	fs.Int("timeout", 60, "")
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

	_ = headers
	_ = profile

	fmt.Fprintln(stdout, "scan functionality not implemented in v0.1 stub")
	return 0
}

func runMatrix(args []string, stdout, stderr io.Writer) int {
	if hasHelp(args) {
		fmt.Fprint(stdout, matrixHelp)
		return 0
	}

	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "table", "")
	failOn := fs.String("fail-on", "high", "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <mcp_url> is required")
		return 3
	}

	if !isAllowed(*format, "table", "md", "json") {
		fmt.Fprintln(stderr, "error: --format must be one of table, md, json")
		return 3
	}

	if !isAllowed(*failOn, "none", "low", "medium", "high") {
		fmt.Fprintln(stderr, "error: --fail-on must be one of none, low, medium, high")
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
	target := fs.String("target", "", "")
	fs.Bool("explain", false, "")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: <FINDING_CODE> is required")
		return 3
	}

	if *target == "" {
		fmt.Fprintln(stderr, "error: --target is required")
		return 3
	}

	if !isAllowed(*target, "fastapi", "nginx", "envoy", "generic") {
		fmt.Fprintln(stderr, "error: --target must be one of fastapi, nginx, envoy, generic")
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

func isAllowed(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
