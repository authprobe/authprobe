package cli

import "strings"

func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]struct{}{
		"-p":                {},
		"--profile":         {},
		"-H":                {},
		"--header":          {},
		"--proxy":           {},
		"--timeout":         {},
		"--connect-timeout": {},
		"--retries":         {},
		"--mcp":             {},
		"--rfc":             {},
		"--fail-on":         {},
		"--json":            {},
		"--md":              {},
		"--sarif":           {},
		"--bundle":          {},
		"--output-dir":      {},
		"--tool-detail":     {},
	}

	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if _, ok := valueFlags[arg]; ok && !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}

	return append(flags, positionals...)
}
