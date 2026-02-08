package cli

// normalize.go - Command-line argument normalization
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ normalizeScanArgs                   │ Reorder args so flags appear before positional args        │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import "strings"

func normalizeScanArgs(args []string) []string {
	valueFlags := map[string]struct{}{
		"-H":            {},
		"--header":      {},
		"--timeout":     {},
		"--mcp":         {},
		"--rfc":         {},
		"--fail-on":     {},
		"--json":        {},
		"--md":          {},
		"--trace-ascii": {},
		"--bundle":      {},
		"--output-dir":  {},
		"-d":            {},
		"--tool-detail": {},
	}

	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if _, ok := valueFlags[arg]; ok && !strings.Contains(arg, "=") && i+1 < len(args) {
				nextArg := args[i+1]
				// Don't consume next arg as value if it looks like a URL (positional arg)
				// or if it looks like another flag (but allow single "-" as a valid value for stdout)
				if !looksLikeURL(nextArg) && !looksLikeFlag(nextArg) {
					i++
					flags = append(flags, nextArg)
				}
			}
			continue
		}
		positionals = append(positionals, arg)
	}

	return append(flags, positionals...)
}

// looksLikeURL returns true if the string looks like a URL (positional argument).
func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// looksLikeFlag returns true if the string looks like a flag.
// Single "-" is NOT considered a flag (it means stdout).
func looksLikeFlag(s string) bool {
	return len(s) > 1 && strings.HasPrefix(s, "-")
}
