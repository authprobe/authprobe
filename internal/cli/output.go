package cli

// output.go - Output formatting and file writing for scan results
//
// Function Index:
// ┌─────────────────────────────────────┬────────────────────────────────────────────────────────────┐
// │ Function                            │ Purpose                                                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Summary Building                    │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ buildSummary                        │ Build scanSummary with stdout, markdown, and JSON          │
// │ buildScanExplanation                │ Generate human-readable RFC 9728 explanation               │
// │ renderMarkdown                      │ Generate markdown report from scan results                 │
// │ appendVerboseMarkdown               │ Append verbose output section to markdown                  │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ Text Formatting                     │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ summarizeStepDetail                 │ Format step details for console output                     │
// │ summarizeToolsList                  │ Truncate long tool lists for display                       │
// │ wrapText                            │ Wrap text to fit within specified width                    │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ File Output                         │                                                            │
// ├─────────────────────────────────────┼────────────────────────────────────────────────────────────┤
// │ writeOutputs                        │ Write scan results to configured output paths              │
// │ resolveOutputPath                   │ Resolve relative path against output directory             │
// │ writeBundle                         │ Create zip bundle with all outputs                         │
// │ writeZipFile                        │ Write single file entry to zip archive                     │
// │ buildTraceJSONL                     │ Convert trace entries to JSONL format                      │
// │ ensureParentDir                     │ Create parent directory if needed                          │
// └─────────────────────────────────────┴────────────────────────────────────────────────────────────┘

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// buildSummary constructs a scanSummary with stdout, markdown, and JSON representations.
func buildSummary(report scanReport) scanSummary {
	var out strings.Builder
	if report.Command != "" {
		fmt.Fprintf(&out, "%-10s %s\n", "Command:", report.Command)
	}
	fmt.Fprintf(&out, "%-10s %s\n", "Scanning:", report.Target)
	fmt.Fprintf(&out, "%-10s %s\n", "Scan time:", formatHumanTime(report.Timestamp))
	fmt.Fprintf(&out, "%-10s %s\n", "Github:", "https://github.com/authprobe/authprobe")
	fmt.Fprintln(&out, "\nFunnel")
	maxLabel := 0
	for _, step := range report.Steps {
		label := fmt.Sprintf("  [%d] %s", step.ID, step.Name)
		if len(label) > maxLabel {
			maxLabel = len(label)
		}
	}
	for i, step := range report.Steps {
		label := fmt.Sprintf("  [%d] %s", step.ID, step.Name)
		indicator := statusIndicator(step.Status)
		fmt.Fprintf(&out, "%-*s  %s %s\n", maxLabel, label, indicator, step.Status)
		if strings.TrimSpace(step.Detail) != "" {
			detailLines := summarizeStepDetail(step.Detail, 4, 72)
			for _, line := range detailLines {
				fmt.Fprintf(&out, "        %s\n", line)
			}
		}
		// Add blank line between steps for readability (except after last step)
		if i < len(report.Steps)-1 {
			fmt.Fprintln(&out)
		}
	}
	if report.PrimaryFinding.Code != "" {
		fmt.Fprintf(&out, "\nPrimary finding (%s): %s (confidence %.2f)\n", strings.ToUpper(report.PrimaryFinding.Severity), report.PrimaryFinding.Code, report.PrimaryFinding.Confidence)
		if len(report.PrimaryFinding.Evidence) > 0 {
			fmt.Fprintln(&out, "  Evidence:")
			for _, line := range report.PrimaryFinding.Evidence {
				for _, wrapped := range wrapText(line, 96-6) {
					fmt.Fprintf(&out, "      %s\n", wrapped)
				}
			}
		}
	}
	stdout := out.String()

	md := renderMarkdown(report)
	jsonBytes, _ := json.MarshalIndent(report, "", "  ")

	return scanSummary{Stdout: stdout, MD: md, JSON: jsonBytes}
}

// summarizeStepDetail formats step details for console output.
func summarizeStepDetail(detail string, maxTools int, maxWidth int) []string {
	lines := strings.Split(strings.TrimSpace(detail), "\n")
	var summarized []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = summarizeToolsList(line, maxTools)
		summarized = append(summarized, wrapText(line, maxWidth)...)
	}
	if len(summarized) == 0 {
		return []string{""}
	}
	return summarized
}

// summarizeToolsList truncates long tool lists for display.
func summarizeToolsList(detail string, maxTools int) string {
	const marker = "tools:"
	start := strings.Index(detail, marker)
	if start == -1 {
		return detail
	}
	start += len(marker)
	rest := detail[start:]
	end := strings.Index(rest, ")")
	if end == -1 {
		return detail
	}
	list := strings.TrimSpace(rest[:end])
	if list == "" {
		return detail
	}
	tools := strings.Split(list, ",")
	for i := range tools {
		tools[i] = strings.TrimSpace(tools[i])
	}
	if len(tools) <= maxTools {
		return detail
	}
	compact := strings.Join(tools[:maxTools], ", ")
	compact = fmt.Sprintf("%s, +%d more", compact, len(tools)-maxTools)
	prefix := strings.TrimRight(detail[:start], " ")
	suffix := rest[end:]
	return fmt.Sprintf("%s %s%s", prefix, compact, suffix)
}

// wrapText wraps text to fit within the specified width.
func wrapText(text string, width int) []string {
	if width <= 0 || len(text) <= width {
		return []string{text}
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}
	var lines []string
	var current strings.Builder
	for _, word := range words {
		if current.Len() == 0 {
			current.WriteString(word)
			continue
		}
		if current.Len()+1+len(word) > width {
			lines = append(lines, current.String())
			current.Reset()
			current.WriteString(word)
			continue
		}
		current.WriteByte(' ')
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

// formatHumanTime converts an RFC3339 timestamp to a human-readable format.
func formatHumanTime(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return timestamp
	}
	return t.Format("Jan 02, 2006 15:04:05 UTC")
}

// statusIndicator returns a visual indicator for the step status.
func statusIndicator(status string) string {
	switch status {
	case "PASS":
		return "[+]"
	case "FAIL":
		return "[X]"
	case "SKIP":
		return "[-]"
	default:
		return "[?]"
	}
}

// buildScanExplanation generates a human-readable explanation of the scan process.
func buildScanExplanation(config scanConfig, resourceMetadata string, prmResult prmResult, authRequired bool) string {
	var out strings.Builder
	fmt.Fprintln(&out, "Explain (RFC 9728 rationale)")
	if !authRequired {
		fmt.Fprintln(&out, "1) MCP probe")
		fmt.Fprintln(&out, "- AuthProbe did not receive a 401 response that indicates authentication is required, so RFC 9728 PRM discovery is skipped.")
		return out.String()
	}

	fmt.Fprintln(&out, "1) MCP probe")
	fmt.Fprintf(&out, "- AuthProbe sends an unauthenticated GET to %s.\n", config.Target)
	fmt.Fprintln(&out, "- RFC 9728 discovery hinges on a 401 with WWW-Authenticate that includes resource_metadata.")
	if resourceMetadata != "" {
		fmt.Fprintf(&out, "- resource_metadata hint: %s\n", resourceMetadata)
	} else {
		fmt.Fprintln(&out, "- resource_metadata hint: (none)")
	}

	fmt.Fprintln(&out, "\n2) MCP initialize + tools/list")
	fmt.Fprintln(&out, "- AuthProbe sends an MCP initialize request followed by tools/list to enumerate server tools.")

	fmt.Fprintln(&out, "\n3) Protected Resource Metadata (PRM) discovery")
	fmt.Fprintln(&out, "- RFC 9728 defines PRM URLs by inserting /.well-known/oauth-protected-resource between the host and path.")
	candidates, hasPathSuffix, err := buildPRMCandidates(config.Target, resourceMetadata)
	if err != nil {
		fmt.Fprintf(&out, "- Unable to build PRM candidates: %v\n", err)
	} else {
		for _, candidate := range candidates {
			fmt.Fprintf(&out, "- %s (%s)\n", candidate.URL, candidate.Source)
		}
		if hasPathSuffix {
			fmt.Fprintln(&out, "- Because the resource has a path, the path-suffix PRM endpoint is required by RFC 9728.")
		}
	}
	fmt.Fprintln(&out, "- PRM responses must be JSON objects with a resource that matches the target URL; trailing-slash mismatches are warned for compatibility.")
	fmt.Fprintln(&out, "- authorization_servers is required for OAuth discovery; it lists issuer URLs.")

	fmt.Fprintln(&out, "\n4) Authorization server metadata")
	if len(prmResult.AuthorizationServers) == 0 {
		fmt.Fprintln(&out, "- No authorization_servers found in PRM, so AuthProbe skips metadata fetches.")
	} else {
		for _, issuer := range prmResult.AuthorizationServers {
			fmt.Fprintf(&out, "- issuer: %s\n", issuer)
			candidates, err := buildIssuerDiscoveryCandidates(issuer)
			if err != nil {
				fmt.Fprintf(&out, "- metadata: error building discovery URLs (%v)\n", err)
				continue
			}
			fmt.Fprintln(&out, "- metadata candidates (RFC 8414 + OIDC):")
			fmt.Fprintf(&out, "  - %s\n", candidates[0])
			fmt.Fprintf(&out, "  - %s\n", candidates[1])
			fmt.Fprintf(&out, "  - %s\n", candidates[2])
		}
	}

	fmt.Fprintln(&out, "\n5) Token endpoint readiness (heuristics)")
	fmt.Fprintln(&out, "- AuthProbe sends a safe, invalid grant request to the token endpoint to observe error response behavior.")
	fmt.Fprintln(&out, "- It flags non-JSON responses or HTTP 200 responses that still contain error payloads.")

	return out.String()
}

// renderMarkdown generates a markdown representation of the scan report.
func renderMarkdown(report scanReport) string {
	var md strings.Builder
	fmt.Fprintf(&md, "# AuthProbe report\n\n")
	if report.Command != "" {
		fmt.Fprintf(&md, "```\n%s\n```\n\n", report.Command)
	}
	fmt.Fprintf(&md, "Scanning: %s\n\n", report.Target)
	fmt.Fprintf(&md, "- Target: %s\n", report.Target)
	fmt.Fprintf(&md, "- MCP: %s\n", report.MCPMode)
	fmt.Fprintf(&md, "- RFC: %s\n", report.RFCMode)
	fmt.Fprintf(&md, "- Timestamp: %s\n\n", report.Timestamp)
	fmt.Fprintf(&md, "## Funnel\n\n")
	for _, step := range report.Steps {
		fmt.Fprintf(&md, "- [%d] %s: **%s**", step.ID, step.Name, step.Status)
		if step.Detail != "" {
			fmt.Fprintf(&md, " (%s)", step.Detail)
		}
		fmt.Fprintln(&md)
	}
	if report.PrimaryFinding.Code != "" {
		fmt.Fprintf(&md, "\n## Primary finding\n\n")
		fmt.Fprintf(&md, "- Code: %s\n", report.PrimaryFinding.Code)
		fmt.Fprintf(&md, "- Severity: %s\n", report.PrimaryFinding.Severity)
		fmt.Fprintf(&md, "- Confidence: %.2f\n", report.PrimaryFinding.Confidence)
		if len(report.PrimaryFinding.Evidence) > 0 {
			fmt.Fprintf(&md, "- Evidence:\n")
			for _, line := range report.PrimaryFinding.Evidence {
				fmt.Fprintf(&md, "  - %s\n", line)
			}
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintf(&md, "\n## All findings\n\n")
		for _, item := range report.Findings {
			fmt.Fprintf(&md, "- %s (%s, %.2f)\n", item.Code, item.Severity, item.Confidence)
			for _, line := range item.Evidence {
				fmt.Fprintf(&md, "  - %s\n", line)
			}
		}
	}
	return md.String()
}

// appendVerboseMarkdown appends verbose output to the markdown report.
func appendVerboseMarkdown(md string, verbose string) string {
	trimmed := strings.TrimSpace(verbose)
	if trimmed == "" {
		return md
	}
	var out strings.Builder
	out.WriteString(strings.TrimRight(md, "\n"))
	out.WriteString("\n\n## Verbose output\n\n```\n")
	out.WriteString(trimmed)
	out.WriteString("\n```\n")
	return out.String()
}

// writeOutputs writes the scan results to configured output paths.
func writeOutputs(report scanReport, summary scanSummary, config scanConfig) error {
	outputDir := config.OutputDir
	jsonPath := resolveOutputPath(config.JSONPath, outputDir)
	mdPath := resolveOutputPath(config.MDPath, outputDir)
	traceASCIIPath := resolveOutputPath(config.TraceASCIIPath, outputDir)
	bundlePath := resolveOutputPath(config.BundlePath, outputDir)

	if config.JSONPath == "-" {
		if _, err := os.Stdout.Write(summary.JSON); err != nil {
			return err
		}
	} else if jsonPath != "" {
		if err := ensureParentDir(jsonPath); err != nil {
			return err
		}
		if err := os.WriteFile(jsonPath, summary.JSON, 0o644); err != nil {
			return err
		}
	}
	if config.MDPath == "-" {
		if _, err := os.Stdout.Write([]byte(summary.MD)); err != nil {
			return err
		}
	} else if mdPath != "" {
		if err := ensureParentDir(mdPath); err != nil {
			return err
		}
		if err := os.WriteFile(mdPath, []byte(summary.MD), 0o644); err != nil {
			return err
		}
	}
	if config.TraceASCIIPath == "-" {
		if _, err := os.Stdout.Write([]byte(buildTraceASCII(summary.Trace))); err != nil {
			return err
		}
	} else if traceASCIIPath != "" {
		if err := ensureParentDir(traceASCIIPath); err != nil {
			return err
		}
		if err := os.WriteFile(traceASCIIPath, []byte(buildTraceASCII(summary.Trace)), 0o644); err != nil {
			return err
		}
	}
	if bundlePath != "" {
		if err := writeBundle(bundlePath, summary); err != nil {
			return err
		}
	}
	return nil
}

// resolveOutputPath resolves a relative output path against the output directory.
func resolveOutputPath(path string, dir string) string {
	if path == "" {
		return ""
	}
	if dir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// writeBundle creates a zip bundle containing all scan outputs.
func writeBundle(path string, summary scanSummary) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	if err := writeZipFile(zipWriter, "report.json", summary.JSON); err != nil {
		return err
	}
	if err := writeZipFile(zipWriter, "report.md", []byte(summary.MD)); err != nil {
		return err
	}
	traceBytes := buildTraceJSONL(summary.Trace)
	if err := writeZipFile(zipWriter, "trace.jsonl", traceBytes); err != nil {
		return err
	}
	traceASCII := buildTraceASCII(summary.Trace)
	if err := writeZipFile(zipWriter, "trace.txt", []byte(traceASCII)); err != nil {
		return err
	}
	meta := map[string]string{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeZipFile(zipWriter, "meta.json", metaBytes); err != nil {
		return err
	}
	return nil
}

// writeZipFile writes a single file entry to a zip archive.
func writeZipFile(zipWriter *zip.Writer, name string, payload []byte) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(payload)
	return err
}

// buildTraceJSONL converts trace entries to JSONL format.
func buildTraceJSONL(entries []traceEntry) []byte {
	var buffer bytes.Buffer
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

// buildTraceASCII converts trace entries into an ASCII call trace.
func buildTraceASCII(entries []traceEntry) string {
	var out strings.Builder
	out.WriteString("Call Trace Using: https://github.com/authprobe/authprobe\n\n")
	if len(entries) == 0 {
		out.WriteString("(no trace entries)\n")
		return out.String()
	}
	out.WriteString("  ┌────────────┐                                                    ┌────────────┐    \n")
	out.WriteString("  │ authprobe  │                                                    │ MCP Server │    \n")
	out.WriteString("  └─────┬──────┘                                                    └─────┬──────┘    \n")
	out.WriteString("        │                                                                 │           \n")

	mcpHost, authHost := traceHosts(entries)
	currentStep := ""
	for i, entry := range entries {
		step := traceStep(entry, mcpHost, authHost)
		if step != currentStep {
			currentStep = step
			if currentStep != "" {
				writeTraceStepBanner(&out, currentStep)
			}
		}
		fullURL := entry.URL
		if parsed, err := url.Parse(entry.URL); err == nil {
			if parsed.String() != "" {
				fullURL = parsed.String()
			}
		}
		statusLine := entry.StatusLine
		if statusLine == "" && entry.Status != 0 {
			statusLine = fmt.Sprintf("%d", entry.Status)
		}
		targetColumn := "MCP"
		if authHost != "" && hostFromURL(entry.URL) == authHost {
			targetColumn = "AUTH"
		}
		requestLine := fmt.Sprintf("%s %s", entry.Method, fullURL)
		responseLine := fmt.Sprintf("%s", statusLine)
		if targetColumn == "AUTH" {
			writeTraceLine(&out, requestLine)
			writeTraceHeaderLines(&out, entry.RequestHeaders)
			fmt.Fprintf(&out, "        ├──────────────────────────────────────────────────────────────────┼─►│\n")
			writeTraceLine(&out, responseLine)
			writeTraceHeaderLines(&out, entry.ResponseHeaders)
			fmt.Fprintf(&out, "        │◄─────────────────────────────────────────────────────────────────┼  ┤\n")
		} else {
			writeTraceLine(&out, requestLine)
			writeTraceHeaderLines(&out, entry.RequestHeaders)
			fmt.Fprintf(&out, "        ├─────────────────────────────────────────────────────────────────►│\n")
			writeTraceLine(&out, responseLine)
			writeTraceHeaderLines(&out, entry.ResponseHeaders)
			fmt.Fprintf(&out, "        │◄─────────────────────────────────────────────────────────────────┤\n")
		}
		if i < len(entries)-1 {
			out.WriteString("        │                                                                  │\n")
		}
	}
	out.WriteString("        ▼                                                                  ▼\n")
	return out.String()
}

const traceLineWidth = 62
const traceStepWidth = 36

func writeTraceLine(out *strings.Builder, content string) {
	fmt.Fprintf(out, "        │  %-*s\n", traceLineWidth, content)
}

func writeTraceStepBanner(out *strings.Builder, step string) {
	fmt.Fprintf(out, "        │ ╔═══ %-*s ═══════╪══════════════════════════════════╗\n", traceStepWidth, step)
}

func writeTraceHeaderLines(out *strings.Builder, headers map[string]string) {
	if len(headers) == 0 {
		return
	}
	keys := make([]string, 0, len(headers))
	maxKeyLen := 0
	for key := range headers {
		keys = append(keys, key)
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(out, "        │    %-*s  %s\n", maxKeyLen+1, key+":", headers[key])
	}
}

func traceHosts(entries []traceEntry) (string, string) {
	if len(entries) == 0 {
		return "", ""
	}
	mcpHost := hostFromURL(entries[0].URL)
	authHost := ""
	for _, entry := range entries[1:] {
		host := hostFromURL(entry.URL)
		if host != "" && host != mcpHost {
			authHost = host
			break
		}
	}
	return mcpHost, authHost
}

func hostFromURL(raw string) string {
	if parsed, err := url.Parse(raw); err == nil {
		return parsed.Host
	}
	return ""
}

func traceStep(entry traceEntry, mcpHost string, authHost string) string {
	parsed, err := url.Parse(entry.URL)
	if err != nil {
		return ""
	}
	path := parsed.Path
	if strings.Contains(path, ".well-known/oauth-protected-resource") {
		return "Step 3: PRM Discovery"
	}
	if strings.Contains(path, ".well-known/oauth-authorization-server") || strings.Contains(path, ".well-known/openid-configuration") {
		return "Step 4: Auth Server Metadata"
	}
	if strings.Contains(path, "/token") && entry.Method == http.MethodPost {
		return "Step 5: Token Readiness"
	}
	if strings.Contains(path, "/register") && entry.Method == http.MethodPost {
		return "Step 6: DCR"
	}
	if parsed.Host == mcpHost {
		if entry.Method == http.MethodGet {
			return "Step 1: MCP probe"
		}
		if entry.Method == http.MethodPost {
			return "Step 2: MCP initialize"
		}
	}
	if authHost != "" && parsed.Host == authHost {
		return "Step 4: Auth Server Metadata"
	}
	return "Step 2: MCP initialize"
}

// ensureParentDir creates the parent directory for a file path if it doesn't exist.
func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
