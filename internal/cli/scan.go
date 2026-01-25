package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type scanConfig struct {
	Target              string
	Profile             string
	Headers             []string
	Timeout             time.Duration
	Verbose             bool
	FailOn              string
	RFC9728Mode         string
	AllowPrivateIssuers bool
	NoFollowRedirects   bool
	JSONPath            string
	MDPath              string
	BundlePath          string
	OutputDir           string
}

type scanReport struct {
	Target         string     `json:"target"`
	Profile        string     `json:"profile"`
	RFC9728Mode    string     `json:"rfc9728_mode"`
	Timestamp      string     `json:"timestamp"`
	Steps          []scanStep `json:"steps"`
	Findings       []finding  `json:"findings"`
	PrimaryFinding finding    `json:"primary_finding"`
}

type scanStep struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type finding struct {
	Code       string   `json:"code"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type scanSummary struct {
	Stdout string
	MD     string
	JSON   []byte
	Trace  []traceEntry
}

type traceEntry struct {
	Timestamp string            `json:"ts"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers,omitempty"`
}

func runScanFunnel(config scanConfig, stdout io.Writer) (scanReport, scanSummary, error) {
	report := scanReport{
		Target:      config.Target,
		Profile:     config.Profile,
		RFC9728Mode: config.RFC9728Mode,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	client := &http.Client{Timeout: config.Timeout}
	if config.NoFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	trace := []traceEntry{}
	findings := []finding{}
	steps := []scanStep{}

	step1 := scanStep{ID: 1, Name: "MCP probe (401 + WWW-Authenticate)"}
	resourceMetadata, step1Findings, step1Evidence, authRequired, err := probeMCP(client, config, &trace, stdout)
	if err != nil {
		return report, scanSummary{}, err
	}
	findings = append(findings, step1Findings...)
	step1.Status = statusFromFindings(step1Findings, authRequired)
	step1.Detail = step1Evidence
	steps = append(steps, step1)

	if !authRequired {
		steps = append(steps, scanStep{ID: 2, Name: "PRM fetch matrix", Status: "SKIP", Detail: "auth not required"})
		steps = append(steps, scanStep{ID: 3, Name: "Auth server metadata", Status: "SKIP", Detail: "auth not required"})
		report.Steps = steps
		report.Findings = findings
		report.PrimaryFinding = choosePrimaryFinding(findings)
		summary := buildSummary(report)
		summary.Trace = trace
		if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
			return report, scanSummary{}, err
		}
		return report, summary, nil
	}

	step2 := scanStep{ID: 2, Name: "PRM fetch matrix"}
	prmResult, step2Findings, step2Evidence, err := fetchPRMMatrix(client, config, resourceMetadata, &trace, stdout)
	if err != nil {
		return report, scanSummary{}, err
	}
	findings = append(findings, step2Findings...)
	step2.Status = statusFromFindings(step2Findings, true)
	step2.Detail = step2Evidence
	steps = append(steps, step2)

	step3 := scanStep{ID: 3, Name: "Auth server metadata"}
	if len(prmResult.AuthorizationServers) == 0 {
		step3.Status = "SKIP"
		step3.Detail = "no authorization_servers in PRM"
	} else {
		step3Findings, step3Evidence := fetchAuthServerMetadata(client, config, prmResult.AuthorizationServers, &trace, stdout)
		findings = append(findings, step3Findings...)
		step3.Status = statusFromFindings(step3Findings, true)
		step3.Detail = step3Evidence
	}
	steps = append(steps, step3)

	report.Steps = steps
	report.Findings = findings
	report.PrimaryFinding = choosePrimaryFinding(findings)
	summary := buildSummary(report)
	summary.Trace = trace
	if _, err := stdout.Write([]byte(summary.Stdout)); err != nil {
		return report, scanSummary{}, err
	}
	return report, summary, nil
}

type prmResult struct {
	AuthorizationServers []string
	Resource             string
}

func probeMCP(client *http.Client, config scanConfig, trace *[]traceEntry, stdout io.Writer) (string, []finding, string, bool, error) {
	req, err := http.NewRequest(http.MethodGet, config.Target, nil)
	if err != nil {
		return "", nil, "", false, err
	}
	if err := applyHeaders(req, config.Headers); err != nil {
		return "", nil, "", false, err
	}
	if config.Verbose {
		if err := writeVerboseRequest(stdout, req); err != nil {
			return "", nil, "", false, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, "", false, err
	}
	defer resp.Body.Close()
	_, _ = drainBody(&resp.Body)

	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return "", nil, "", false, err
		}
	}

	addTrace(trace, req, resp)

	if resp.StatusCode != http.StatusUnauthorized {
		return "", nil, "auth not required", false, nil
	}

	resourceMetadata, ok := extractResourceMetadata(resp.Header.Values("WWW-Authenticate"))
	if !ok {
		return "", []finding{newFinding("DISCOVERY_NO_WWW_AUTHENTICATE", "missing resource_metadata in WWW-Authenticate")}, "missing WWW-Authenticate/resource_metadata", true, nil
	}
	return resourceMetadata, nil, "401 with resource_metadata", true, nil
}

func fetchPRMMatrix(client *http.Client, config scanConfig, resourceMetadata string, trace *[]traceEntry, stdout io.Writer) (prmResult, []finding, string, error) {
	parsedTarget, err := url.Parse(config.Target)
	if err != nil {
		return prmResult{}, nil, "", fmt.Errorf("invalid mcp url: %w", err)
	}

	candidates := []prmCandidate{}
	if resourceMetadata != "" {
		rmURL, err := resolveURL(parsedTarget, resourceMetadata)
		if err == nil {
			candidates = append(candidates, prmCandidate{URL: rmURL.String(), Source: "resource_metadata"})
		}
	}

	rootURL := parsedTarget.ResolveReference(&url.URL{Path: "/.well-known/oauth-protected-resource"})
	candidates = append(candidates, prmCandidate{URL: rootURL.String(), Source: "root"})

	pathSuffix := buildPathSuffixCandidate(parsedTarget)
	if pathSuffix != "" {
		candidates = append(candidates, prmCandidate{URL: pathSuffix, Source: "path-suffix"})
	}

	findings := []finding{}
	var evidence strings.Builder
	var bestPRM prmResult
	pathSuffixMissing := false
	for _, candidate := range candidates {
		resp, payload, err := fetchJSON(client, config, candidate.URL, trace, stdout)
		if err != nil {
			if candidate.Source == "path-suffix" {
				pathSuffixMissing = true
			}
			if config.RFC9728Mode != "off" {
				findings = append(findings, newFinding("PRM_HTTP_STATUS_NOT_200", fmt.Sprintf("%s fetch error: %v", candidate.Source, err)))
			}
			continue
		}
		status := resp.StatusCode
		fmt.Fprintf(&evidence, "%s -> %d\n", candidate.URL, status)
		if status == http.StatusNotFound && candidate.Source == "root" {
			findings = append(findings, newFinding("DISCOVERY_ROOT_WELLKNOWN_404", "root PRM endpoint returned 404"))
		}
		if candidate.Source == "path-suffix" && status == http.StatusNotFound {
			pathSuffixMissing = true
		}
		if status != http.StatusOK && config.RFC9728Mode != "off" {
			findings = append(findings, newFinding("PRM_HTTP_STATUS_NOT_200", fmt.Sprintf("%s status %d", candidate.Source, status)))
			continue
		}
		if status != http.StatusOK {
			continue
		}
		contentType := resp.Header.Get("Content-Type")
		if config.RFC9728Mode != "off" && !strings.HasPrefix(contentType, "application/json") {
			findings = append(findings, newFinding("PRM_CONTENT_TYPE_NOT_JSON", fmt.Sprintf("%s content-type %q", candidate.Source, contentType)))
			continue
		}
		obj, ok := payload.(map[string]any)
		if !ok {
			if config.RFC9728Mode != "off" {
				findings = append(findings, newFinding("PRM_NOT_JSON_OBJECT", fmt.Sprintf("%s response not JSON object", candidate.Source)))
			}
			continue
		}
		prm := prmResult{}
		if resourceValue, ok := obj["resource"].(string); ok {
			prm.Resource = resourceValue
			if config.RFC9728Mode != "off" && resourceValue == "" {
				findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource empty", candidate.Source)))
			}
		} else if config.RFC9728Mode != "off" {
			findings = append(findings, newFinding("PRM_RESOURCE_MISSING", fmt.Sprintf("%s resource missing", candidate.Source)))
		}
		if prm.Resource != "" && prm.Resource != config.Target {
			findings = append(findings, newFinding("PRM_RESOURCE_MISMATCH", fmt.Sprintf("%s resource %q != %q", candidate.Source, prm.Resource, config.Target)))
		}
		if servers, ok := obj["authorization_servers"].([]any); ok {
			for _, entry := range servers {
				if value, ok := entry.(string); ok && value != "" {
					prm.AuthorizationServers = append(prm.AuthorizationServers, value)
				}
			}
		}
		if len(prm.AuthorizationServers) == 0 {
			findings = append(findings, newFinding("PRM_MISSING_AUTHORIZATION_SERVERS", fmt.Sprintf("%s authorization_servers missing", candidate.Source)))
		}

		if bestPRM.AuthorizationServers == nil && (prm.Resource != "" || len(prm.AuthorizationServers) > 0) {
			bestPRM = prm
		}
	}

	if pathSuffix != "" && pathSuffixMissing && config.RFC9728Mode != "off" {
		findings = append(findings, newFinding("PRM_WELLKNOWN_PATH_SUFFIX_MISSING", "path-suffix PRM endpoint missing"))
	}

	return bestPRM, findings, strings.TrimSpace(evidence.String()), nil
}

type prmCandidate struct {
	URL    string
	Source string
}

func fetchAuthServerMetadata(client *http.Client, config scanConfig, issuers []string, trace *[]traceEntry, stdout io.Writer) ([]finding, string) {
	findings := []finding{}
	var evidence strings.Builder
	for _, issuer := range issuers {
		if issuer == "" {
			continue
		}
		if !config.AllowPrivateIssuers {
			if blocked := issuerPrivate(issuer); blocked {
				findings = append(findings, newFinding("AUTH_SERVER_ISSUER_PRIVATE_BLOCKED", fmt.Sprintf("blocked issuer %s", issuer)))
				continue
			}
		}
		metadataURL := buildMetadataURL(issuer)
		resp, payload, err := fetchJSON(client, config, metadataURL, trace, stdout)
		if err != nil {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_UNREACHABLE", fmt.Sprintf("%s fetch error: %v", issuer, err)))
			continue
		}
		fmt.Fprintf(&evidence, "%s -> %d\n", metadataURL, resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s status %d", issuer, resp.StatusCode)))
			continue
		}
		obj, ok := payload.(map[string]any)
		if !ok {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s response not JSON object", issuer)))
			continue
		}
		if _, ok := obj["authorization_endpoint"].(string); !ok {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing authorization_endpoint", issuer)))
			continue
		}
		if _, ok := obj["token_endpoint"].(string); !ok {
			findings = append(findings, newFinding("AUTH_SERVER_METADATA_INVALID", fmt.Sprintf("%s missing token_endpoint", issuer)))
			continue
		}
	}
	return findings, strings.TrimSpace(evidence.String())
}

func fetchJSON(client *http.Client, config scanConfig, target string, trace *[]traceEntry, stdout io.Writer) (*http.Response, any, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := applyHeaders(req, config.Headers); err != nil {
		return nil, nil, err
	}
	if config.Verbose {
		if err := writeVerboseRequest(stdout, req); err != nil {
			return nil, nil, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if config.Verbose {
		if err := writeVerboseResponse(stdout, resp); err != nil {
			return resp, nil, err
		}
	}
	addTrace(trace, req, resp)

	var payload any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			payload = nil
		}
	}
	return resp, payload, nil
}

func applyHeaders(req *http.Request, headers []string) error {
	for _, header := range headers {
		key, value, err := parseHeader(header)
		if err != nil {
			return err
		}
		req.Header.Add(key, value)
	}
	return nil
}

func resolveURL(base *url.URL, ref string) (*url.URL, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, err
	}
	if parsed.IsAbs() {
		return parsed, nil
	}
	return base.ResolveReference(parsed), nil
}

func buildPathSuffixCandidate(target *url.URL) string {
	path := target.EscapedPath()
	if path == "" || path == "/" {
		return ""
	}
	trimmed := strings.TrimSuffix(path, "/")
	if trimmed == "" {
		return ""
	}
	targetCopy := *target
	targetCopy.Path = "/.well-known/oauth-protected-resource" + trimmed
	targetCopy.RawQuery = ""
	targetCopy.Fragment = ""
	return targetCopy.String()
}

func extractResourceMetadata(headers []string) (string, bool) {
	re := regexp.MustCompile(`resource_metadata\\s*=\\s*\"([^\"]+)\"|resource_metadata\\s*=\\s*([^,\\s]+)`)
	for _, header := range headers {
		matches := re.FindStringSubmatch(header)
		if len(matches) > 1 && matches[1] != "" {
			return matches[1], true
		}
		if len(matches) > 2 && matches[2] != "" {
			return matches[2], true
		}
	}
	return "", false
}

func buildMetadataURL(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return issuer
	}
	if strings.Contains(parsed.Path, "/.well-known/") {
		return parsed.String()
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/.well-known/oauth-authorization-server"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func issuerPrivate(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func statusFromFindings(findings []finding, authRequired bool) string {
	if !authRequired {
		return "SKIP"
	}
	if len(findings) == 0 {
		return "PASS"
	}
	return "FAIL"
}

func newFinding(code string, evidence string) finding {
	severity := findingSeverity(code)
	confidence := findingConfidence(code)
	f := finding{Code: code, Severity: severity, Confidence: confidence}
	if evidence != "" {
		f.Evidence = []string{evidence}
	}
	return f
}

func findingSeverity(code string) string {
	switch code {
	case "DISCOVERY_NO_WWW_AUTHENTICATE",
		"DISCOVERY_ROOT_WELLKNOWN_404",
		"PRM_MISSING_AUTHORIZATION_SERVERS",
		"PRM_RESOURCE_MISMATCH",
		"PRM_RESOURCE_MISSING",
		"PRM_HTTP_STATUS_NOT_200",
		"PRM_CONTENT_TYPE_NOT_JSON",
		"PRM_NOT_JSON_OBJECT",
		"AUTH_SERVER_METADATA_UNREACHABLE",
		"AUTH_SERVER_METADATA_INVALID":
		return "high"
	case "PRM_WELLKNOWN_PATH_SUFFIX_MISSING",
		"AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		return "medium"
	default:
		return "low"
	}
}

func findingConfidence(code string) float64 {
	switch code {
	case "DISCOVERY_ROOT_WELLKNOWN_404":
		return 0.92
	case "AUTH_SERVER_ISSUER_PRIVATE_BLOCKED":
		return 0.85
	default:
		return 1.00
	}
}

func choosePrimaryFinding(findings []finding) finding {
	if len(findings) == 0 {
		return finding{}
	}
	sorted := make([]finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		si := severityRank(sorted[i].Severity)
		sj := severityRank(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		if sorted[i].Confidence != sorted[j].Confidence {
			return sorted[i].Confidence > sorted[j].Confidence
		}
		return sorted[i].Code < sorted[j].Code
	})
	return sorted[0]
}

func severityRank(severity string) int {
	switch severity {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func buildSummary(report scanReport) scanSummary {
	var out strings.Builder
	fmt.Fprintln(&out, "Funnel")
	for _, step := range report.Steps {
		label := fmt.Sprintf("  [%d] %s", step.ID, step.Name)
		dots := strings.Repeat(".", max(1, 60-len(label)))
		status := step.Status
		if step.Detail != "" {
			fmt.Fprintf(&out, "%s %s %s (%s)\n", label, dots, status, step.Detail)
		} else {
			fmt.Fprintf(&out, "%s %s %s\n", label, dots, status)
		}
	}
	if report.PrimaryFinding.Code == "" {
		fmt.Fprintln(&out, "\nPrimary finding: -")
	} else {
		fmt.Fprintf(&out, "\nPrimary finding (%s): %s (confidence %.2f)\n", strings.ToUpper(report.PrimaryFinding.Severity), report.PrimaryFinding.Code, report.PrimaryFinding.Confidence)
	}
	stdout := out.String()

	md := renderMarkdown(report)
	jsonBytes, _ := json.MarshalIndent(report, "", "  ")

	return scanSummary{Stdout: stdout, MD: md, JSON: jsonBytes}
}

func renderMarkdown(report scanReport) string {
	var md strings.Builder
	fmt.Fprintf(&md, "# AuthProbe report\n\n")
	fmt.Fprintf(&md, "- Target: %s\n", report.Target)
	fmt.Fprintf(&md, "- Profile: %s\n", report.Profile)
	fmt.Fprintf(&md, "- RFC9728: %s\n", report.RFC9728Mode)
	fmt.Fprintf(&md, "- Timestamp: %s\n\n", report.Timestamp)
	fmt.Fprintf(&md, "## Funnel\n\n")
	for _, step := range report.Steps {
		fmt.Fprintf(&md, "- [%d] %s: **%s**", step.ID, step.Name, step.Status)
		if step.Detail != "" {
			fmt.Fprintf(&md, " (%s)", step.Detail)
		}
		fmt.Fprintln(&md)
	}
	fmt.Fprintf(&md, "\n## Primary finding\n\n")
	if report.PrimaryFinding.Code == "" {
		fmt.Fprintln(&md, "None.")
	} else {
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

func writeOutputs(report scanReport, summary scanSummary, config scanConfig) error {
	outputDir := config.OutputDir
	jsonPath := resolveOutputPath(config.JSONPath, outputDir)
	mdPath := resolveOutputPath(config.MDPath, outputDir)
	bundlePath := resolveOutputPath(config.BundlePath, outputDir)

	if jsonPath != "" {
		if err := ensureParentDir(jsonPath); err != nil {
			return err
		}
		if err := os.WriteFile(jsonPath, summary.JSON, 0o644); err != nil {
			return err
		}
	}
	if mdPath != "" {
		if err := ensureParentDir(mdPath); err != nil {
			return err
		}
		if err := os.WriteFile(mdPath, []byte(summary.MD), 0o644); err != nil {
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

func resolveOutputPath(path string, dir string) string {
	if path == "" {
		return ""
	}
	if dir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

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
	meta := map[string]string{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeZipFile(zipWriter, "meta.json", metaBytes); err != nil {
		return err
	}
	return nil
}

func writeZipFile(zipWriter *zip.Writer, name string, payload []byte) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(payload)
	return err
}

func addTrace(trace *[]traceEntry, req *http.Request, resp *http.Response) {
	headers := map[string]string{}
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	*trace = append(*trace, traceEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Method:    req.Method,
		URL:       req.URL.String(),
		Status:    resp.StatusCode,
		Headers:   headers,
	})
}

func shouldFail(primary finding, failOn string) bool {
	if primary.Code == "" {
		return false
	}
	threshold := severityRank(strings.ToLower(failOn))
	if threshold == 0 {
		return false
	}
	return severityRank(primary.Severity) >= threshold
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
