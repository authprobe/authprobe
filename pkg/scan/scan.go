package scan

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	enginescan "authprobe/internal/scan"
)

const (
	// DefaultTimeout is the scan timeout used when Options.Timeout is omitted.
	DefaultTimeout = 8 * time.Second
	// DefaultMCPProbeTimeout bounds the initial GET/SSE discovery probe by default.
	DefaultMCPProbeTimeout = 2 * time.Second
)

// MCPMode controls how MCP protocol checks are evaluated during a scan.
type MCPMode string

const (
	// MCPModeOff disables MCP protocol checks while leaving OAuth/RFC checks available.
	MCPModeOff MCPMode = "off"
	// MCPModeBestEffort reports MCP interoperability findings without promoting all strict checks.
	MCPModeBestEffort MCPMode = "best-effort"
	// MCPModeStrict applies AuthProbe's strict MCP conformance severity rules.
	MCPModeStrict MCPMode = "strict"
)

// RFCMode controls how OAuth/RFC checks are evaluated during a scan.
type RFCMode string

const (
	// RFCModeOff disables RFC-driven OAuth and metadata checks where the engine supports it.
	RFCModeOff RFCMode = "off"
	// RFCModeBestEffort reports OAuth/RFC findings using AuthProbe's default compatibility posture.
	RFCModeBestEffort RFCMode = "best-effort"
	// RFCModeStrict applies AuthProbe's strict RFC severity rules.
	RFCModeStrict RFCMode = "strict"
)

// Report is AuthProbe's typed scan report, including steps, findings, and auth discovery details.
type Report = enginescan.ScanReport

// Summary contains rendered report artifacts and redacted request/response trace entries.
type Summary = enginescan.ScanSummary

// Step describes one stage of the AuthProbe scan funnel.
type Step = enginescan.ScanStep

// Finding is a stable diagnostic emitted by AuthProbe's scan engine.
type Finding = enginescan.Finding

// TraceEntry records one redacted HTTP request/response observation from a scan.
type TraceEntry = enginescan.TraceEntry

// AuthDiscoverySummary describes OAuth issuer and endpoint metadata discovered during a scan.
type AuthDiscoverySummary = enginescan.AuthDiscoverySummary

// Options captures the public scan settings needed by embedders such as mcpd.
type Options struct {
	TargetURL           string
	MCPMode             MCPMode
	RFCMode             RFCMode
	Timeout             time.Duration
	MCPProbeTimeout     time.Duration
	Headers             http.Header
	AllowPrivateIssuers bool
	InsecureSkipVerify  bool
	NoFollowRedirects   bool
	TraceFailure        bool
}

// Result contains the structured report and optional rendered artifacts from a scan.
type Result struct {
	Report  Report
	Summary Summary
}

// Run executes AuthProbe's scan funnel for one MCP endpoint without invoking the CLI.
//
// Args:
//   - options Options: Public scan settings; omitted modes and timeouts use defaults.
//
// Returns:
//
//	Result containing the typed ScanReport and in-memory rendered summary artifacts.
//
// Errors:
//
//	Option validation errors before I/O or scanner errors from the probe engine.
func Run(options Options) (Result, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return Result{}, err
	}

	report, summary, err := enginescan.RunScanFunnel(scanConfig(normalized), io.Discard, io.Discard)
	if err != nil {
		return Result{}, err
	}
	return Result{Report: report, Summary: summary}, nil
}

// ValidateOptions checks whether scan settings are safe to pass to the engine.
//
// Args:
//   - options Options: Public scan settings to validate and default.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Missing targets, invalid URLs, invalid modes, or malformed headers.
func ValidateOptions(options Options) error {
	_, err := normalizeOptions(options)
	return err
}

// normalizeOptions validates public input and fills defaults expected by callers.
//
// Args:
//   - options Options: Raw public scan settings supplied by a library caller.
//
// Returns:
//
//	Options with default modes and timeouts applied.
//
// Errors:
//
//	Invalid target URL, modes, timeouts, or headers.
func normalizeOptions(options Options) (Options, error) {
	options.TargetURL = strings.TrimSpace(options.TargetURL)
	if err := validateTargetURL(options.TargetURL); err != nil {
		return Options{}, err
	}

	if options.MCPMode == "" {
		options.MCPMode = MCPModeBestEffort
	}
	if !validMCPMode(options.MCPMode) {
		return Options{}, fmt.Errorf("mcp mode must be one of %q, %q, or %q", MCPModeOff, MCPModeBestEffort, MCPModeStrict)
	}

	if options.RFCMode == "" {
		options.RFCMode = RFCModeBestEffort
	}
	if !validRFCMode(options.RFCMode) {
		return Options{}, fmt.Errorf("rfc mode must be one of %q, %q, or %q", RFCModeOff, RFCModeBestEffort, RFCModeStrict)
	}

	if options.Timeout < 0 {
		return Options{}, errors.New("timeout must be zero or positive")
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.MCPProbeTimeout < 0 {
		return Options{}, errors.New("mcp probe timeout must be zero or positive")
	}
	if options.MCPProbeTimeout == 0 {
		options.MCPProbeTimeout = DefaultMCPProbeTimeout
	}
	if err := validateHeaders(options.Headers); err != nil {
		return Options{}, err
	}
	return options, nil
}

// scanConfig converts public options into the internal scan engine contract.
//
// Args:
//   - options Options: Validated public scan settings with defaults already applied.
//
// Returns:
//
//	Internal ScanConfig that preserves redaction and avoids CLI output paths.
func scanConfig(options Options) enginescan.ScanConfig {
	return enginescan.NewBaseConfig(enginescan.BaseConfigInput{
		Target:              options.TargetURL,
		Command:             "authprobe pkg/scan",
		Headers:             headerStrings(options.Headers),
		Timeout:             options.Timeout,
		MCPProbeTimeout:     options.MCPProbeTimeout,
		MCPMode:             string(options.MCPMode),
		MCPProtocolVersion:  enginescan.SupportedMCPProtocolVersion,
		RFCMode:             string(options.RFCMode),
		AllowPrivateIssuers: options.AllowPrivateIssuers,
		Insecure:            options.InsecureSkipVerify,
		NoFollowRedirects:   options.NoFollowRedirects,
		TraceFailure:        options.TraceFailure,
		Redact:              true,
	})
}

// validateTargetURL rejects missing or unsupported endpoint URLs at the package boundary.
//
// Args:
//   - raw string: Target endpoint URL supplied by the caller.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Empty, unparsable, hostless, or non-HTTP URLs.
func validateTargetURL(raw string) error {
	if raw == "" {
		return errors.New("target URL is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("target URL is invalid: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("target URL scheme must be http or https")
	}
	if parsed.Host == "" {
		return errors.New("target URL must include a host")
	}
	return nil
}

// validateHeaders rejects header names or values that cannot be safely attached to HTTP probes.
//
// Args:
//   - headers http.Header: Optional HTTP headers to include on every scan request.
//
// Returns:
//
//	None.
//
// Errors:
//
//	Empty names, invalid token characters, or newline-bearing values.
func validateHeaders(headers http.Header) error {
	for name, values := range headers {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			return errors.New("header name must not be empty")
		}
		if !validHeaderName(trimmedName) {
			return fmt.Errorf("header %q has an invalid name", name)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("header %q contains a newline", trimmedName)
			}
		}
	}
	return nil
}

// validMCPMode reports whether a public MCP mode maps to an engine-supported value.
//
// Args:
//   - mode MCPMode: Candidate MCP mode from Options.
//
// Returns:
//
//	True when mode is off, best-effort, or strict.
func validMCPMode(mode MCPMode) bool {
	switch mode {
	case MCPModeOff, MCPModeBestEffort, MCPModeStrict:
		return true
	default:
		return false
	}
}

// validRFCMode reports whether a public RFC mode maps to an engine-supported value.
//
// Args:
//   - mode RFCMode: Candidate RFC mode from Options.
//
// Returns:
//
//	True when mode is off, best-effort, or strict.
func validRFCMode(mode RFCMode) bool {
	switch mode {
	case RFCModeOff, RFCModeBestEffort, RFCModeStrict:
		return true
	default:
		return false
	}
}

// validHeaderName checks the HTTP token grammar needed for header field names.
//
// Args:
//   - name string: Candidate HTTP header field name.
//
// Returns:
//
//	True when every byte is permitted by RFC 9110 token syntax.
func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

// headerStrings converts typed HTTP headers into the internal CLI-style header representation.
//
// Args:
//   - headers http.Header: Optional HTTP headers supplied by the caller.
//
// Returns:
//
//	A stable, sorted slice of "Name: value" header strings for ScanConfig.
func headerStrings(headers http.Header) []string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]string, 0, len(headers))
	for _, name := range names {
		for _, value := range headers[name] {
			out = append(out, http.CanonicalHeaderKey(strings.TrimSpace(name))+": "+value)
		}
	}
	return out
}
