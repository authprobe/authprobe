package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxMetadataRedirects = 5

func addTrace(trace *[]TraceEntry, req *http.Request, resp *http.Response, redact bool, reason string) {
	entry := TraceEntry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		Method:          req.Method,
		URL:             req.URL.String(),
		Status:          resp.StatusCode,
		StatusLine:      resp.Status,
		Reason:          reason,
		Headers:         sanitizeHeadersForTrace(resp.Header, redact),
		RequestHeaders:  sanitizeRequestHeadersForTrace(req, redact),
		ResponseHeaders: sanitizeHeadersForTrace(resp.Header, redact),
	}
	*trace = append(*trace, entry)
}

func sanitizeRequestHeadersForTrace(req *http.Request, redact bool) map[string]string {
	if req == nil {
		return nil
	}
	headers := req.Header.Clone()
	if req.Host != "" && headers.Get("Host") == "" {
		headers.Set("Host", req.Host)
	}
	return sanitizeHeadersForTrace(headers, redact)
}

func fetchJSON(client *http.Client, config ScanConfig, target string, trace *[]TraceEntry, stdout io.Writer, verboseLabel string) (*http.Response, any, error) {
	resp, body, err := fetchWithRedirects(client, config, target, trace, stdout, verboseLabel)
	if err != nil {
		return resp, nil, err
	}
	var payload any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			payload = nil
		}
	}
	return resp, payload, nil
}

func fetchWithRedirects(client *http.Client, config ScanConfig, target string, trace *[]TraceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
	current := target
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
	}
	for redirects := 0; ; redirects++ {
		if err := validateFetchTarget(config, current); err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequest(http.MethodGet, current, nil)
		if err != nil {
			return nil, nil, err
		}
		if err := applyHeaders(req, config.Headers); err != nil {
			return nil, nil, err
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}
		if config.Verbose {
			if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
				return nil, nil, err
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			return resp, nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if config.Verbose {
			if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
				return resp, body, err
			}
		}
		addTrace(trace, req, resp, config.Redact, verboseLabel)
		if !isRedirectStatus(resp.StatusCode) || config.NoFollowRedirects {
			return resp, body, nil
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("missing Location for redirect from %s", current)}
		}
		next, err := resolveURL(req.URL, location)
		if err != nil {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("invalid redirect Location %q", location)}
		}
		if rfcModeEnabled(config.RFCMode) {
			if !next.IsAbs() {
				return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("redirect Location not absolute: %q", location)}
			}
			if rfcModeEnabled(config.RFCMode) && !isHTTPSURL(next) {
				if rfcModeStrict(config.RFCMode) {
					return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_BLOCKED", Detail: fmt.Sprintf("redirect Location not https: %q", location)}
				}
			}
		}
		if redirects >= maxMetadataRedirects {
			return resp, body, fetchPolicyError{Code: "METADATA_REDIRECT_LIMIT", Detail: fmt.Sprintf("redirect limit exceeded for %s", target)}
		}
		current = next.String()
	}
}

func postTokenProbe(client *http.Client, config ScanConfig, target string, trace *[]TraceEntry, stdout io.Writer, verboseLabel string) (*http.Response, []byte, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid")
	form.Set("redirect_uri", "https://invalid.example/callback")
	form.Set("client_id", "authprobe")

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if err := applySafeHeaders(req, config.Headers); err != nil {
		return nil, nil, err
	}
	if config.Verbose {
		writeVerboseHeading(stdout, verboseLabel)
		if err := writeVerboseRequest(stdout, req, config.Redact); err != nil {
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
		if err := writeVerboseResponse(stdout, resp, config.Redact); err != nil {
			return resp, body, err
		}
	}
	addTrace(trace, req, resp, config.Redact, verboseLabel)
	return resp, body, nil
}
