package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// StartStdioGateway starts a local HTTP bridge for an MCP stdio command.
// It returns a localhost URL compatible with existing HTTP scan flow.
func StartStdioGateway(command, endpointPath string, timeout time.Duration) (string, func() error, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return "", nil, fmt.Errorf("stdio command is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sh", "-c", trimmed)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("open stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("open stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("open stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return "", nil, fmt.Errorf("start stdio command: %w", err)
	}

	gateway := &stdioGateway{
		command: trimmed,
		stdin:   stdin,
		stdout:  bufio.NewReader(stdout),
		timeout: timeout,
		cmd:     cmd,
		cancel:  cancel,
	}
	go gateway.captureStderr(stderr)

	path := normalizeGatewayPath(endpointPath)
	mux := http.NewServeMux()
	mux.HandleFunc(path, gateway.handle)
	mux.HandleFunc("/debug", gateway.handleDebug)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = gateway.close()
		return "", nil, fmt.Errorf("listen gateway: %w", err)
	}
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(ln)
	}()

	cleanup := func() error {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		_ = ln.Close()
		return gateway.close()
	}

	return "http://" + ln.Addr().String() + path, cleanup, nil
}

type stdioGateway struct {
	command string
	stdin   io.WriteCloser
	stdout  *bufio.Reader
	timeout time.Duration
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	mu      sync.Mutex
	debug   gatewayDebug
}

type gatewayDebug struct {
	RequestCount int      `json:"request_count"`
	LastRequest  string   `json:"last_request,omitempty"`
	LastResponse string   `json:"last_response,omitempty"`
	LastError    string   `json:"last_error,omitempty"`
	RecentStderr []string `json:"recent_stderr,omitempty"`
}

type gatewayDebugSnapshot struct {
	Command      string   `json:"command"`
	ProcessPID   int      `json:"process_pid"`
	Timeout      string   `json:"timeout"`
	RequestCount int      `json:"request_count"`
	LastRequest  string   `json:"last_request,omitempty"`
	LastResponse string   `json:"last_response,omitempty"`
	LastError    string   `json:"last_error,omitempty"`
	RecentStderr []string `json:"recent_stderr,omitempty"`
}

func (g *stdioGateway) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Streamable HTTP expects MCP endpoints to accept GET (SSE) as well as
		// POST. In stdio mode we only bridge request/response JSON-RPC over POST,
		// but responding to GET keeps probe behavior compatible.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ": ok\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	case http.MethodOptions:
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var envelope struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(body, &envelope)

	if strings.TrimSpace(envelope.Method) == "notifications/initialized" && len(bytes.TrimSpace(envelope.ID)) == 0 {
		g.recordRequest(body)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp, err := g.roundTrip(body)
	if err != nil {
		g.recordError(err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	g.recordResponse(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (g *stdioGateway) handleDebug(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g.snapshot())
}

func (g *stdioGateway) roundTrip(payload []byte) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recordRequest(payload)

	if _, err := g.stdin.Write(append(payload, '\n')); err != nil {
		return nil, fmt.Errorf("write stdio request: %w", err)
	}

	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := g.stdout.ReadBytes('\n')
		ch <- result{line: bytes.TrimSpace(line), err: err}
	}()

	wait := g.timeout
	if wait <= 0 {
		wait = 8 * time.Second
	}
	select {
	case out := <-ch:
		if out.err != nil {
			return nil, fmt.Errorf("read stdio response: %w", out.err)
		}
		if len(out.line) == 0 {
			return nil, fmt.Errorf("empty stdio response")
		}
		return out.line, nil
	case <-time.After(wait):
		return nil, fmt.Errorf("stdio response timeout after %s", wait)
	}
}

func (g *stdioGateway) close() error {
	g.cancel()
	_ = g.stdin.Close()
	if g.cmd.Process != nil {
		_ = g.cmd.Process.Kill()
	}
	if g.cmd.Process != nil {
		_, _ = g.cmd.Process.Wait()
	}
	return nil
}

func (g *stdioGateway) captureStderr(r io.Reader) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			g.addStderrLine(line)
		}
	}
}

func (g *stdioGateway) addStderrLine(line string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.debug.RecentStderr = append(g.debug.RecentStderr, line)
	if len(g.debug.RecentStderr) > 25 {
		g.debug.RecentStderr = g.debug.RecentStderr[len(g.debug.RecentStderr)-25:]
	}
}

func (g *stdioGateway) recordRequest(payload []byte) {
	g.debug.RequestCount++
	g.debug.LastRequest = trimPayload(payload)
}

func (g *stdioGateway) recordResponse(payload []byte) {
	g.debug.LastResponse = trimPayload(payload)
	g.debug.LastError = ""
}

func (g *stdioGateway) recordError(err error) {
	g.debug.LastError = err.Error()
}

func (g *stdioGateway) snapshot() gatewayDebugSnapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	pid := 0
	if g.cmd != nil && g.cmd.Process != nil {
		pid = g.cmd.Process.Pid
	}
	stderr := make([]string, len(g.debug.RecentStderr))
	copy(stderr, g.debug.RecentStderr)
	return gatewayDebugSnapshot{
		Command:      g.command,
		ProcessPID:   pid,
		Timeout:      g.timeout.String(),
		RequestCount: g.debug.RequestCount,
		LastRequest:  g.debug.LastRequest,
		LastResponse: g.debug.LastResponse,
		LastError:    g.debug.LastError,
		RecentStderr: stderr,
	}
}

func trimPayload(payload []byte) string {
	const max = 1200
	trimmed := strings.TrimSpace(string(payload))
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "...<truncated>"
}

func normalizeGatewayPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if trimmed == "/debug" {
		return "/"
	}
	return trimmed
}
