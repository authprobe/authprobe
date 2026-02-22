package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"authprobe/internal/mcpserver"
)

// main selects transport mode and starts the AuthProbe MCP server.
// Inputs: command-line flags (--transport, --http-addr, --http-path, --auth-required).
// Outputs: none (starts server loop; exits process on fatal errors).
func main() {
	transport := flag.String("transport", "stdio", "MCP transport: stdio or http")
	httpAddr := flag.String("http-addr", "127.0.0.1:38080", "address for HTTP transport")
	httpPath := flag.String("http-path", "/mcp", "path for HTTP transport")
	authRequired := flag.Bool("auth-required", false, "advertise OAuth-protected-resource behavior (401 challenge + PRM/auth metadata)")
	flag.Parse()

	log.Printf("%s", startupConnectMessage(*transport, *httpAddr, *httpPath, *authRequired))

	server := mcpserver.New(os.Stdin, os.Stdout, os.Stderr)
	switch *transport {
	case "stdio":
		if err := server.Serve(); err != nil {
			log.Fatal(err)
		}
	case "http":
		path := normalizePath(*httpPath)
		mux := buildHTTPMux(server, path, *authRequired)
		log.Printf("authprobe MCP HTTP server listening on http://%s%s", *httpAddr, path)
		if err := http.ListenAndServe(*httpAddr, mux); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported --transport value %q", *transport)
	}
}

// startupConnectMessage builds a startup hint for client connection configuration.
// Inputs: transport mode, HTTP listen address, HTTP path, and auth-required mode flag.
// Outputs: human-readable startup guidance string for stdio or HTTP mode.
func startupConnectMessage(transport, httpAddr, httpPath string, authRequired bool) string {
	if transport == "http" {
		mode := "public/no-auth"
		if authRequired {
			mode = "auth-required"
		}
		return fmt.Sprintf("Connect to AuthProbe MCP over HTTP at http://%s%s (mode: %s)", httpAddr, normalizePath(httpPath), mode)
	}

	cfg := map[string]any{
		"mcpServers": map[string]any{
			"authprobe": map[string]any{
				"command": filepath.Base(os.Args[0]),
				"args":    []string{"--transport", "stdio"},
			},
		},
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "AuthProbe MCP server ready (stdio transport)."
	}
	return "AuthProbe MCP server ready (stdio transport). Client config:\n" + string(encoded)
}

// normalizePath ensures an HTTP path is non-empty and starts with a slash.
// Inputs: raw path string from CLI flag.
// Outputs: normalized HTTP path (e.g., "/mcp").
func normalizePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/mcp"
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	}
	return "/" + trimmed
}

// buildHTTPMux mounts MCP JSON-RPC and optional OAuth discovery endpoints for HTTP transport.
// Inputs: MCP server handler, normalized MCP path, and auth-required mode flag.
// Outputs: configured HTTP mux.
func buildHTTPMux(server *mcpserver.Server, mcpPath string, authRequired bool) *http.ServeMux {
	mux := http.NewServeMux()
	if authRequired {
		mux.Handle(mcpPath, withProbeChallenge(server, mcpPath))
		mux.HandleFunc("/.well-known/oauth-protected-resource", prmHandler(mcpPath))
		mux.HandleFunc("/.well-known/oauth-protected-resource/", prmHandler(mcpPath))
		mux.HandleFunc("/.well-known/oauth-authorization-server", authMetadataHandler())
		mux.HandleFunc("/.well-known/openid-configuration", authMetadataHandler())
		mux.HandleFunc("/authorize", authorizeHandler)
		mux.HandleFunc("/token", tokenHandler)
		mux.HandleFunc("/register", registerHandler)
	} else {
		mux.Handle(mcpPath, withPublicProbeBehavior(server))
	}
	return mux
}

// withPublicProbeBehavior returns 405 for GET probe requests on public/no-auth servers.
// Inputs: downstream MCP handler.
// Outputs: HTTP handler with public probe behavior.
func withPublicProbeBehavior(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withProbeChallenge returns 401 + WWW-Authenticate on unauthenticated GET probe requests.
// Inputs: downstream MCP handler and MCP endpoint path.
// Outputs: HTTP handler with probe/auth challenge behavior.
func withProbeChallenge(next http.Handler, mcpPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			resourceMetadata := absoluteURL(r, "/.well-known/oauth-protected-resource"+mcpPath)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="authprobe", resource_metadata="%s"`, resourceMetadata))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// prmHandler serves OAuth Protected Resource Metadata for root and path-suffix discovery.
// Inputs: MCP path used to compute the protected resource URL.
// Outputs: HTTP handler that emits PRM JSON.
func prmHandler(mcpPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer := absoluteURL(r, "")
		resource := absoluteURL(r, mcpPath)
		payload := map[string]any{
			"resource":              resource,
			"authorization_servers": []string{issuer},
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

// authMetadataHandler serves RFC 8414/OIDC-compatible authorization server metadata.
// Inputs: request context (host/scheme).
// Outputs: HTTP handler response with JSON metadata.
func authMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer := absoluteURL(r, "")
		payload := map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": absoluteURL(r, "/authorize"),
			"token_endpoint":         absoluteURL(r, "/token"),
			"registration_endpoint":  absoluteURL(r, "/register"),
			"response_types_supported": []string{
				"code",
			},
			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
			},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

// authorizeHandler returns a deterministic not-implemented response for OAuth UI in local mode.
// Inputs: HTTP request.
// Outputs: JSON response noting client-managed OAuth responsibility.
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error":             "client_managed_oauth",
		"error_description": "AuthProbe MCP server does not run OAuth UI; client handles authentication.",
	})
}

// tokenHandler returns RFC6749-style JSON error for token probe readiness checks.
// Inputs: HTTP request.
// Outputs: HTTP 400 JSON error body.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":             "invalid_request",
		"error_description": "token endpoint is metadata-only in local MCP mode",
	})
}

// registerHandler denies open dynamic registration in local mode.
// Inputs: HTTP request.
// Outputs: HTTP 401 JSON error body.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":             "access_denied",
		"error_description": "dynamic registration requires authorization",
	})
}

// absoluteURL builds an absolute URL for the current request host/scheme and given path.
// Inputs: HTTP request and desired path.
// Outputs: absolute URL string.
func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: r.Host, Path: path}
	return strings.TrimRight(u.String(), "/")
}

// writeJSON serializes and writes JSON responses with status and content-type.
// Inputs: response writer, HTTP status, and payload object.
// Outputs: none (writes response directly).
func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
