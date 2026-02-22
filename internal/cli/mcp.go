package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"authprobe/internal/mcpserver"
)

// runMCP starts the embedded MCP server in stdio or HTTP transport mode.
// Inputs: mcp args, stdout writer, stderr writer.
// Outputs: integer exit code.
func runMCP(args []string, stdout, stderr io.Writer) int {
	if hasHelp(args) {
		fmt.Fprint(stdout, mcpHelp)
		return 0
	}

	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	transport := fs.String("transport", "stdio", "")
	httpAddr := fs.String("http-addr", "127.0.0.1:38080", "")
	httpPath := fs.String("http-path", "/mcp", "")
	authRequired := fs.Bool("auth-required", false, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 3
	}

	logger := log.New(stderr, "", log.LstdFlags)
	logger.Printf("%s", startupConnectMessage(*transport, *httpAddr, *httpPath, *authRequired))

	server := mcpserver.New(os.Stdin, stdout, stderr)
	switch *transport {
	case "stdio":
		if err := server.Serve(); err != nil {
			logger.Print(err)
			return 1
		}
	case "http":
		path := normalizePath(*httpPath)
		mux := buildHTTPMux(server, path, *authRequired)
		logger.Printf("authprobe MCP HTTP server listening on http://%s%s", *httpAddr, path)
		if err := http.ListenAndServe(*httpAddr, mux); err != nil {
			logger.Print(err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "error: unsupported --transport value %q\n", *transport)
		return 3
	}

	return 0
}

// startupConnectMessage builds user-facing startup guidance for MCP connection config.
// Inputs: transport mode, HTTP address, HTTP path, auth-required flag.
// Outputs: connection hint string.
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
				"args":    []string{"mcp", "--transport", "stdio"},
			},
		},
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "AuthProbe MCP server ready (stdio transport)."
	}
	return "AuthProbe MCP server ready (stdio transport). Client config:\n" + string(encoded)
}

// normalizePath ensures a non-empty leading-slash HTTP path.
// Inputs: raw path string.
// Outputs: normalized path string.
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

// buildHTTPMux wires MCP endpoint and optional OAuth discovery/auth handlers.
// Inputs: MCP server handler, MCP path, auth-required flag.
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

// withPublicProbeBehavior returns 405 for GET probes in public mode.
// Inputs: downstream HTTP handler.
// Outputs: wrapped HTTP handler.
func withPublicProbeBehavior(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withProbeChallenge returns OAuth challenge responses for GET probes.
// Inputs: downstream HTTP handler and MCP path.
// Outputs: wrapped HTTP handler.
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

// prmHandler serves OAuth protected resource metadata payloads.
// Inputs: MCP path for resource URL composition.
// Outputs: HTTP handler function.
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

// authMetadataHandler serves authorization server metadata.
// Inputs: none.
// Outputs: HTTP handler function.
func authMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer := absoluteURL(r, "")
		payload := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"registration_endpoint":                 issuer + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"},
			"scopes_supported":                      []string{"openid", "profile", "email"},
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

// authorizeHandler returns a placeholder authorization endpoint response.
// Inputs: HTTP response writer and request.
// Outputs: JSON HTTP response.
func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented"})
}

// tokenHandler returns a probe-friendly token endpoint error response.
// Inputs: HTTP response writer and request.
// Outputs: JSON HTTP response.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
}

// registerHandler returns unauthorized for dynamic client registration probes.
// Inputs: HTTP response writer and request.
// Outputs: JSON HTTP response.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized_client"})
}

// absoluteURL builds an absolute URL from request host/scheme and path.
// Inputs: incoming HTTP request and path string.
// Outputs: absolute URL string.
func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	u := url.URL{Scheme: scheme, Host: host, Path: path}
	return u.String()
}

// writeJSON serializes payload as JSON with status and content type headers.
// Inputs: HTTP response writer, status code, arbitrary payload.
// Outputs: JSON HTTP response bytes to writer.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
