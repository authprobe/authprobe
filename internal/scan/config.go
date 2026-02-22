package scan

import "time"

// BaseConfigInput captures shared scan settings used by CLI and MCP wrappers.
type BaseConfigInput struct {
	Target              string
	Command             string
	Headers             []string
	Timeout             time.Duration
	MCPProbeTimeout     time.Duration
	MCPMode             string
	MCPProtocolVersion  string
	RFCMode             string
	AllowPrivateIssuers bool
	Insecure            bool
	NoFollowRedirects   bool
	TraceFailure        bool
	Redact              bool
}

// NewBaseConfig builds the common ScanConfig portion shared by CLI and MCP.
func NewBaseConfig(in BaseConfigInput) ScanConfig {
	return ScanConfig{
		Target:              in.Target,
		Command:             in.Command,
		Headers:             in.Headers,
		Timeout:             in.Timeout,
		MCPProbeTimeout:     in.MCPProbeTimeout,
		MCPMode:             in.MCPMode,
		MCPProtocolVersion:  in.MCPProtocolVersion,
		RFCMode:             in.RFCMode,
		AllowPrivateIssuers: in.AllowPrivateIssuers,
		Insecure:            in.Insecure,
		NoFollowRedirects:   in.NoFollowRedirects,
		TraceFailure:        in.TraceFailure,
		Redact:              in.Redact,
	}
}
