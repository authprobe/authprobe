package main

import (
	"os"

	"authprobe/internal/cli"
)

var version = "dev"
var commit = "none"
var date = "unknown"

// main injects build metadata and runs the CLI entrypoint.
// Inputs: process args/stdin/stdout/stderr.
// Outputs: process exit via os.Exit with CLI status code.
func main() {
	cli.SetVersionInfo(cli.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
