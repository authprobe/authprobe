package main

import (
	"os"

	"authprobe/internal/cli"
)

var version = "dev"
var commit = "none"
var date = "unknown"

func main() {
	cli.SetVersionInfo(cli.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
