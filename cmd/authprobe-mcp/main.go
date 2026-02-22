package main

import (
	"os"

	"authprobe/internal/cli"
)

func main() {
	os.Exit(cli.Run([]string{"mcp", "--transport", "stdio"}, os.Stdout, os.Stderr))
}
