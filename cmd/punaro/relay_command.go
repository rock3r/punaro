package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/rock3r/punaro/internal/operator"
)

type relayConfigureCommand func(string, string) (operator.Installation, error)

func runRelayConfigure(args []string, stdout, stderr io.Writer, configure relayConfigureCommand) int {
	flags := flag.NewFlagSet("relay configure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	machinesFile := flags.String("relay-machines-file", "", "protected complete public relay machine enrollment JSON file")
	confirmed := flags.Bool("yes", false, "confirm replacing the complete relay machine enrollment set")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *machinesFile == "" || !*confirmed || configure == nil {
		return 2
	}
	installation, err := configure(*directory, *machinesFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay configuration failed; generated configuration was not changed")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "relay_configured", "directory": installation.Directory})
}
