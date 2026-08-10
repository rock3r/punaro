package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type relayConfigureCommand func(string, string) (operator.Installation, error)

type relayRegisterCommand func(string, string) (operator.Installation, error)

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
		_, _ = fmt.Fprintln(stderr, "relay configuration did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "relay_configured", "directory": installation.Directory})
}

func runRelayRegister(args []string, stdout, stderr io.Writer, register relayRegisterCommand) int {
	flags := flag.NewFlagSet("relay register", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	machineFile := flags.String("machine-enrollment-file", "", "protected single public machine enrollment JSON object")
	confirmed := flags.Bool("yes", false, "confirm post-cutover registration and relay authority publication")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *machineFile == "" || !*confirmed || register == nil {
		return 2
	}
	installation, err := register(*directory, *machineFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay machine registration did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "relay_machine_registered", "directory": installation.Directory})
}

func registerPostCutoverRelayMachine(directory, machineFile string) (operator.Installation, error) {
	installation, err := operator.LoadMailCutoverRecovery(directory)
	if err != nil || installation.MailCutover == nil {
		return operator.Installation{}, fmt.Errorf("post-cutover installation is unavailable")
	}
	ctx := context.Background()
	state, err := inspectSchema(ctx, installation.AppDSNFile)
	if err != nil || state.Classification != punaropostgres.Compatible {
		return operator.Installation{}, fmt.Errorf("post-cutover schema is incompatible")
	}
	if err := verifyInstallationPair(ctx, installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		return operator.Installation{}, fmt.Errorf("post-cutover database roles do not match")
	}
	owner, err := inspectOwner(ctx, installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		return operator.Installation{}, fmt.Errorf("post-cutover owner does not match")
	}
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		return operator.Installation{}, fmt.Errorf("post-cutover administration is unavailable")
	}
	defer func() { _ = admin.Close() }()
	return operator.RegisterPostCutoverRelayMachine(directory, machineFile, func(name string, publicKey ed25519.PublicKey) error {
		_, err := admin.RegisterPostCutoverLegacyMachine(ctx, installation.OwnerPrincipalID, name, publicKey)
		return err
	})
}
