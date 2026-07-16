// punaro-keygen creates a machine keypair while printing only the public
// enrollment record for the relay configuration.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

func main() {
	flags := flag.NewFlagSet("punaro-keygen", flag.ExitOnError)
	id := flags.String("id", "", "machine ID")
	prefix := flags.String("endpoint-prefix", "", "exclusive endpoint prefix")
	privateFile := flags.String("private-key-file", "", "new private key file (must not exist)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fail(err)
	}
	private, enrollment, err := newMachineKey(*id, *prefix)
	if err != nil {
		fail(err)
	}
	if strings.TrimSpace(*privateFile) == "" {
		fail(fmt.Errorf("--private-key-file is required"))
	}
	file, err := os.OpenFile(*privateFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(fmt.Errorf("create private key file: %w", err))
	}
	if _, err := file.WriteString(base64.RawURLEncoding.EncodeToString(private) + "\n"); err != nil {
		_ = file.Close()
		fail(fmt.Errorf("write private key file: %w", err))
	}
	if err := file.Close(); err != nil {
		fail(fmt.Errorf("close private key file: %w", err))
	}
	output := struct {
		ID               string   `json:"id"`
		PublicKey        string   `json:"public_key"`
		EndpointPrefixes []string `json:"endpoint_prefixes"`
	}{ID: enrollment.ID, PublicKey: base64.RawURLEncoding.EncodeToString(enrollment.PublicKey), EndpointPrefixes: enrollment.EndpointPrefixes}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fail(err)
	}
}

func newMachineKey(id, prefix string) (ed25519.PrivateKey, relay.Machine, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(prefix) == "" {
		return nil, relay.Machine{}, fmt.Errorf("machine ID and endpoint prefix are required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, relay.Machine{}, fmt.Errorf("generate machine key: %w", err)
	}
	return private, relay.Machine{ID: id, PublicKey: public, EndpointPrefixes: []string{prefix}}, nil
}

func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "punaro-keygen:", err)
	os.Exit(2)
}
