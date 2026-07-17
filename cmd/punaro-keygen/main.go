// punaro-keygen creates a machine keypair while printing only the public
// enrollment record for the relay configuration.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

func main() {
	flags := flag.NewFlagSet("punaro-keygen", flag.ExitOnError)
	id := flags.String("id", "", "machine ID")
	prefix := flags.String("endpoint-prefix", "", "exclusive endpoint prefix")
	privateFile := flags.String("private-key-file", "", "new private key file (must not exist)")
	normalizeLegacyFile := flags.String("normalize-legacy-private-key-file", "", "atomically remove the legacy trailing newline from one private key file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fail(err)
	}
	if *normalizeLegacyFile != "" {
		if *id != "" || *prefix != "" || *privateFile != "" || flags.NArg() != 0 {
			fail(errors.New("--normalize-legacy-private-key-file cannot be combined with key-generation flags"))
		}
		if err := normalizeLegacyPrivateKey(*normalizeLegacyFile); err != nil {
			fail(err)
		}
		return
	}
	private, enrollment, err := newMachineKey(*id, *prefix)
	if err != nil {
		fail(err)
	}
	if strings.TrimSpace(*privateFile) == "" {
		fail(fmt.Errorf("--private-key-file is required"))
	}
	if err := writePrivateKey(*privateFile, private); err != nil {
		fail(err)
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

func encodePrivateKey(private ed25519.PrivateKey) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(private))
}

func writePrivateKey(path string, private ed25519.PrivateKey) error {
	// #nosec G304 -- path is an explicit CLI output selected by the local owner.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	if _, err := file.Write(encodePrivateKey(private)); err != nil {
		_ = file.Close()
		return fmt.Errorf("write private key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private key file: %w", err)
	}
	return nil
}

// normalizeLegacyPrivateKey performs the one supported migration from the
// historical newline-terminated writer to the canonical raw-base64url format.
// It validates the whole Ed25519 private key before atomically replacing it.
func normalizeLegacyPrivateKey(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("legacy private key path must be absolute")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("legacy private key parent must be private and non-symlinked")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("legacy private key file must be private and non-symlinked")
	}
	// #nosec G304 -- path is an explicit migration target, constrained above to a
	// private, absolute, non-symlinked regular file.
	file, err := os.Open(path)
	if err != nil {
		return errors.New("legacy private key is unavailable")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize)+2)))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.New("legacy private key is unavailable")
	}
	encodedLength := base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize)
	if len(raw) != encodedLength+1 || raw[encodedLength] != '\n' {
		return errors.New("legacy private key does not have exactly one trailing newline")
	}
	encoded := raw[:encodedLength]
	private, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil || len(private) != ed25519.PrivateKeySize || string(encodePrivateKey(ed25519.PrivateKey(private))) != string(encoded) || !ed25519.PrivateKey(private).Equal(ed25519.NewKeyFromSeed(ed25519.PrivateKey(private).Seed())) {
		return errors.New("legacy private key is not a canonical Ed25519 private key")
	}
	temporary, err := os.CreateTemp(parent, ".punaro-machine-key-*")
	if err != nil {
		return fmt.Errorf("create private key migration file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set private key migration mode: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write private key migration file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync private key migration file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private key migration file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace legacy private key: %w", err)
	}
	return nil
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
