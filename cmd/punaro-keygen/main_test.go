package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
)

type testFileInfo struct {
	mode os.FileMode
	sys  any
}

func (info testFileInfo) Name() string       { return "fixture" }
func (info testFileInfo) Size() int64        { return 0 }
func (info testFileInfo) Mode() os.FileMode  { return info.mode }
func (info testFileInfo) ModTime() time.Time { return time.Time{} }
func (info testFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info testFileInfo) Sys() any           { return info.sys }

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "punaro-keygen-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestNewMachineKeyProducesEd25519KeypairAndPublicEnrollment(t *testing.T) {
	t.Parallel()
	private, enrollment, err := newMachineKey("mac-review", "agent/mac-review/")
	if err != nil {
		t.Fatal(err)
	}
	if len(private) != ed25519.PrivateKeySize || enrollment.ID != "mac-review" || len(enrollment.PublicKey) != ed25519.PublicKeySize || len(enrollment.EndpointPrefixes) != 1 {
		t.Fatal("invalid generated machine enrollment")
	}
}

func TestPrivateOwnershipChecksRejectOtherUsers(t *testing.T) {
	t.Parallel()
	// #nosec G115 -- os.Geteuid is non-negative on the supported Unix targets.
	owner := uint32(os.Geteuid())
	notOwner := owner + 1
	if notOwner == owner {
		notOwner--
	}
	if !isPrivateOwnedDirectory(testFileInfo{mode: os.ModeDir | 0o700, sys: &syscall.Stat_t{Uid: owner}}) {
		t.Fatal("current-user private directory was rejected")
	}
	if isPrivateOwnedDirectory(testFileInfo{mode: os.ModeDir | 0o700, sys: &syscall.Stat_t{Uid: notOwner}}) {
		t.Fatal("other-user private directory was accepted")
	}
	if !isPrivateOwnedRegularFile(testFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: owner}}) {
		t.Fatal("current-user private file was rejected")
	}
	if isPrivateOwnedRegularFile(testFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: notOwner}}) {
		t.Fatal("other-user private file was accepted")
	}
}

func TestWritePrivateKeyUsesCanonicalRawBase64URL(t *testing.T) {
	t.Parallel()
	private, _, err := newMachineKey("mac-review", "agent/mac-review/")
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "machine.key")
	if err := writePrivateKey(path, private); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- test-owned path inside a private temporary directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 86 || raw[len(raw)-1] == '\n' {
		t.Fatalf("machine key is not canonical raw base64url: %q", raw)
	}
	if _, err := attachmentv2.LoadPrivateEd25519KeyFile(path); err != nil {
		t.Fatalf("canonical machine key is not accepted by v3: %v", err)
	}
}

func TestNormalizeLegacyPrivateKeyRemovesOnlyTrailingNewline(t *testing.T) {
	t.Parallel()
	private, _, err := newMachineKey("mac-review", "agent/mac-review/")
	if err != nil {
		t.Fatal(err)
	}
	directory := privateTestDirectory(t)
	path := filepath.Join(directory, "machine.key")
	if err := os.WriteFile(path, append(encodePrivateKey(private), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := normalizeLegacyPrivateKey(path); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- test-owned path inside a private temporary directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 86 || raw[len(raw)-1] == '\n' {
		t.Fatalf("legacy key was not normalized: %q", raw)
	}
	if _, err := attachmentv2.LoadPrivateEd25519KeyFile(path); err != nil {
		t.Fatalf("normalized machine key is not accepted by v3: %v", err)
	}
}
