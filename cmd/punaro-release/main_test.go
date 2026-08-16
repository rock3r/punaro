package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestReleaseToolAssemblesSignsAndVerifiesExactBytes(t *testing.T) {
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "punaro-adapter-linux-amd64"), []byte("adapter"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(dir, "production.yaml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"assemble",
		"--dir", artifacts,
		"--release", "v0.1.0",
		"--sequence", "1",
		"--catalog-sequence", "1",
		"--published-at", "2026-08-16T12:00:00Z",
		"--expires-at", "2026-08-23T12:00:00Z",
		"--compose-file", compose,
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate", "--dir", artifacts}); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(artifacts, punarorelease.ReleaseManifestFile)
	privatePath := filepath.Join(dir, "release.key")
	publicPath := filepath.Join(dir, "release.pub")
	signaturePath := filepath.Join(dir, punarorelease.ReleaseSignatureFile)
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", privatePath, "--public-key-file", publicPath}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-1", "--key-file", privatePath, "--in", manifestPath, "--out", signaturePath}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", publicPath, "--document", manifestPath, "--signature", signaturePath}); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := punarorelease.ParseReleaseManifest(manifest); err != nil {
		t.Fatal(err)
	}
	catalog, err := os.ReadFile(filepath.Join(artifacts, punarorelease.CatalogFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := punarorelease.ParseCatalog(catalog); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key permissions=%v", info.Mode())
	}
}

func TestReleaseToolRefusesToOverwritePrivateKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "release.key")
	publicPath := filepath.Join(dir, "release.pub")
	if err := os.WriteFile(privatePath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", privatePath, "--public-key-file", publicPath}); err == nil {
		t.Fatal("existing private key overwritten")
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"schema":1}`)
	if err := os.WriteFile(filepath.Join(dir, "doc.json"), document, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.key"), punarorelease.EncodePrivateKey(private), 0o600); err != nil {
		t.Fatal(err)
	}
	public, err := punarorelease.EncodePublicKeys("punaro-release-1", private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.pub"), public, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-1", "--key-file", filepath.Join(dir, "release.key"), "--in", filepath.Join(dir, "doc.json"), "--out", filepath.Join(dir, "doc.sig")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc.json"), []byte(`{"schema":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", filepath.Join(dir, "release.pub"), "--document", filepath.Join(dir, "doc.json"), "--signature", filepath.Join(dir, "doc.sig")}); err == nil {
		t.Fatal("tampered document verified")
	}
}
