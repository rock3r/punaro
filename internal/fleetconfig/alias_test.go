package fleetconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateAliasSymlinkDoesNotOverwriteUnmanagedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "AGENTS.md")
	link := filepath.Join(dir, "CLAUDE.md")
	if err := os.WriteFile(target, []byte("# fleet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	disabled, err := CreateAlias(target, link, false)
	if err != nil || disabled.State != "disabled" {
		t.Fatalf("disabled=%#v err=%v", disabled, err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("disabled alias created a file")
	}
	linked, err := CreateAlias(target, link, true)
	if runtime.GOOS == "windows" && linked.State == "unsupported" {
		return
	}
	if err != nil || linked.State != "linked" {
		t.Fatalf("linked=%#v err=%v", linked, err)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink info=%v err=%v", info, err)
	}
	got, err := os.Readlink(link)
	if err != nil || filepath.Clean(got) != filepath.Clean(target) {
		t.Fatalf("readlink=%q err=%v", got, err)
	}
	collisionPath := filepath.Join(dir, "CLAUDE-real.md")
	if err := os.WriteFile(collisionPath, []byte("local claude\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collision, err := CreateAlias(target, collisionPath, true)
	if err != nil || collision.State != "collision" {
		t.Fatalf("collision=%#v err=%v", collision, err)
	}
	body, err := os.ReadFile(collisionPath) //nolint:gosec // G304: test fixture path under t.TempDir.
	if err != nil || string(body) != "local claude\n" {
		t.Fatalf("overwrote unmanaged file %q", body)
	}
}

func TestCreateAliasRemovesManagedLinkWhenDisabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "AGENTS.md")
	link := filepath.Join(dir, "CLAUDE.md")
	if err := os.WriteFile(target, []byte("# fleet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked, err := CreateAlias(target, link, true)
	if runtime.GOOS == "windows" && linked.State == "unsupported" {
		return
	}
	if err != nil || linked.State != "linked" {
		t.Fatalf("linked=%#v err=%v", linked, err)
	}
	disabled, err := CreateAlias(target, link, false)
	if err != nil || disabled.State != "disabled" {
		t.Fatalf("disabled=%#v err=%v", disabled, err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("disabled alias left a managed symlink")
	}
	collisionPath := filepath.Join(dir, "CLAUDE-real.md")
	if err := os.WriteFile(collisionPath, []byte("local claude\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collision, err := CreateAlias(target, collisionPath, false)
	if err != nil || collision.State != "disabled" {
		t.Fatalf("collision disable=%#v err=%v", collision, err)
	}
	body, err := os.ReadFile(collisionPath) //nolint:gosec // G304: test fixture path under t.TempDir.
	if err != nil || string(body) != "local claude\n" {
		t.Fatalf("disabled alias removed unmanaged file %q", body)
	}
}
