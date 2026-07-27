//go:build !windows

package embeddingprovider

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadAPIKeyFileReadsOwnerOnlySingleLineKey(t *testing.T) {
	directory := secureAPIKeyDir(t)
	path := filepath.Join(directory, "provider-key")
	if err := os.WriteFile(path, []byte("provider-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ReadAPIKeyFile(path)
	if err != nil || key != "provider-key" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	hardlink := filepath.Join(directory, "provider-key-copy")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKeyFile(path); err == nil {
		t.Fatal("multiply linked provider key accepted")
	}
}

func TestReadAPIKeyFileRejectsUnsafeInput(t *testing.T) {
	root := secureAPIKeyDir(t)
	unsafe := filepath.Join(root, "unsafe")
	if err := os.WriteFile(unsafe, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- deliberately relax permissions to verify rejection.
	if err := os.Chmod(unsafe, 0o644); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(root, "canonical")
	if err := os.WriteFile(canonical, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":    "provider-key",
		"non-clean":   root + "/./canonical",
		"unsafe mode": unsafe,
		"missing":     filepath.Join(root, "missing"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadAPIKeyFile(path); err == nil {
				t.Fatal("ReadAPIKeyFile accepted unsafe input")
			}
		})
	}
}

func TestPrivateAPIKeyFileRejectsPermissionsRelaxedAfterOpen(t *testing.T) {
	path := filepath.Join(secureAPIKeyDir(t), "provider-key")
	if err := os.WriteFile(path, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- this controlled temporary path models a file changed after open.
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	// #nosec G302 -- deliberately relax permissions to verify post-open validation.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if privateAPIKeyFile(info) {
		t.Fatal("privateAPIKeyFile accepted relaxed permissions after open")
	}
}

func TestReadAPIKeyFileRejectsWritableParent(t *testing.T) {
	directory := secureAPIKeyDir(t)
	path := filepath.Join(directory, "provider-key")
	if err := os.WriteFile(path, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- deliberately unsafe parent verifies rejection.
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKeyFile(path); err == nil {
		t.Fatal("provider key beneath writable directory accepted")
	}
}

func TestReadAPIKeyFileRejectsInvalidContents(t *testing.T) {
	directory := secureAPIKeyDir(t)
	path := filepath.Join(directory, "provider-key")
	for name, value := range map[string]string{
		"empty":      "",
		"whitespace": "two words",
		"multiline":  "first\nsecond",
		"nul":        "provider\x00key",
		"delete":     "provider\x7fkey",
		"oversized":  strings.Repeat("a", maxAPIKeyFileBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadAPIKeyFile(path); err == nil {
				t.Fatalf("ReadAPIKeyFile accepted invalid %s key", name)
			}
		})
	}
}

func TestReadAPIKeyFileRejectsSymlinkedParent(t *testing.T) {
	directory := secureAPIKeyDir(t)
	target := filepath.Join(directory, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(target, "provider-key")
	if err := os.WriteFile(path, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-parent")
	if err := os.Symlink(target, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKeyFile(filepath.Join(linkedParent, "provider-key")); err == nil {
		t.Fatal("provider key below symlinked parent accepted")
	}
}

func TestReadAPIKeyFileRejectsSymlinkedFile(t *testing.T) {
	directory := secureAPIKeyDir(t)
	target := filepath.Join(directory, "provider-key-target")
	if err := os.WriteFile(target, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "provider-key")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKeyFile(path); err == nil {
		t.Fatal("symlinked provider key accepted")
	}
}

func TestPrivateAPIKeyFileRejectsForeignOwner(t *testing.T) {
	path := filepath.Join(secureAPIKeyDir(t), "provider-key")
	if err := os.WriteFile(path, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("provider key metadata did not contain syscall.Stat_t")
	}
	foreign := *stat
	foreign.Uid++
	if !privateAPIKeyFile(apiKeyFileInfo{FileInfo: info, sys: &foreign}) {
		return
	}
	t.Fatal("provider key with foreign owner accepted")
}

func TestTrustedAPIKeyDirectoryRejectsForeignOwner(t *testing.T) {
	directory := secureAPIKeyDir(t)
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("provider key directory metadata did not contain syscall.Stat_t")
	}
	foreign := *stat
	foreign.Uid++
	uid := os.Getuid()
	if uid < 0 {
		t.Fatal("current UID is negative")
	}
	currentUID := uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
	if trustedAPIKeyDirectory(apiKeyFileInfo{FileInfo: info, sys: &foreign}, currentUID) {
		t.Fatal("foreign-owned provider key directory accepted")
	}
}

func secureAPIKeyDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(home, ".embeddingprovider-key-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary API key directory: %v", err)
		}
	})
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- test directory must be owner-only.
		t.Fatal(err)
	}
	if !privateAPIKeyPath(filepath.Join(directory, "provider-key")) {
		t.Fatal("temporary API key directory has unsafe ancestry")
	}
	return directory
}

type apiKeyFileInfo struct {
	os.FileInfo
	sys any
}

func (info apiKeyFileInfo) Sys() any { return info.sys }
