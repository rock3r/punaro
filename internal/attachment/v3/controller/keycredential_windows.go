//go:build windows

package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/zeebo/blake3"
	"golang.org/x/sys/windows"
)

const maxDPAPIHostKeyBlob = 4096

// DPAPIHostKeyProvider reads a CurrentUser DPAPI-protected 32-byte wrapping
// key from a local file. The blob is encrypted at rest by Windows and no raw
// wrapping key is accepted through configuration or an environment variable.
type DPAPIHostKeyProvider struct{ File string }

// SenderKeyEncryptionKey returns the DPAPI-unprotected wrapping key.
func (p DPAPIHostKeyProvider) SenderKeyEncryptionKey(context.Context) ([32]byte, error) {
	var key [32]byte
	raw, err := p.read()
	if err != nil || len(raw) != len(key) {
		return key, errors.New("windows DPAPI sender key is unavailable")
	}
	copy(key[:], raw)
	zeroBytes(raw)
	return key, nil
}

// SenderKeyEncryptionKeyID derives a non-secret identifier from the current
// host key so wrapped journal entries fail closed after key replacement.
func (p DPAPIHostKeyProvider) SenderKeyEncryptionKeyID(ctx context.Context) ([32]byte, error) {
	key, err := p.SenderKeyEncryptionKey(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(append([]byte("punaro/host-key-id/v1\x00"), key[:]...)), nil
}

// WriteDPAPIHostKeyFile creates a new CurrentUser DPAPI-wrapped key at path.
// Callers must create and ACL the containing directory before invoking it.
func WriteDPAPIHostKeyFile(path string) error {
	if err := validateDPAPIHostKeyPath(path, true); err != nil {
		return err
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return errors.New("could not generate Windows DPAPI sender key")
	}
	defer zeroBytes(raw)
	protected, err := protectCurrentUser(raw)
	if err != nil {
		return errors.New("could not protect Windows DPAPI sender key")
	}
	defer zeroBytes(protected)
	// #nosec G304 -- path is an explicit, validated private local output chosen
	// by the operator; O_EXCL prevents replacement of a pre-existing key blob.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("could not create Windows DPAPI sender key file")
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(protected); err != nil || file.Sync() != nil || file.Close() != nil {
		_ = file.Close()
		return errors.New("could not write Windows DPAPI sender key file")
	}
	remove = false
	return nil
}

func (p DPAPIHostKeyProvider) read() ([]byte, error) {
	if err := validateDPAPIHostKeyPath(p.File, false); err != nil {
		return nil, err
	}
	file, err := os.Open(p.File)
	if err != nil {
		return nil, errors.New("windows DPAPI sender key file is unavailable")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("windows DPAPI sender key file is unavailable")
	}
	protected, err := io.ReadAll(io.LimitReader(file, maxDPAPIHostKeyBlob+1))
	if err != nil || len(protected) == 0 || len(protected) > maxDPAPIHostKeyBlob {
		return nil, errors.New("windows DPAPI sender key file is unavailable")
	}
	defer zeroBytes(protected)
	return unprotectCurrentUser(protected)
}

func validateDPAPIHostKeyPath(path string, mustNotExist bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("invalid Windows DPAPI sender key file")
	}
	info, err := os.Lstat(path)
	if mustNotExist {
		if err == nil || !os.IsNotExist(err) {
			return errors.New("windows DPAPI sender key file already exists")
		}
		parent, parentErr := os.Lstat(filepath.Dir(path))
		if parentErr != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
			return errors.New("windows DPAPI sender key directory is unavailable")
		}
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("windows DPAPI sender key file is unavailable")
	}
	return nil
}

func protectCurrentUser(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty Windows DPAPI input")
	}
	// #nosec G115 -- raw is a generated 32-byte wrapping key.
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer freeDataBlob(&out)
	if out.Data == nil || out.Size == 0 || out.Size > maxDPAPIHostKeyBlob {
		return nil, errors.New("invalid Windows DPAPI output")
	}
	// #nosec G103 -- CryptProtectData returned this bounded LocalAlloc blob.
	protected := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	runtime.KeepAlive(raw)
	return protected, nil
}

func unprotectCurrentUser(protected []byte) ([]byte, error) {
	if len(protected) == 0 || len(protected) > maxDPAPIHostKeyBlob {
		return nil, errors.New("invalid Windows DPAPI input")
	}
	// #nosec G115 -- protected was bounded to maxDPAPIHostKeyBlob above.
	in := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer freeDataBlob(&out)
	if out.Data == nil || out.Size != 32 {
		return nil, errors.New("invalid Windows DPAPI output")
	}
	// #nosec G103 -- CryptUnprotectData returned exactly 32 bytes in LocalAlloc memory.
	raw := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	runtime.KeepAlive(protected)
	return raw, nil
}

func freeDataBlob(blob *windows.DataBlob) {
	if blob.Data != nil {
		// #nosec G103 -- Windows requires LocalFree for the DataBlob allocation.
		_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(blob.Data))))
		blob.Data = nil
		blob.Size = 0
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
