//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func safeStateDir(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func safeStateChild(directory, path string) bool {
	return safeStateDir(directory) && filepath.Dir(path) == directory && filepath.Base(path) != "." && filepath.Base(path) != ".."
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe private directory")
		}
		return privateDir(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Existing directories are never re-ACLed: a mistyped state path must fail
	// closed rather than changing the permissions of a user directory. Build
	// missing parents explicitly so only paths this invocation created receive
	// the private DACL.
	missing := []string{path}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe private directory")
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) || parent == filepath.Dir(parent) {
			return err
		}
		missing = append(missing, parent)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		created := false
		if err := os.Mkdir(directory, 0o700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
		} else {
			created = true
		}
		if created && protectWindowsPath(directory) != nil {
			return errors.New("could not protect private directory")
		}
		if err := privateDir(directory); err != nil {
			return err
		}
	}
	return privateDir(path)
}
func privateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateWindowsACL(path) {
		return errors.New("unsafe private directory")
	}
	return nil
}
func readPrivate(path string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("unsafe private file")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !privateWindowsACL(path) {
		return nil, errors.New("unsafe private file")
	}
	file, err := os.Open(path) // #nosec G304 -- validated absolute local private file; remote data never selects it.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("private file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("invalid private file")
	}
	return raw, nil
}
func writePrivateNew(path string, raw []byte) error {
	if len(raw) == 0 || !filepath.IsAbs(path) {
		return errors.New("unsafe private file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed child of validated private state.
	if err != nil {
		return err
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(path) // #nosec G703 -- exclusive new child of the validated private state directory.
		}
	}()
	if err := file.Close(); err != nil {
		return err
	}
	// The file is deliberately empty while it has the inherited creation ACL.
	// Install the verified exclusive DACL before opening it again to write a
	// credential or enrollment code.
	if err := protectWindowsPath(path); err != nil || !privateWindowsACL(path) {
		return errors.New("could not protect private file")
	}
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- DACL is verified private before this secret write.
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	removeOnFailure = false
	return nil
}
func writeCredential(path, credential string) error {
	if credential == "" || strings.ContainsAny(credential, " \t\r\n") {
		return errors.New("invalid credential")
	}
	if raw, err := readPrivate(path, maxEnrollmentFile); err == nil {
		if string(raw) == credential+"\n" {
			return nil
		}
		return errors.New("credential exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePrivateNew(path, []byte(credential+"\n"))
}

func privateWindowsACL(path string) bool {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask&windows.ACCESS_MASK(0x1f01ff) != windows.ACCESS_MASK(0x1f01ff) {
		return false
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SidStart is the documented flexible-array start of this ACE's SID.
	return aceSID.Equals(user.User.Sid)
}

func protectWindowsPath(path string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return errors.New("current user is unavailable")
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		// Use the expanded file FullControl mask rather than GENERIC_ALL so the
		// post-write verifier sees exactly the DACL shape it accepts.
		AccessPermissions: windows.ACCESS_MASK(0x1f01ff),
		AccessMode:        windows.GRANT_ACCESS,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil)
}
