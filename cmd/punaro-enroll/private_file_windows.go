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
	base := filepath.Base(path)
	// A tilde is legal in a Win32 filename, but it can also be an NTFS 8.3
	// short-name alias for the recovery journal or lock. Credentials are named
	// by this local CLI, so reserve it rather than letting an alias redirect a
	// later recovery-file operation.
	return safeStateDir(directory) && filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) == directory && base != "." && base != ".." && !strings.ContainsAny(base, ":~")
}

// Win32 normalizes trailing dots and spaces in ordinary file paths, so those
// spellings must remain reserved alongside the journal's canonical name.
func reservedStateFileName(name string) bool {
	name = strings.TrimRight(name, ". ")
	return strings.EqualFold(name, redemptionJournalName) || strings.EqualFold(name, redemptionLockName)
}

func lockEnrollmentState(stateDir string) (func(), error) {
	path := filepath.Join(stateDir, redemptionLockName)
	// Publish a fully protected file atomically. Creating the final lock path
	// first would expose a crash window where its inherited DACL permanently
	// poisons all later redemptions.
	if err := writePrivateAtomicNew(path, []byte("lock\n")); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- fixed private state child.
	if err != nil {
		return nil, err
	}
	if !privateWindowsACL(path) {
		_ = file.Close()
		return nil, errors.New("unsafe enrollment lock")
	}
	overlapped := windows.Overlapped{}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
		_ = file.Close()
	}, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe private directory")
		}
		if err := privateDir(path); err != nil {
			return err
		}
		return syncPrivateDirectory(filepath.Dir(path))
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
			if grandparent := filepath.Dir(parent); grandparent != parent {
				if err := syncPrivateDirectory(grandparent); err != nil {
					return err
				}
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
			if err := syncPrivateDirectory(filepath.Dir(directory)); err != nil {
				return err
			}
		} else {
			created = true
		}
		if created {
			if err := protectWindowsPath(directory); err != nil {
				_ = os.Remove(directory) // #nosec G703 -- exact empty directory created by this invocation.
				return errors.New("could not protect private directory")
			}
			if err := privateDir(directory); err != nil {
				_ = os.Remove(directory) // #nosec G703 -- exact new directory failed post-protection verification.
				return err
			}
			if err := syncPrivateDirectory(filepath.Dir(directory)); err != nil {
				return err
			}
			continue
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

func protectEnrollmentMaterial(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("unsafe enrollment material")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maxEnrollmentMaterial {
		return errors.New("unsafe enrollment material")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	) // #nosec G304 -- explicit absolute transfer path is opened without following a final reparse point.
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	opened, err := file.Stat()
	var details windows.ByHandleFileInformation
	if detailsErr := windows.GetFileInformationByHandle(handle, &details); err != nil || detailsErr != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || !opened.Mode().IsRegular() || opened.Size() < 1 || opened.Size() > maxEnrollmentMaterial || !os.SameFile(before, opened) {
		_ = file.Close()
		return errors.New("enrollment material changed while opening")
	}
	user, acl, err := currentUserFullControlACL()
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user, nil, acl, nil); err != nil {
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
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || after.Size() < 1 || after.Size() > maxEnrollmentMaterial || !os.SameFile(opened, after) || !privateWindowsACL(path) {
		return errors.New("protected enrollment material could not be verified")
	}
	return syncPrivateDirectory(filepath.Dir(path))
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
	return syncPrivateDirectory(filepath.Dir(path))
}

func writePrivateAtomic(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Close(); err != nil {
		return err
	}
	if err := protectWindowsPath(temporary); err != nil || !privateWindowsACL(temporary) {
		return errors.New("could not protect private file")
	}
	file, err = os.OpenFile(temporary, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- DACL is verified private before this secret write.
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
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	removeOnFailure = false
	return syncPrivateDirectory(filepath.Dir(path))
}

func writePrivateAtomicNew(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Close(); err != nil {
		return err
	}
	if err := protectWindowsPath(temporary); err != nil || !privateWindowsACL(temporary) {
		return errors.New("could not protect private file")
	}
	file, err = os.OpenFile(temporary, os.O_WRONLY|os.O_TRUNC, 0) // #nosec G304 -- DACL is verified private before this secret write.
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
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	removeTemporary = false
	return syncPrivateDirectory(filepath.Dir(path))
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
	return writePrivateAtomicNew(path, []byte(credential+"\n"))
}

var syncPrivateDirectory = syncPrivateDirectoryImpl

func syncPrivateDirectoryImpl(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return windows.FlushFileBuffers(handle)
}

func removePrivate(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	// The caller's durable credential is already published. Attempt to flush
	// the unlink, but do not turn that completed enrollment into a false
	// failure when the directory metadata barrier is unavailable.
	_ = syncPrivateDirectory(filepath.Dir(path))
	return nil
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

var protectWindowsPath = protectWindowsPathImpl

func protectWindowsPathImpl(path string) error {
	user, acl, err := currentUserFullControlACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user, nil, acl, nil)
}

func currentUserFullControlACL() (*windows.SID, *windows.ACL, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil, nil, errors.New("current user is unavailable")
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		// Use the expanded file FullControl mask rather than GENERIC_ALL so the
		// post-write verifier sees exactly the DACL shape it accepts.
		AccessPermissions: windows.ACCESS_MASK(0x1f01ff),
		AccessMode:        windows.GRANT_ACCESS,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
	}}, nil)
	if err != nil {
		return nil, nil, err
	}
	return user.User.Sid, acl, nil
}
