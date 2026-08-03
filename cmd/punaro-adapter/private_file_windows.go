//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows installer grants the current user an exclusive ACL on the
// configuration directory. Keep a no-reparse-point, bounded descriptor read
// here; Windows does not expose POSIX mode or UID checks through os.FileInfo.
func readPrivateFile(path, label string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	// #nosec G703 -- path is a local operator configuration path, constrained to
	// an absolute, non-reparse regular file under the installer-owned ACL.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	if !privateWindowsACL(path) {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	// #nosec G304,G703 -- validated absolute local configuration path; remote data
	// never selects this file.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("invalid %s file", label)
	}
	return raw, nil
}

// privateWindowsACL accepts only a protected, current-user-only FullControl
// DACL. This prevents an explicit profile path from weakening the
// confidentiality boundary for embedded service secrets.
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
	// Protect-PunaroPath emits one FullControl ACE for the current SID, with no
	// inherited or shared grants. DACL() also rejects absent/null DACLs.
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != windows.ACCESS_MASK(0x1f01ff) {
		return false
	}
	// #nosec G103 -- SidStart is the documented flexible-array start of this ACE's SID.
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	return aceSID.Equals(user.User.Sid)
}
