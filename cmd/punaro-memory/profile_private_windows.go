//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateProfilePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !hasWindowsUnsafePathComponent(path) && noWindowsReparseParent(path)
}

func privateProfileFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
func privateProfileFilePath(path string) bool { return privateWindowsACL(path) }

func protectProfileFile(path string) error {
	if err := protectWindowsPath(path); err != nil || !privateWindowsACL(path) {
		return errors.New("could not protect profile")
	}
	return nil
}

func syncProfileDirectory(string) error { return nil }

func hasWindowsUnsafePathComponent(path string) bool {
	rest := path[len(filepath.VolumeName(path)):]
	for {
		part, next, found := strings.Cut(rest, string(filepath.Separator))
		if strings.ContainsAny(part, ":~") || strings.TrimRight(part, ". ") != part {
			return true
		}
		if !found {
			return false
		}
		rest = next
	}
}

func noWindowsReparseParent(path string) bool {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(parent))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return false
		}
		if parent == filepath.Dir(parent) {
			return true
		}
	}
}

// privateWindowsACL accepts precisely the installer-owned protected DACL:
// one FullControl ACE for the current user and no inherited or shared access.
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
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != windows.ACCESS_MASK(0x1f01ff) {
		return false
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- documented flexible-array start of this ACE SID.
	return aceSID.Equals(user.User.Sid)
}

func protectWindowsPath(path string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return errors.New("current user is unavailable")
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(0x1f01ff),
		AccessMode:        windows.GRANT_ACCESS,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil)
}
