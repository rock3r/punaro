//go:build windows

package memoryclient

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateCredentialPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !hasUnsafeComponent(path) && noWindowsReparseParent(path)
}

func privateCredentialFile(path string, info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && privateWindowsACL(path)
}

func openCredential(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- explicit local credential path is checked before and after open.
	if err != nil {
		return nil, err
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		if err != nil {
			return nil, err
		}
		return nil, os.ErrInvalid
	}
	return os.NewFile(uintptr(handle), path), nil // #nosec G115 -- successful Win32 handles are nonnegative.
}

func hasUnsafeComponent(path string) bool {
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
