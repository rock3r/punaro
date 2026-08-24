//go:build windows

package canopiadapter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func canonicalSpoolDirectory(path string) (string, error) {
	return finalWindowsSpoolPath(path)
}

func validateSpoolDirectoryAncestors(path string) error {
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(filepath.Clean(path), current)
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := windows.GetFileAttributes(name)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return err
		}
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("canopi spool path must not traverse a Windows reparse point")
		}
	}
	return nil
}

func prepareSpoolRepairCoordinator(directory string) error {
	file, err := openSpoolRepairCoordinator(filepath.Join(directory, ".canopi-spool-repair.lock"))
	if err != nil {
		return err
	}
	return file.Close()
}

func secureSpoolDirectory(path string, before os.FileInfo) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return errors.New("cannot identify the current user for the Canopi spool")
	}
	if !windowsSpoolOwnedBy(path, user.User.Sid) {
		return errors.New("canopi spool directory must be owned by the current user")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("cannot construct the private Canopi spool ACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || !privateWindowsSpoolACL(path, user.User.Sid) {
		return errors.New("canopi spool directory is not protected by an exclusive current-user ACL")
	}
	return nil
}

func privateSpoolDirectory(path string, info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && privateWindowsSpoolACL(path, currentWindowsSpoolSID())
}

func privateSpoolFile(path string, info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && privateWindowsSpoolACL(path, currentWindowsSpoolSID())
}

func openSpoolEventFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- path is inside the validated private spool and checked before and after.
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

func protectSpoolFile(path string, file *os.File) error {
	sid := currentWindowsSpoolSID()
	if sid == nil {
		return errors.New("cannot identify the current user for a queued Canopi event")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("cannot construct a private queued-event ACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !privateSpoolFile(path, info) {
		return errors.New("cannot protect queued Canopi event")
	}
	return nil
}

func currentWindowsSpoolSID() *windows.SID {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil
	}
	return user.User.Sid
}

func windowsSpoolOwnedBy(path string, sid *windows.SID) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	return err == nil && owner != nil && owner.Equals(sid)
}

func privateWindowsSpoolACL(path string, sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(sid) {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return false
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != windows.ACCESS_MASK(0x1f01ff) {
		return false
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- documented flexible-array start of this ACE SID.
	return aceSID.Equals(sid)
}
