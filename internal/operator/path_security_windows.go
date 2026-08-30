//go:build windows

package operator

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFullControl = windows.ACCESS_MASK(0x1f01ff)

func requireTrustedPrivateDirectory(path string) error {
	return requirePrivateDirectory(path)
}

func requireTrustedDirectoryAncestors(string) error { return nil }

func requireTrustedProtectedFile(path string, maximum int64) error {
	return requireProtectedFile(path, maximum)
}

func requireTrustedExternalFile(path string, maximum int64) error {
	file, err := openTrustedExternalFile(path, maximum)
	if err != nil {
		return err
	}
	return file.Close()
}

// openTrustedExternalFile binds type, link-count, owner, and DACL validation
// to the same non-reparse handle whose bytes the caller reads. A junction
// retarget therefore cannot make validation describe a different object.
func openTrustedExternalFile(path string, maximum int64) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil || maximum < 0 {
		return nil, errors.New("external file is unsafe")
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	) // #nosec G304 -- explicit release input is opened without following the final reparse point.
	if err != nil {
		return nil, errors.New("external file is unsafe")
	}
	if !trustedWindowsFileHandle(handle, maximum, true) || !trustedWindowsACLHandle(handle, 0) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("external file is unsafe")
	}
	return os.NewFile(uintptr(handle), path), nil // #nosec G115 -- successful Win32 handles are nonnegative.
}

func protectNewOperatorDirectory(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("operator directory cannot be protected")
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.New("operator directory cannot be protected")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("operator directory cannot be protected")
	}
	_, acl, err := currentUserWindowsACL(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil || windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil) != nil || !trustedWindowsACLHandle(handle, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) {
		return errors.New("operator directory cannot be protected")
	}
	return nil
}

func protectNewOperatorFile(file *os.File) error {
	_, acl, err := currentUserWindowsACL(0)
	if err != nil {
		return errors.New("operator file cannot be protected")
	}
	handle := windows.Handle(file.Fd())
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil || !trustedWindowsACLHandle(handle, 0) {
		return errors.New("operator file cannot be protected")
	}
	return nil
}

func requireTrustedCatalogDirectory(path string) error {
	unpin, err := pinTrustedCatalogDirectory(path)
	if err != nil {
		return err
	}
	unpin()
	return nil
}

// pinTrustedCatalogDirectory retains non-delete-shared handles for the
// catalog directory and its complete ancestor chain. The target's protected
// ACL prevents leaf replacement, while each ancestor must deny unprivileged
// child deletion and security-descriptor takeover. Rechecking the target file
// identity after the chain is pinned detects a concurrent path swap.
func pinTrustedCatalogDirectory(path string) (func(), error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || requirePrivateDirectory(path) != nil {
		return nil, errors.New("catalog directory is unsafe")
	}
	var handles []windows.Handle
	closeHandles := func() {
		for index := len(handles) - 1; index >= 0; index-- {
			_ = windows.CloseHandle(handles[index])
		}
	}
	current := path
	for {
		handle, err := openPinnedWindowsDirectory(current)
		if err != nil {
			closeHandles()
			return nil, errors.New("catalog directory is unsafe")
		}
		handles = append(handles, handle)
		if len(handles) == 1 {
			if !trustedWindowsACLHandle(handle, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) {
				closeHandles()
				return nil, errors.New("catalog directory is unsafe")
			}
		} else if !trustedWindowsCatalogAncestorHandle(handle) {
			closeHandles()
			return nil, errors.New("catalog directory ancestors are unsafe")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	verification, err := openPinnedWindowsDirectory(path)
	if err != nil || !sameWindowsFile(handles[0], verification) {
		if err == nil {
			_ = windows.CloseHandle(verification)
		}
		closeHandles()
		return nil, errors.New("catalog directory changed during validation")
	}
	_ = windows.CloseHandle(verification)
	return closeHandles, nil
}

func openPinnedWindowsDirectory(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, err
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return 0, errors.New("catalog path component is unsafe")
	}
	return handle, nil
}

func sameWindowsFile(first, second windows.Handle) bool {
	var firstDetails, secondDetails windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(first, &firstDetails) == nil &&
		windows.GetFileInformationByHandle(second, &secondDetails) == nil &&
		firstDetails.VolumeSerialNumber == secondDetails.VolumeSerialNumber &&
		firstDetails.FileIndexHigh == secondDetails.FileIndexHigh &&
		firstDetails.FileIndexLow == secondDetails.FileIndexLow
}

func trustedWindowsCatalogAncestorHandle(handle windows.Handle) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return false
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.Equals(system) || sid.Equals(administrators) || sid.Equals(trustedInstaller))
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	dangerous := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL)
	dangerous |= fileDeleteChild
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&dangerous == 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			// Deny and audit ACEs do not grant replacement authority. Unknown
			// allow-object layouts are rejected conservatively below.
			if ace.Header.AceType == 1 || ace.Header.AceType == 2 || ace.Header.AceType == 3 || ace.Header.AceType == 6 || ace.Header.AceType == 7 || ace.Header.AceType == 8 {
				continue
			}
			return false
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SidStart is the documented flexible-array start of this ACE's SID.
		if !trusted(aceSID) {
			return false
		}
	}
	return true
}

// ensureTrustedCatalogDirectory performs the one supported legacy migration:
// an existing published installation with no catalog state and a DACL limited
// to the current user, LocalSystem, and built-in administrators. Validation
// and replacement are bound to one non-reparse directory handle.
func ensureTrustedCatalogDirectory(path string) error {
	if requireTrustedCatalogDirectory(path) == nil {
		return nil
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("catalog directory is unsafe")
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.New("catalog directory is unsafe")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !trustedLegacyWindowsACLHandle(handle) {
		return errors.New("catalog directory is unsafe")
	}
	for _, child := range []string{acceptedCatalogName, acceptedCatalogPendingName, acceptedCatalogRequiredName} {
		if _, err := os.Lstat(filepath.Join(path, child)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("catalog directory migration is unavailable")
		}
	}
	if requireTrustedLegacyWindowsInstallationFile(filepath.Join(path, configName)) != nil {
		return errors.New("catalog directory migration is unavailable")
	}
	if _, err := Load(path); err != nil {
		return errors.New("catalog directory migration is unavailable")
	}
	_, acl, err := currentUserWindowsACL(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil || windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil) != nil || !trustedWindowsACLHandle(handle, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) {
		return errors.New("catalog directory migration is unavailable")
	}
	return requireTrustedCatalogDirectory(path)
}

func requireTrustedCatalogFile(path string, maximum int64) error {
	if err := requireProtectedFile(path, maximum); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("catalog file is unsafe")
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.New("catalog file is unsafe")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if !trustedWindowsFileHandle(handle, maximum, false) || !trustedWindowsACLHandle(handle, 0) {
		return errors.New("catalog file is unsafe")
	}
	return nil
}

func trustedWindowsFileHandle(handle windows.Handle, maximum int64, requireSingleLink bool) bool {
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || requireSingleLink && details.NumberOfLinks != 1 {
		return false
	}
	size := uint64(details.FileSizeHigh)<<32 | uint64(details.FileSizeLow)
	return maximum >= 0 && size <= uint64(maximum)
}

func trustedWindowsACLHandle(handle windows.Handle, expectedFlags uint8) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
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
	if windows.GetAce(dacl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != expectedFlags || ace.Mask != windowsFullControl {
		return false
	}
	// #nosec G103 -- SidStart is the documented flexible-array start of this ACE's SID.
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	return aceSID.Equals(user.User.Sid)
}

func requireTrustedLegacyWindowsInstallationFile(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("legacy installation file is unsafe")
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return errors.New("legacy installation file is unsafe")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if !trustedWindowsFileHandle(handle, 64<<10, false) || !trustedLegacyWindowsACLHandle(handle) {
		return errors.New("legacy installation file is unsafe")
	}
	return nil
}

func trustedLegacyWindowsACLHandle(handle windows.Handle) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return false
	}
	currentUserFullControl := false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SidStart is the documented flexible-array start of this ACE's SID.
		if aceSID.Equals(user.User.Sid) {
			currentUserFullControl = currentUserFullControl || ace.Mask&windowsFullControl == windowsFullControl
			continue
		}
		if !aceSID.Equals(system) && !aceSID.Equals(administrators) {
			return false
		}
	}
	return currentUserFullControl
}

func currentUserWindowsACL(inheritance uint32) (*windows.SID, *windows.ACL, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return nil, nil, errors.New("current user is unavailable")
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windowsFullControl,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid)},
	}}, nil)
	if err != nil {
		return nil, nil, err
	}
	return user.User.Sid, acl, nil
}

func runtimeIdentityMatches(Installation) bool { return true }
