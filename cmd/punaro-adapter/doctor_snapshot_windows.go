//go:build windows

package main

import (
	"errors"
	"net/url"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func protectMailboxDoctorSnapshot(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return errors.New("current user is unavailable")
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(0x1f01ff),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		acl,
		nil,
	)
}

func mailboxDoctorReadOnlyURI(path string) string {
	normalized := filepath.ToSlash(path)
	volume := filepath.VolumeName(path)
	if len(volume) == 2 && volume[1] == ':' {
		normalized = "/" + normalized
	}
	return (&url.URL{Scheme: "file", Path: normalized, RawQuery: "mode=ro"}).String()
}
