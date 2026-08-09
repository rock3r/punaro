//go:build windows

package memoryclient

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func TestWindowsLoadCredentialRequiresExclusiveDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.credential")
	credential := uuid.NewString() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(path, []byte(credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setMemoryCredentialACL(t, path, "")
	loaded, err := LoadCredential(path)
	if err != nil || loaded != credential {
		t.Fatalf("credential=%q err=%v", loaded, err)
	}
	setMemoryCredentialACL(t, path, "(A;;FR;;;WD)")
	if _, err := LoadCredential(path); err == nil {
		t.Fatal("shared credential ACL was accepted")
	}
}

func setMemoryCredentialACL(t *testing.T, path, additionalACE string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")" + additionalACE)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
