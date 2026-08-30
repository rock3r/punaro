//go:build windows

package operator

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"golang.org/x/sys/windows"
)

func TestWindowsCatalogAcceptanceRequiresExclusiveACLs(t *testing.T) {
	directory := t.TempDir()
	setWindowsOperatorFixtureACL(t, directory, true, "(A;OICI;FW;;;WD)")
	if err := AcceptServerCatalogSequence(directory, 4, 1); err == nil {
		t.Fatal("catalog acceptance trusted a shared installation directory")
	}
	if err := protectNewOperatorDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := AcceptServerCatalogSequence(directory, 4, 1); err != nil {
		t.Fatal(err)
	}
	accepted := filepath.Join(directory, acceptedCatalogName)
	required := filepath.Join(directory, acceptedCatalogRequiredName)
	if requireTrustedCatalogFile(accepted, acceptedCatalogMaximum) != nil || requireTrustedCatalogFile(required, acceptedCatalogMaximum) != nil {
		t.Fatal("catalog acceptance files lack protected current-user-only ACLs")
	}
	setWindowsOperatorFixtureACL(t, accepted, false, "(A;;FR;;;WD)")
	if _, err := ServerCatalogSequence(directory); err == nil {
		t.Fatal("catalog acceptance trusted a shared high-water file")
	}
}

func TestWindowsCatalogAcceptanceMigratesLegacyInstallationACL(t *testing.T) {
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(_ context.Context, _ string, name string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: name}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	setLegacyWindowsOperatorDirectoryACL(t, installation.Directory)
	if requireTrustedCatalogDirectory(installation.Directory) == nil {
		t.Fatal("legacy inherited installation ACL unexpectedly passed strict validation")
	}
	sequence, err := ServerCatalogSequence(installation.Directory)
	if err != nil || sequence != 0 {
		t.Fatalf("legacy snapshot sequence=%d err=%v", sequence, err)
	}
	if err := requireTrustedCatalogDirectory(installation.Directory); err != nil {
		t.Fatalf("legacy installation ACL was not migrated: %v", err)
	}
	if err := AcceptServerCatalogSequence(installation.Directory, 4, 1); err != nil {
		t.Fatalf("first catalog acceptance after migration: %v", err)
	}
}

func TestWindowsCatalogAcceptanceRejectsReplaceableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "operator-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "catalog")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectNewOperatorDirectory(directory); err != nil {
		t.Fatal(err)
	}
	setWindowsOperatorFixtureACL(t, parent, true, "(A;;DC;;;WD)")
	if _, err := pinTrustedCatalogDirectory(directory); err == nil {
		t.Fatal("catalog acceptance trusted an ancestor that grants delete-child authority")
	}
	if err := protectNewOperatorDirectory(parent); err != nil {
		t.Fatal(err)
	}
	unpin, err := pinTrustedCatalogDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	moved := directory + "-moved"
	if err := os.Rename(directory, moved); err == nil {
		unpin()
		t.Fatal("pinned catalog directory allowed concurrent replacement")
	}
	unpin()
	if err := os.Rename(directory, moved); err != nil {
		t.Fatalf("catalog directory remained pinned after release: %v", err)
	}
}

func TestWindowsTrustedExternalFilePinsValidatedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.json")
	file, err := os.Create(path) // #nosec G304 -- test fixture path.
	if err != nil {
		t.Fatal(err)
	}
	if err := protectNewOperatorFile(file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteString("signed release\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	pinned, err := OpenTrustedExternalFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil { // #nosec G304 -- intentional concurrent-open probe of this test fixture.
		_ = writer.Close()
		t.Fatal("validated release handle allowed a concurrent writer")
	}
	body, err := io.ReadAll(pinned)
	if err != nil || string(body) != "signed release\n" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func setWindowsOperatorFixtureACL(t *testing.T, path string, directory bool, additionalACE string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + flags + ";FA;;;" + sid + ")" + additionalACE)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func setLegacyWindowsOperatorDirectoryACL(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
