//go:build !windows

package operator

import (
	"os"
	"testing"
)

func TestTrustedAncestorOwnershipPolicy(t *testing.T) {
	if !trustedAncestorUID(0) || !trustedAncestorUID(os.Getuid()) {
		t.Fatal("root or current user was rejected")
	}
	foreign := os.Getuid() + 1
	if foreign == 0 {
		foreign++
	}
	if trustedAncestorUID(foreign) {
		t.Fatal("foreign-owned ancestor was accepted")
	}
}
