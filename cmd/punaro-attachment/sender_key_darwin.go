//go:build darwin

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

// newSenderKeyProtector binds source file-key wrapping to the logged-in
// machine's Keychain. The key material itself is never an environment value.
func newSenderKeyProtector() (controller.SenderFileKeyProtector, error) {
	service := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_HOST_KEY_SERVICE"))
	account := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT"))
	if service == "" || account == "" {
		return nil, errors.New("PUNARO_ATTACHMENT_HOST_KEY_SERVICE and PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT are required")
	}
	return controller.NewHostAEADFileKeyProtector(controller.MacOSKeychainHostKeyProvider{Service: service, Account: account})
}
