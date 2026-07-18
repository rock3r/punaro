//go:build !darwin && !windows

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

// newSenderKeyProtector reads a source wrapping key only from a private
// systemd credential file. It intentionally does not accept that key through
// a generic environment variable.
func newSenderKeyProtector() (controller.SenderFileKeyProtector, error) {
	directory := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY"))
	name := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME"))
	if directory == "" || name == "" {
		return nil, errors.New("PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY and PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME are required")
	}
	return controller.NewHostAEADFileKeyProtector(controller.SystemdCredentialHostKeyProvider{CredentialDirectory: directory, CredentialName: name})
}
