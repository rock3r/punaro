//go:build windows

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

// newSenderKeyProtector binds source file-key wrapping to a Windows DPAPI
// CurrentUser-protected blob. The unwrapped key is never an environment value.
func newSenderKeyProtector() (controller.SenderFileKeyProtector, error) {
	path := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_HOST_DPAPI_FILE"))
	if path == "" {
		return nil, errors.New("PUNARO_ATTACHMENT_HOST_DPAPI_FILE is required")
	}
	return controller.NewHostAEADFileKeyProtector(controller.DPAPIHostKeyProvider{File: path})
}
