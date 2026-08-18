//go:build linux

package bootstrap

import (
	"os"
	"strconv"
)

func processImagePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errProcessImageUnknown
	}
	path, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe") // #nosec G304 -- live process image for the recorded pid.
	if err != nil {
		if os.IsNotExist(err) {
			return "", errProcessImageGone
		}
		return "", errProcessImageUnknown
	}
	if path == "" {
		return "", errProcessImageUnknown
	}
	return path, nil
}
