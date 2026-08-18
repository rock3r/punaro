//go:build darwin

package bootstrap

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

func processImagePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errProcessImageUnknown
	}
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EINVAL) {
			return "", errProcessImageGone
		}
		return "", errProcessImageUnknown
	}
	if len(buf) < 5 {
		return "", errProcessImageUnknown
	}
	path := buf[4:]
	end := bytes.IndexByte(path, 0)
	if end <= 0 {
		return "", errProcessImageUnknown
	}
	return string(path[:end]), nil
}
