//go:build windows

package bootstrap

import (
	"errors"

	"golang.org/x/sys/windows"
)

func pidsMatchingImage(string) ([]int, error) {
	return nil, errProcessImageUnknown
}

func processImagePath(pid int) (string, error) {
	if pid <= 0 || pid > int(^uint32(0)) {
		return "", errProcessImageUnknown
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) // #nosec G115 -- pid is bounded above.
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return "", errProcessImageGone
		}
		return "", errProcessImageUnknown
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	const imageNameMaxChars = 4096
	buf := make([]uint16, imageNameMaxChars)
	n := uint32(imageNameMaxChars)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &n); err != nil || n == 0 {
		return "", errProcessImageUnknown
	}
	return windows.UTF16ToString(buf[:n]), nil
}
