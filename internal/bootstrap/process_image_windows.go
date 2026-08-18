//go:build windows

package bootstrap

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func pidsMatchingImage(path string) ([]int, error) {
	if path == "" {
		return nil, errProcessImageUnknown
	}
	buf := make([]uint32, 1024)
	for {
		var bytes uint32
		if err := windows.EnumProcesses(buf, &bytes); err != nil {
			return nil, errProcessImageUnknown
		}
		count := int(bytes / 4)
		if count == 0 {
			return nil, errProcessImageUnknown
		}
		if count < len(buf) {
			buf = buf[:count]
			break
		}
		if len(buf) >= 1<<20 {
			return nil, errProcessImageUnknown
		}
		buf = make([]uint32, len(buf)*2)
	}
	var pids []int
	self := os.Getpid()
	for _, raw := range buf {
		pid := int(raw)
		if pid <= 0 || pid == self {
			continue
		}
		if matchProcessImage(pid, path) == processImageMatch {
			pids = append(pids, pid)
		}
	}
	return pids, nil
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
