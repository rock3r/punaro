//go:build linux

package bootstrap

import (
	"os"
	"strconv"
)

func pidsMatchingImage(path string) ([]int, error) {
	if path == "" {
		return nil, errProcessImageUnknown
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, errProcessImageUnknown
	}
	var pids []int
	self := os.Getpid()
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == self {
			continue
		}
		if matchProcessImage(pid, path) == processImageMatch {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

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
