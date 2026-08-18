//go:build darwin

package bootstrap

import (
	"bytes"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func pidsMatchingImage(path string) ([]int, error) {
	if path == "" {
		return nil, errProcessImageUnknown
	}
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, errProcessImageUnknown
	}
	var pids []int
	self := os.Getpid()
	for _, proc := range procs {
		pid := int(proc.Proc.P_pid)
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
