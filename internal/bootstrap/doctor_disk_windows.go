//go:build windows

package bootstrap

import "golang.org/x/sys/windows"

func doctorFreeBytes(path string) (uint64, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var available uint64
	err = windows.GetDiskFreeSpaceEx(pointer, &available, nil, nil)
	return available, err
}
