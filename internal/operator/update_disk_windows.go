//go:build windows

package operator

import (
	"errors"

	"golang.org/x/sys/windows"
)

// UpdateAvailableBytes returns filesystem capacity available to the operator.
func UpdateAvailableBytes(path string) (uint64, error) {
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, errors.New("update disk capacity is unavailable")
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, nil, nil); err != nil {
		return 0, errors.New("update disk capacity is unavailable")
	}
	return available, nil
}
