//go:build !windows

package operator

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

// UpdateAvailableBytes returns filesystem capacity available to the operator.
func UpdateAvailableBytes(path string) (uint64, error) {
	var statistics unix.Statfs_t
	if err := unix.Statfs(path, &statistics); err != nil {
		return 0, errors.New("update disk capacity is unavailable")
	}
	if statistics.Bsize <= 0 {
		return 0, errors.New("update disk capacity is invalid")
	}
	blockSize := uint64(statistics.Bsize) // #nosec G115 -- positivity is checked immediately above.
	if statistics.Bavail > math.MaxUint64/blockSize {
		return 0, errors.New("update disk capacity is invalid")
	}
	return statistics.Bavail * blockSize, nil
}
