//go:build !windows

package bootstrap

import "golang.org/x/sys/unix"

func doctorFreeBytes(path string) (uint64, error) {
	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return 0, err
	}
	if stats.Bsize <= 0 {
		return 0, unix.EOVERFLOW
	}
	blockSize := uint64(stats.Bsize) // #nosec G115 -- positive value checked above.
	if stats.Bavail > ^uint64(0)/blockSize {
		return 0, unix.EOVERFLOW
	}
	return stats.Bavail * blockSize, nil
}
