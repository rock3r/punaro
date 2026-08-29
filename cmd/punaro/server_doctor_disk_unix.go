//go:build !windows

package main

import "syscall"

func inspectServerStorage(path string, minimum uint64) knownDoctorBool {
	var state syscall.Statfs_t
	if syscall.Statfs(path, &state) != nil {
		return knownDoctorBool{}
	}
	if state.Bsize <= 0 {
		return knownDoctorBool{}
	}
	blockSize := uint64(state.Bsize) // #nosec G115 -- positive value checked above.
	if state.Bavail > ^uint64(0)/blockSize {
		return knownDoctorBool{}
	}
	available := state.Bavail * blockSize
	return known(true, available >= minimum)
}
