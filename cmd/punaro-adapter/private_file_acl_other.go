//go:build !windows && !darwin

package main

func hasExtendedACL(int) bool {
	return false
}
