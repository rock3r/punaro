//go:build darwin && !cgo

package main

// Without the macOS ACL APIs, the adapter cannot prove a private file lacks
// an extended grant. Reject it rather than accepting a possibly shared secret.
func hasExtendedACL(int) bool {
	return true
}
