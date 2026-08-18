//go:build !windows && !linux && !darwin

package bootstrap

func processImagePath(int) (string, error) {
	return "", errProcessImageUnknown
}
