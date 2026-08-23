//go:build !windows && !linux && !darwin

package bootstrap

func pidsMatchingImage(string) ([]int, error) {
	return nil, errProcessImageUnknown
}

func processImagePath(int) (string, error) {
	return "", errProcessImageUnknown
}
