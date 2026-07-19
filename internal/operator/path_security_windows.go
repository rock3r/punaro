//go:build windows

package operator

func requireTrustedPrivateDirectory(path string) error {
	return requirePrivateDirectory(path)
}

func requireTrustedDirectoryAncestors(string) error { return nil }

func requireTrustedProtectedFile(path string, maximum int64) error {
	return requireProtectedFile(path, maximum)
}

func runtimeIdentityMatches(Installation) bool { return true }
