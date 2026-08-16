package release

import (
	"errors"
	"strings"
)

var (
	knownComponents = []string{
		"punaro-trusted-attachment",
		"punaro-bootstrap",
		"punaro-telegram",
		"punaro-adapter",
		"punaro-memory",
		"punaro-enroll",
		"punaro",
	}
	knownOperatingSystems = map[string]struct{}{"darwin": {}, "linux": {}, "windows": {}}
	knownArchitectures    = map[string]struct{}{"amd64": {}, "arm64": {}}
)

func knownComponent(name string) bool {
	for _, component := range knownComponents {
		if component == name {
			return true
		}
	}
	return false
}

func knownOS(name string) bool {
	_, ok := knownOperatingSystems[name]
	return ok
}

func knownArch(name string) bool {
	_, ok := knownArchitectures[name]
	return ok
}

func parseArtifactFilename(name string) (component, osName, arch string, err error) {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return "", "", "", errors.New("invalid artifact filename")
	}
	exe := strings.HasSuffix(name, ".exe")
	base := strings.TrimSuffix(name, ".exe")
	for _, candidate := range knownComponents {
		prefix := candidate + "-"
		if !strings.HasPrefix(base, prefix) {
			continue
		}
		rest := strings.TrimPrefix(base, prefix)
		osName, arch, ok := strings.Cut(rest, "-")
		if !ok || !knownOS(osName) || !knownArch(arch) || strings.Contains(arch, "-") {
			continue
		}
		if osName == "windows" != exe {
			return "", "", "", errors.New("invalid artifact filename")
		}
		return candidate, osName, arch, nil
	}
	return "", "", "", errors.New("invalid artifact filename")
}
