package fleetconfig

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const maxLocalConfigBytes = 8 << 10

// LocalConfig is machine-local fleet-config choice. It is never fleet source.
type LocalConfig struct {
	Schema               int               `json:"schema"`
	ProjectBasePath      string            `json:"project_base_path"`
	ProjectPathOverrides map[string]string `json:"project_path_overrides"`
	ClaudeAliases        bool              `json:"claude_aliases"`
}

// LoadLocalConfig reads a bounded v1 machine-local config, or returns defaults.
func LoadLocalConfig(path string) (LocalConfig, error) {
	defaults := LocalConfig{Schema: SchemaV1}
	if path == "" {
		return defaults, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaults, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return LocalConfig{}, errors.New("fleet-config local config is unsafe")
	}
	// #nosec G304 -- operator-supplied local adapter path, Lstat-fenced.
	file, err := os.Open(path)
	if err != nil {
		return LocalConfig{}, errors.New("fleet-config local config is unavailable")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxLocalConfigBytes+1))
	if err != nil || len(data) > maxLocalConfigBytes {
		return LocalConfig{}, errors.New("fleet-config local config is invalid")
	}
	var config LocalConfig
	if err := json.Unmarshal(data, &config); err != nil || config.Schema != SchemaV1 {
		return LocalConfig{}, errors.New("fleet-config local config is invalid")
	}
	if config.ProjectBasePath != "" && !filepath.IsAbs(config.ProjectBasePath) {
		return LocalConfig{}, errors.New("fleet-config local config is invalid")
	}
	for name, override := range config.ProjectPathOverrides {
		if name == "" || !filepath.IsAbs(override) {
			return LocalConfig{}, errors.New("fleet-config local config is invalid")
		}
	}
	return config, nil
}
