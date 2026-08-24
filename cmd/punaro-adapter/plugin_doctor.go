package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rock3r/punaro/internal/plugindiagnostic"
)

const maximumPluginManifestBytes = 64 << 10

// adapterExpectedSkillSetDigest is injected by the release builder from the
// exact three skill trees. Development builds intentionally fail parity.
var adapterExpectedSkillSetDigest string

// adapterExpectedPluginRuntimeDigest binds the portable MCP registrations and
// launcher scripts shipped with the same release.
var adapterExpectedPluginRuntimeDigest string

func inspectAdapterPlugin(ctx context.Context, root string) pluginDoctorResult {
	if ctx == nil || ctx.Err() != nil || root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return pluginDoctorResult{}
	}
	info, err := os.Lstat(root) // #nosec G703 -- explicit local plugin root.
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return pluginDoctorResult{}
	}
	portableVersion, portableOK := readPluginIdentity(ctx, filepath.Join(root, "plugin.json"))
	codexVersion, codexOK := readPluginIdentity(ctx, filepath.Join(root, ".codex-plugin", "plugin.json"))
	claudeVersion, claudeOK := readPluginIdentity(ctx, filepath.Join(root, ".claude-plugin", "plugin.json"))
	result := pluginDoctorResult{Portable: portableOK, Codex: codexOK, Claude: claudeOK}
	if portableOK && codexOK && claudeOK && portableVersion == codexVersion && portableVersion == claudeVersion && "v"+portableVersion == adapterBuildRelease {
		result.Version = "v" + portableVersion
	}
	launcher := "punaro-plugin-mcp"
	if runtime.GOOS == "windows" {
		launcher += ".cmd"
	}
	launcherInfo, launcherErr := os.Lstat(filepath.Join(root, "scripts", launcher)) // #nosec G703 -- fixed plugin child.
	runtimeDigest, runtimeErr := plugindiagnostic.RuntimeDigestContext(ctx, root)
	result.Launcher = launcherErr == nil && launcherInfo.Mode().IsRegular() && launcherInfo.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || launcherInfo.Mode().Perm()&0o111 != 0) && runtimeErr == nil && adapterExpectedPluginRuntimeDigest != "" && runtimeDigest == adapterExpectedPluginRuntimeDigest
	digest, digestErr := plugindiagnostic.SkillSetDigestContext(ctx, filepath.Join(root, "skills"))
	if digestErr == nil && adapterExpectedSkillSetDigest != "" && digest == adapterExpectedSkillSetDigest {
		result.SkillDigest = "sha256:" + digest
	}
	return result
}

func readPluginIdentity(ctx context.Context, path string) (string, bool) {
	body, err := readPluginFile(ctx, path, maximumPluginManifestBytes)
	if err != nil {
		return "", false
	}
	fields, err := decodeUniqueTopLevel(body)
	if err != nil {
		return "", false
	}
	var name, version string
	if json.Unmarshal(fields["name"], &name) != nil || json.Unmarshal(fields["version"], &version) != nil || name != "punaro" || version == "" || strings.ContainsAny(version, "\r\n\x00") {
		return "", false
	}
	return version, true
}

func decodeUniqueTopLevel(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid plugin manifest")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid plugin manifest")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("invalid plugin manifest")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errors.New("invalid plugin manifest")
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid plugin manifest")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid plugin manifest")
	}
	return fields, nil
}

func readPluginFile(ctx context.Context, path string, maximum int) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("plugin file unavailable")
	}
	info, err := os.Lstat(path) // #nosec G703 -- fixed plugin child.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > int64(maximum) {
		return nil, errors.New("plugin file unavailable")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated fixed plugin file.
	if err != nil {
		return nil, errors.New("plugin file unavailable")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(pluginDoctorContextReader{ctx: ctx, reader: file}, int64(maximum)+1))
	if err != nil || len(body) == 0 || len(body) > maximum {
		return nil, errors.New("plugin file unavailable")
	}
	return body, nil
}

type pluginDoctorContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader pluginDoctorContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
