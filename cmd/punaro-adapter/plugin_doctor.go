package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
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

func inspectAdapterPluginIsolated(ctx context.Context, root string) pluginDoctorResult {
	if ctx == nil || ctx.Err() != nil {
		return pluginDoctorResult{}
	}
	executable, err := os.Executable()
	if err != nil {
		return pluginDoctorResult{}
	}
	command := exec.CommandContext(ctx, executable, "doctor-plugin-inspect", "--root", root) // #nosec G204,G702 -- os.Executable self helper with explicit data argument.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: maximumPluginManifestBytes}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return pluginDoctorResult{}
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	var result pluginDoctorResult
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return pluginDoctorResult{}
	}
	return result
}

func runAdapterPluginInspect(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro-adapter doctor-plugin-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "installed plugin root")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	if json.NewEncoder(stdout).Encode(inspectAdapterPlugin(context.Background(), *root)) != nil {
		return 1
	}
	return 0
}

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
	launcherOK := inspectPluginLauncher(filepath.Join(root, "scripts", launcher))
	runtimeDigest, runtimeErr := plugindiagnostic.RuntimeDigestContext(ctx, root)
	result.Launcher = launcherOK && runtimeErr == nil && adapterExpectedPluginRuntimeDigest != "" && runtimeDigest == adapterExpectedPluginRuntimeDigest
	digest, digestErr := plugindiagnostic.SkillSetDigestContext(ctx, filepath.Join(root, "skills"))
	if digestErr == nil && adapterExpectedSkillSetDigest != "" && digest == adapterExpectedSkillSetDigest {
		result.SkillDigest = "sha256:" + digest
	}
	return result
}

func inspectPluginLauncher(path string) bool {
	expected, err := os.Lstat(path) // #nosec G703 -- fixed plugin child.
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && expected.Mode().Perm()&0o111 == 0 {
		return false
	}
	file, err := os.Open(path) // #nosec G304,G703 -- child-isolated validated plugin launcher.
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	return err == nil && opened.Mode().IsRegular() && os.SameFile(expected, opened) && opened.Size() == expected.Size() && (runtime.GOOS == "windows" || opened.Mode().Perm()&0o111 != 0)
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
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() || opened.Size() < 1 || opened.Size() > int64(maximum) {
		return nil, errors.New("plugin file unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(pluginDoctorContextReader{ctx: ctx, reader: file}, int64(maximum)+1))
	if err != nil || len(body) == 0 || int64(len(body)) != opened.Size() || len(body) > maximum {
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
