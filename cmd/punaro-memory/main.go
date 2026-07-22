// Command punaro-memory provides one-shot access to Punaro's native memory API.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/memoryclient"
)

type client interface {
	Resolve(context.Context, string, string) (memoryclient.Result, error)
	Get(context.Context, string, string) (memoryclient.Result, error)
	Search(context.Context, string, string, int) (memoryclient.Result, error)
	Brief(context.Context, string, string) (memoryclient.Result, error)
	Changes(context.Context, string, json.RawMessage, int) (memoryclient.Result, error)
	Create(context.Context, string, string, json.RawMessage) (memoryclient.Result, error)
	Update(context.Context, string, string, string, string, json.RawMessage) (memoryclient.Result, error)
	SetArchived(context.Context, string, string, string, string, bool) (memoryclient.Result, error)
	Delete(context.Context, string, string, string, string) (memoryclient.Result, error)
	CreateProposal(context.Context, string, string, json.RawMessage) (memoryclient.Result, error)
	GetProposal(context.Context, string, string) (memoryclient.Result, error)
	DecideProposal(context.Context, string, string, string, string, bool) (memoryclient.Result, error)
}

var newMemoryClient = func(origin, credential string) (client, error) { return memoryclient.New(origin, credential) }
var loadCredential = memoryclient.LoadCredential

const (
	profileVersion = 1
	maxProfileSize = int64(4096)
)

type profile struct {
	Version        int    `json:"version"`
	Origin         string `json:"origin"`
	CredentialFile string `json:"credential_file"`
	Project        string `json:"project,omitempty"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "", "absolute protected non-secret profile file")
	origin := flags.String("origin", "", "fixed Punaro HTTPS origin")
	credentialFile := flags.String("credential-file", "", "absolute protected device credential file")
	project := flags.String("project", "", "opaque project UUID")
	item := flags.String("item", "", "opaque memory item UUID")
	proposal := flags.String("proposal", "", "opaque proposal UUID")
	key := flags.String("idempotency-key", "", "stable mutation UUID")
	etag := flags.String("etag", "", "exact strong ETag")
	input := flags.String("input", "", "absolute bounded JSON input file")
	query := flags.String("query", "", "bounded search query")
	limit := flags.Int("limit", 0, "bounded result limit")
	kind := flags.String("kind", "", "project identity kind")
	locator := flags.String("locator", "", "project identity locator")
	cursorFile := flags.String("cursor-file", "", "optional absolute JSON cursor file")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !validFlags(command, args[1:], flags) {
		return 2
	}
	explicit := make(map[string]bool)
	flags.Visit(func(parsed *flag.Flag) { explicit[parsed.Name] = true })
	if command == "profile-write" {
		candidate := profile{Origin: *origin, CredentialFile: *credentialFile, Project: *project}
		if !safeProfilePath(*profilePath) || !validProfile(candidate) || sameCleanPath(*profilePath, candidate.CredentialFile) {
			return 2
		}
		if err := saveProfile(*profilePath, candidate); err != nil {
			_, _ = fmt.Fprintln(stderr, "punaro-memory: profile failed")
			return 1
		}
		return 0
	}
	if *profilePath != "" {
		loaded, err := loadProfile(*profilePath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "punaro-memory: profile failed")
			return 1
		}
		if !explicit["origin"] {
			*origin = loaded.Origin
		}
		if !explicit["credential-file"] {
			*credentialFile = loaded.CredentialFile
		}
		if !explicit["project"] {
			*project = loaded.Project
		}
	}
	if *origin == "" || !filepath.IsAbs(*credentialFile) {
		return 2
	}
	if !validCommand(command, *project, *item, *proposal, *key, *etag, *input, *query, *kind, *locator, *cursorFile, *limit) {
		return 2
	}
	credential, err := loadCredential(*credentialFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-memory: protected credential is unavailable")
		return 1
	}
	remote, err := newMemoryClient(*origin, credential)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-memory: client configuration is invalid")
		return 1
	}
	ctx := context.Background()
	var result memoryclient.Result
	switch command {
	case "resolve":
		result, err = remote.Resolve(ctx, *kind, *locator)
	case "get":
		result, err = remote.Get(ctx, *project, *item)
	case "search":
		result, err = remote.Search(ctx, *project, *query, *limit)
	case "brief":
		result, err = remote.Brief(ctx, *project, *query)
	case "changes":
		var cursor json.RawMessage
		if *cursorFile != "" {
			cursor, err = readInput(*cursorFile, 4096)
			if err != nil {
				break
			}
		}
		result, err = remote.Changes(ctx, *project, cursor, *limit)
	case "create", "propose":
		var body json.RawMessage
		limit := int64(1 << 20)
		if command == "create" {
			limit = 264 << 10
		}
		body, err = readInput(*input, limit)
		if err != nil {
			break
		}
		if command == "create" {
			result, err = remote.Create(ctx, *project, *key, body)
		} else {
			result, err = remote.CreateProposal(ctx, *project, *key, body)
		}
	case "update":
		var body json.RawMessage
		body, err = readInput(*input, 264<<10)
		if err == nil {
			result, err = remote.Update(ctx, *project, *item, *key, *etag, body)
		}
	case "archive", "restore":
		result, err = remote.SetArchived(ctx, *project, *item, *key, *etag, command == "archive")
	case "purge":
		result, err = remote.Delete(ctx, *project, *item, *key, *etag)
	case "proposal-get":
		result, err = remote.GetProposal(ctx, *project, *proposal)
	case "proposal-approve", "proposal-reject":
		result, err = remote.DecideProposal(ctx, *project, *proposal, *key, *etag, command == "proposal-approve")
	default:
		usage(stderr)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-memory: request failed")
		return 1
	}
	if len(result.JSON) == 0 || !json.Valid(result.JSON) {
		_, _ = fmt.Fprintln(stderr, "punaro-memory: response failed validation")
		return 1
	}
	if _, err := stdout.Write(append(append([]byte(nil), result.JSON...), '\n')); err != nil {
		return 1
	}
	return 0
}

func validFlags(command string, args []string, flags *flag.FlagSet) bool {
	allowed := map[string]bool{"profile": true, "origin": true, "credential-file": true}
	for _, name := range commandFlags(command) {
		allowed[name] = true
	}
	seen := make(map[string]bool)
	valid := true
	flags.Visit(func(parsed *flag.Flag) {
		name := parsed.Name
		if !allowed[name] || seen[name] {
			valid = false
			return
		}
		seen[name] = true
	})
	if !valid {
		return false
	}
	duplicates := make(map[string]bool, len(seen))
	for i := 0; i < len(args); i++ {
		name, hasValue := flagName(args[i])
		if name == "" {
			continue
		}
		if duplicates[name] {
			return false
		}
		duplicates[name] = true
		if !hasValue {
			i++
		}
	}
	return true
}

func flagName(argument string) (string, bool) {
	if !strings.HasPrefix(argument, "-") || argument == "-" || argument == "--" {
		return "", false
	}
	name := strings.TrimLeft(argument, "-")
	hasValue := false
	if index := strings.IndexByte(name, '='); index >= 0 {
		name, hasValue = name[:index], true
	}
	return name, hasValue
}

func commandFlags(command string) []string {
	switch command {
	case "profile-write":
		return []string{"profile", "origin", "credential-file", "project"}
	case "resolve":
		return []string{"kind", "locator"}
	case "get":
		return []string{"project", "item"}
	case "search":
		return []string{"project", "query", "limit"}
	case "brief":
		return []string{"project", "query"}
	case "changes":
		return []string{"project", "cursor-file", "limit"}
	case "create", "propose":
		return []string{"project", "idempotency-key", "input"}
	case "update":
		return []string{"project", "item", "idempotency-key", "etag", "input"}
	case "archive", "restore", "purge":
		return []string{"project", "item", "idempotency-key", "etag"}
	case "proposal-get":
		return []string{"project", "proposal"}
	case "proposal-approve", "proposal-reject":
		return []string{"project", "proposal", "idempotency-key", "etag"}
	default:
		return nil
	}
}

func saveProfile(path string, value profile) error {
	if !safeProfilePath(path) || !privateProfilePath(path) || !validProfile(value) || sameCleanPath(path, value.CredentialFile) {
		return errors.New("profile is invalid")
	}
	if !noSymlinkPath(filepath.Dir(path)) || !noSymlinkPath(filepath.Dir(value.CredentialFile)) {
		return errors.New("profile path is unsafe")
	}
	value.Version = profileVersion
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > maxProfileSize {
		return errors.New("profile is too large")
	}
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-") // #nosec G304 -- directory is explicit, absolute, and checked for symlink components.
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath) // #nosec G703 -- tempPath comes from os.CreateTemp in the already validated profile directory.
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if !noSymlinkPath(directory) {
		return errors.New("profile directory changed while writing")
	}
	if err := os.Rename(tempPath, path); err != nil { // #nosec G703 -- source and target are validated absolute profile paths in the same checked directory.
		return err
	}
	removeTemp = false
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func loadProfile(path string) (profile, error) {
	var value profile
	if !safeProfilePath(path) || !privateProfilePath(path) || !noSymlinkPath(path) {
		return value, errors.New("profile path is unsafe")
	}
	before, err := os.Lstat(path) // #nosec G703 -- explicit absolute CLI profile path checked component-by-component.
	if err != nil || !before.Mode().IsRegular() || !privateProfileFile(before) {
		return value, errors.New("profile is unavailable")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- explicit absolute CLI profile path checked before and after opening.
	if err != nil {
		return value, errors.New("profile is unavailable")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !privateProfileFile(after) || !os.SameFile(before, after) || !noSymlinkPath(path) {
		return value, errors.New("profile changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxProfileSize+1))
	if err != nil || int64(len(raw)) > maxProfileSize || len(strings.TrimSpace(string(raw))) == 0 {
		return value, errors.New("profile is invalid")
	}
	if err := rejectDuplicateTopLevelJSONFields(raw); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return value, errors.New("profile has trailing data")
	}
	if value.Version != profileVersion || !validProfile(value) {
		return value, errors.New("profile is invalid")
	}
	return value, nil
}

func safeProfilePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func sameCleanPath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func validProfile(value profile) bool {
	return validProfileOrigin(value.Origin) &&
		filepath.IsAbs(value.CredentialFile) &&
		filepath.Clean(value.CredentialFile) == value.CredentialFile &&
		(value.Project == "" || validProfileUUID(value.Project))
}

func validProfileOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		(parsed.Path == "" || parsed.Path == "/") &&
		parsed.Opaque == ""
}

func validProfileUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func rejectDuplicateTopLevelJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("profile must be a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("profile key is invalid")
		}
		if seen[key] {
			return errors.New("profile has duplicate fields")
		}
		seen[key] = true
		var discard json.RawMessage
		if err := decoder.Decode(&discard); err != nil {
			return err
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return errors.New("profile object is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("profile has trailing data")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304,G703 -- directory path is explicit and checked before use.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func validCommand(command, project, item, proposal, key, etag, input, query, kind, locator, cursorFile string, limit int) bool {
	switch command {
	case "resolve":
		return kind != "" && locator != ""
	case "get":
		return project != "" && item != ""
	case "search":
		return project != "" && query != "" && limit != 0
	case "brief":
		return project != "" && query != ""
	case "changes":
		return project != "" && limit != 0 && (cursorFile == "" || filepath.IsAbs(cursorFile))
	case "create", "propose":
		return project != "" && key != "" && filepath.IsAbs(input)
	case "update":
		return project != "" && item != "" && key != "" && etag != "" && filepath.IsAbs(input)
	case "archive", "restore", "purge":
		return project != "" && item != "" && key != "" && etag != ""
	case "proposal-get":
		return project != "" && proposal != ""
	case "proposal-approve", "proposal-reject":
		return project != "" && proposal != "" && key != "" && etag != ""
	default:
		return false
	}
}

func readInput(path string, limit int64) (json.RawMessage, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !noSymlinkPath(path) {
		return nil, errors.New("input path is unsafe")
	}
	before, err := os.Lstat(path) // #nosec G703 -- explicit absolute CLI input path checked component-by-component.
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("input is unavailable")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- explicit absolute CLI input path checked before and after opening.
	if err != nil {
		return nil, errors.New("input is unavailable")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || !noSymlinkPath(path) {
		return nil, errors.New("input changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit || len(strings.TrimSpace(string(raw))) == 0 {
		return nil, errors.New("input is invalid")
	}
	return json.RawMessage(raw), nil
}

func noSymlinkPath(path string) bool {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current) // #nosec G703 -- deliberate component walk of the explicit absolute input path.
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if current == filepath.Dir(current) {
			return true
		}
	}
}

func usage(stderr io.Writer) {
	_, _ = fmt.Fprintln(stderr, "usage: punaro-memory <profile-write|resolve|get|search|brief|changes|create|update|archive|restore|purge|propose|proposal-get|proposal-approve|proposal-reject> [flags]")
}
