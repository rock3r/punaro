// Command punaro-memory provides one-shot access to Punaro's native memory API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}
	command := args[0]
	if !validFlags(command, args[1:]) {
		usage(stderr)
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
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
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *origin == "" || !filepath.IsAbs(*credentialFile) {
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
		body, err = readInput(*input, 1<<20)
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

func validFlags(command string, args []string) bool {
	allowed := map[string]bool{"origin": true, "credential-file": true}
	for _, name := range commandFlags(command) {
		allowed[name] = true
	}
	seen := make(map[string]bool, len(args)/2)
	for _, argument := range args {
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		name := strings.TrimLeft(argument, "-")
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
		}
		if name == "" || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func commandFlags(command string) []string {
	switch command {
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
	_, _ = fmt.Fprintln(stderr, "usage: punaro-memory <resolve|get|search|brief|changes|create|update|archive|restore|purge|propose|proposal-get|proposal-approve|proposal-reject> [flags]")
}
