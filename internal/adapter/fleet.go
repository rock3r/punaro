package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rock3r/punaro/internal/fleetconfig"
	"github.com/rock3r/punaro/internal/relay"
)

// FleetReconcileRequest is one adapter-side fetch/apply/status cycle.
type FleetReconcileRequest struct {
	Client *HTTPRelayClient
	Root   string
	Home   string
	Local  fleetconfig.LocalConfig
}

// FleetReconcileResult is the content-free outcome of one cycle.
type FleetReconcileResult struct {
	State             string
	AppliedDigest     string
	Generation        int64
	TrailerState      string
	AliasState        string
	ProjectMatchState string
}

// ReconcileFleet atomically applies a validated tree under root, preserving trailers.
func ReconcileFleet(root string, tree fleetconfig.Tree, existing map[string][]byte, lastPrefixDigests map[string]string, digest string) (map[string]fleetconfig.TrailerResult, error) {
	files, trailers, err := fleetconfig.PrepareApply(tree, existing, lastPrefixDigests)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return trailers, nil
	}
	if err := fleetconfig.PublishTree(root, files, digest); err != nil {
		return trailers, err
	}
	return trailers, nil
}

// ReconcileFleetOnce fetches desired state, applies a matching archive, and reports.
func ReconcileFleetOnce(ctx context.Context, request FleetReconcileRequest) (FleetReconcileResult, error) {
	if request.Client == nil || request.Root == "" {
		return FleetReconcileResult{}, errors.New("fleet-config reconcile input is invalid")
	}
	desired, err := request.Client.FleetDesired(ctx)
	if err != nil {
		return FleetReconcileResult{}, err
	}
	if desired.Digest == "" || desired.Generation < 1 {
		return FleetReconcileResult{State: "pending"}, nil
	}
	state := loadFleetApplyState(request.Root)
	reportGeneration := state.ReportGeneration + 1
	if reportGeneration < 1 {
		reportGeneration = 1
	}
	if state.Digest == desired.Digest {
		tree := readManagedTree(request.Root)
		result := FleetReconcileResult{
			AppliedDigest: desired.Digest,
			Generation:    desired.Generation,
			AliasState:    aliasState(request.Local.ClaudeAliases, nil),
		}
		matches := fleetconfig.MatchProjects(request.Local.ProjectBasePath, request.Local.ProjectPathOverrides, tree.Projects(), nil)
		result.ProjectMatchState = projectMatchState(matches)
		liveTrailers, projectErr := projectLiveTree(request, tree, state.PrefixDigests)
		result.TrailerState = trailerState(liveTrailers)
		if projectErr != nil {
			result.State = "failed"
		} else {
			result.State = reconcileState(liveTrailers)
			if request.Local.ClaudeAliases {
				result.AliasState = aliasState(request.Local.ClaudeAliases, applyClaudeAliases(request, tree, matches))
			}
			if result.State == "current" && unsupportedHarness(request.Home) {
				result.State = "unsupported"
			}
		}
		putErr := putFleetStatus(ctx, request, desired, result, reportGeneration)
		if putErr != nil {
			return result, putErr
		}
		if projectErr != nil {
			return result, projectErr
		}
		return result, nil
	}
	archive, err := request.Client.FleetRelease(ctx, desired.Digest)
	if err != nil {
		result := FleetReconcileResult{State: "failed", Generation: desired.Generation}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, err
	}
	tree, err := fleetconfig.ReadArchive(archive)
	if err != nil {
		result := FleetReconcileResult{State: "failed", Generation: desired.Generation}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, err
	}
	release, err := fleetconfig.Materialize(tree, desired.SourceCommit)
	if err != nil || release.Digest != desired.Digest {
		result := FleetReconcileResult{State: "failed", Generation: desired.Generation}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, errors.New("fleet-config release digest mismatch")
	}
	existing := readManagedAgents(request.Root)
	trailers, err := ReconcileFleet(request.Root, tree, existing, state.PrefixDigests, desired.Digest)
	if err != nil {
		result := FleetReconcileResult{State: "failed", Generation: desired.Generation, TrailerState: trailerState(trailers)}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, err
	}
	prefixes := prefixDigests(tree)
	if err := writeFleetApplyState(request.Root, fleetconfig.ApplyState{Digest: desired.Digest, LastGoodDigest: desired.Digest, PrefixDigests: prefixes, ReportGeneration: reportGeneration}); err != nil {
		result := FleetReconcileResult{State: "failed", Generation: desired.Generation, AppliedDigest: desired.Digest, TrailerState: trailerState(trailers)}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, err
	}
	matches := fleetconfig.MatchProjects(request.Local.ProjectBasePath, request.Local.ProjectPathOverrides, tree.Projects(), nil)
	aliases := map[string]fleetconfig.AliasResult{}
	liveTrailers, err := projectLiveTree(request, tree, prefixes)
	trailers = mergeTrailerResults(trailers, liveTrailers)
	if err != nil {
		result := FleetReconcileResult{State: "failed", AppliedDigest: desired.Digest, Generation: desired.Generation, TrailerState: trailerState(trailers), ProjectMatchState: projectMatchState(matches)}
		_ = putFleetStatus(ctx, request, desired, result, reportGeneration)
		return result, err
	}
	if request.Local.ClaudeAliases {
		aliases = applyClaudeAliases(request, tree, matches)
	}
	result := FleetReconcileResult{
		State:             reconcileState(trailers),
		AppliedDigest:     desired.Digest,
		Generation:        desired.Generation,
		TrailerState:      trailerState(trailers),
		AliasState:        aliasState(request.Local.ClaudeAliases, aliases),
		ProjectMatchState: projectMatchState(matches),
	}
	if result.State == "current" && unsupportedHarness(request.Home) {
		result.State = "unsupported"
	}
	if err := putFleetStatus(ctx, request, desired, result, reportGeneration); err != nil {
		return result, err
	}
	return result, nil
}

func putFleetStatus(ctx context.Context, request FleetReconcileRequest, desired relay.FleetDesiredMetadata, result FleetReconcileResult, reportGeneration int64) error {
	putErr := request.Client.PutFleetStatus(ctx, statusReport(desired, result, reportGeneration, "fleet-status-"+strconv.FormatInt(reportGeneration, 10)))
	state := loadFleetApplyState(request.Root)
	state.ReportGeneration = reportGeneration
	_ = writeFleetApplyState(request.Root, state)
	return putErr
}

func mergeTrailerResults(parts ...map[string]fleetconfig.TrailerResult) map[string]fleetconfig.TrailerResult {
	out := map[string]fleetconfig.TrailerResult{}
	for _, part := range parts {
		for path, trailer := range part {
			existing := out[path]
			if trailer.Collision {
				existing.Collision = true
				existing.State = "collision"
			}
			if trailer.Drift {
				existing.Drift = true
			}
			if existing.State == "" {
				existing.State = trailer.State
			}
			out[path] = existing
		}
	}
	return out
}

func statusReport(desired relay.FleetDesiredMetadata, result FleetReconcileResult, reportGeneration int64, key string) relay.FleetStatusReport {
	return relay.FleetStatusReport{
		Generation:        desired.Generation,
		AppliedDigest:     result.AppliedDigest,
		State:             result.State,
		Activation:        "next_turn",
		TrailerState:      result.TrailerState,
		AliasState:        result.AliasState,
		ProjectMatchState: result.ProjectMatchState,
		ReportGeneration:  reportGeneration,
		IdempotencyKey:    key,
	}
}

func loadFleetApplyState(root string) fleetconfig.ApplyState {
	// #nosec G304 -- adapter-owned fleet state under the configured data directory.
	body, err := os.ReadFile(filepath.Join(root, "applied.json"))
	if err != nil {
		return fleetconfig.ApplyState{}
	}
	var state fleetconfig.ApplyState
	if json.Unmarshal(body, &state) != nil {
		return fleetconfig.ApplyState{}
	}
	return state
}

func writeFleetApplyState(root string, state fleetconfig.ApplyState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "applied.json"), append(body, '\n'), 0o600)
}

func readManagedTree(root string) fleetconfig.Tree {
	current := filepath.Join(root, "current")
	var files []fleetconfig.File
	_ = filepath.WalkDir(current, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(current, path)
		if relErr != nil {
			return relErr
		}
		// #nosec G304,G122 -- adapter-owned managed tree under the configured data directory.
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		slash := filepath.ToSlash(rel)
		if slash == "AGENTS.md" || strings.HasSuffix(slash, "/AGENTS.md") {
			if prefix, _, ok := fleetconfig.SplitAgents(body); ok {
				body = prefix
			}
		}
		files = append(files, fleetconfig.File{Path: slash, Data: body})
		return nil
	})
	return fleetconfig.Tree{Files: files}
}

func readManagedAgents(root string) map[string][]byte {
	existing := map[string][]byte{}
	current := filepath.Join(root, "current")
	_ = filepath.WalkDir(current, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(current, path)
		if relErr != nil {
			return relErr
		}
		slash := filepath.ToSlash(rel)
		if slash != "AGENTS.md" && !strings.HasSuffix(slash, "/AGENTS.md") {
			return nil
		}
		// #nosec G304,G122 -- adapter-owned managed tree under the configured data directory.
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		existing[slash] = body
		return nil
	})
	return existing
}

func prefixDigests(tree fleetconfig.Tree) map[string]string {
	digests := map[string]string{}
	for _, file := range tree.Files {
		if file.Path == "AGENTS.md" || strings.HasSuffix(file.Path, "/AGENTS.md") {
			digests[file.Path] = fleetconfig.DigestBytes(file.Data)
		}
	}
	return digests
}

func projectLiveTree(request FleetReconcileRequest, tree fleetconfig.Tree, lastPrefixDigests map[string]string) (map[string]fleetconfig.TrailerResult, error) {
	trailers := map[string]fleetconfig.TrailerResult{}
	home := request.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil || home == "" {
			return trailers, errors.New("fleet-config home is unavailable")
		}
	}
	matches := fleetconfig.MatchProjects(request.Local.ProjectBasePath, request.Local.ProjectPathOverrides, tree.Projects(), nil)
	matched := map[string]string{}
	for _, match := range matches {
		if match.Path != "" {
			matched[match.Name] = match.Path
		}
	}
	for _, file := range tree.Files {
		dest, agents := liveDestination(home, matched, file.Path)
		if dest == "" {
			continue
		}
		body := file.Data
		if agents {
			existing, existed := readExisting(dest)
			next, result, err := fleetconfig.ApplyAgents(file.Data, existing, existed, lastPrefixDigests[file.Path])
			if err != nil {
				return trailers, err
			}
			trailers[file.Path] = result
			if result.Collision {
				continue
			}
			body = next
		}
		if err := writeLiveFile(dest, body); err != nil {
			return trailers, err
		}
	}
	return trailers, nil
}

func liveDestination(home string, matched map[string]string, path string) (string, bool) {
	switch {
	case path == "AGENTS.md":
		return filepath.Join(home, "AGENTS.md"), true
	case strings.HasPrefix(path, "skills/"):
		return filepath.Join(append([]string{home, ".agents"}, strings.Split(path, "/")...)...), false
	case strings.HasPrefix(path, "projects/"):
		name, rest, ok := strings.Cut(strings.TrimPrefix(path, "projects/"), "/")
		if !ok {
			return "", false
		}
		root, found := matched[name]
		if !found {
			return "", false
		}
		if rest == "AGENTS.md" {
			return filepath.Join(root, "AGENTS.md"), true
		}
		if skillRest, ok := strings.CutPrefix(rest, "skills/"); ok {
			return filepath.Join(append([]string{root, ".agents", "skills"}, strings.Split(skillRest, "/")...)...), false
		}
	}
	return "", false
}

func applyClaudeAliases(request FleetReconcileRequest, tree fleetconfig.Tree, matches []fleetconfig.ProjectMatch) map[string]fleetconfig.AliasResult {
	results := map[string]fleetconfig.AliasResult{}
	home := request.Home
	if home != "" {
		if result, err := fleetconfig.CreateAlias(filepath.Join(home, "AGENTS.md"), filepath.Join(home, "CLAUDE.md"), true); err == nil || result.State != "" {
			results["global"] = result
		}
		if result, _ := fleetconfig.CreateAlias(filepath.Join(home, ".agents", "skills"), filepath.Join(home, ".claude", "skills"), true); result.State != "" {
			results["global-skills"] = result
		}
	}
	for _, match := range matches {
		if match.Path == "" {
			continue
		}
		result, _ := fleetconfig.CreateAlias(filepath.Join(match.Path, "AGENTS.md"), filepath.Join(match.Path, "CLAUDE.md"), true)
		results[match.Name] = result
		skillResult, _ := fleetconfig.CreateAlias(filepath.Join(match.Path, ".agents", "skills"), filepath.Join(match.Path, ".claude", "skills"), true)
		results[match.Name+"-skills"] = skillResult
	}
	_ = tree
	return results
}

func writeLiveFile(path string, body []byte) error {
	info, statErr := os.Lstat(path)
	if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("fleet-config live tree is unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("fleet-config apply failed")
	}
	tmp := path + ".punaro-tmp"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- tmp is a sibling of a validated destination.
	if err != nil {
		return errors.New("fleet-config apply failed")
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	if statErr == nil && info.Mode().IsRegular() {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	return nil
}

func readExisting(path string) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	// #nosec G304 -- live destination fenced by Lstat as a regular file.
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return body, true
}

func trailerState(trailers map[string]fleetconfig.TrailerResult) string {
	if len(trailers) == 0 {
		return "missing"
	}
	for _, trailer := range trailers {
		if trailer.Collision {
			return "collision"
		}
	}
	return "present"
}

func reconcileState(trailers map[string]fleetconfig.TrailerResult) string {
	for _, trailer := range trailers {
		if trailer.Collision || trailer.Drift {
			return "drifted"
		}
	}
	return "current"
}

func aliasState(enabled bool, results map[string]fleetconfig.AliasResult) string {
	if !enabled {
		return "disabled"
	}
	state := "linked"
	for _, result := range results {
		if result.State == "unsupported" {
			return "unsupported"
		}
		if result.State == "collision" {
			state = "collision"
		}
	}
	return state
}

func unsupportedHarness(home string) bool {
	for _, harness := range fleetconfig.DetectHarnesses(home, "", nil) {
		if harness.State == "unsupported" {
			return true
		}
	}
	return false
}

func projectMatchState(matches []fleetconfig.ProjectMatch) string {
	if len(matches) == 0 {
		return "none"
	}
	sawOverride, sawMatched := false, false
	for _, match := range matches {
		switch match.Kind {
		case "override":
			sawOverride = true
		case "matched":
			sawMatched = true
		}
	}
	switch {
	case sawOverride:
		return "override"
	case sawMatched:
		return "matched"
	default:
		return "unmatched"
	}
}
