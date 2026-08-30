package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rock3r/punaro/internal/fleetconfig"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const (
	minimumFleetConfigSchema = 58
	fleetConfigSourceName    = "fleet-config-source.json"
	maxFleetConfigSourceSize = 4 << 10
)

type fleetConfigSource struct {
	Schema     int    `json:"schema"`
	Repository string `json:"repository"`
}

var (
	materializeFleetCommit = materializeFleetCommitFromGit
	persistFleetRelease    = persistFleetReleaseDefault
	loadFleetDesired       = loadFleetDesiredDefault
	loadStoredFleetRelease = loadStoredFleetReleaseDefault
)

func runFleetConfigConfigure(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fleet-config configure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	repository := flags.String("repository", "", "absolute Git repository directory")
	confirmed := flags.Bool("yes", false, "confirm writing the fleet-config source repository")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *repository == "" || !*confirmed {
		return 2
	}
	if !filepath.IsAbs(*repository) {
		_, _ = fmt.Fprintln(stderr, "fleet-config source repository must be an absolute directory")
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config configure refused: installation configuration is unavailable")
		return 1
	}
	info, err := os.Lstat(*repository)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_, _ = fmt.Fprintln(stderr, "fleet-config source repository must be an existing directory")
		return 1
	}
	body, err := json.Marshal(fleetConfigSource{Schema: 1, Repository: filepath.Clean(*repository)})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config configure failed")
		return 1
	}
	path := filepath.Join(installation.Directory, fleetConfigSourceName)
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil { // #nosec G306 -- operator-owned installation file.
		_, _ = fmt.Fprintln(stderr, "fleet-config configure failed")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "fleet_config_configured"})
}

func runFleetConfigPublish(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fleet-config publish", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	confirmed := flags.Bool("yes", false, "confirm publishing the exact preview")
	confirmedHash := flags.String("confirm-preview-hash", "", "exact preview hash printed by the prior preview-only run")
	if flags.Parse(args) != nil || flags.NArg() != 1 || *directory == "" {
		return 2
	}
	commit, err := fleetconfig.ParseCommitID(flags.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish requires a full immutable commit identity")
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: installation configuration is unavailable")
		return 1
	}
	source, err := loadFleetConfigSource(installation.Directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: source repository is not configured")
		return 1
	}
	state, err := inspectSchema(context.Background(), installation.AppDSNFile)
	if err != nil || state.Classification != punaropostgres.Compatible || state.Version < minimumFleetConfigSchema {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: database schema is not compatible")
		return 1
	}
	if err := verifyInstallationPair(context.Background(), installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: database roles do not target the same installation")
		return 1
	}
	owner, err := inspectOwner(context.Background(), installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: database owner does not match the installation configuration")
		return 1
	}
	release, err := materializeFleetCommit(source.Repository, commit)
	if err != nil {
		stored, storedErr := loadStoredFleetRelease(context.Background(), installation.OwnerDSNFile, commit)
		if storedErr != nil {
			_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: source commit could not be materialized")
			return 1
		}
		release = stored
	}
	desired, err := loadFleetDesired(context.Background(), installation.OwnerDSNFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: desired revision is unavailable")
		return 1
	}
	previewHash := fleetPublishPreviewHash(release, desired)
	preview := map[string]any{
		"source_commit":      release.SourceCommit,
		"release_digest":     release.Digest,
		"skill_count":        release.SkillCount,
		"total_bytes":        release.TotalBytes,
		"desired_digest":     desired.Digest,
		"desired_generation": desired.Generation,
		"preview_hash":       previewHash,
	}
	if !*confirmed {
		if code := writeJSON(stdout, stderr, preview); code != 0 {
			return code
		}
		_, _ = fmt.Fprintln(stderr, "publish preview printed; rerun with --yes and --confirm-preview-hash to change desired fleet state")
		return 3
	}
	if *confirmedHash == "" || *confirmedHash != previewHash {
		if code := writeJSON(stdout, stderr, preview); code != 0 {
			return code
		}
		_, _ = fmt.Fprintln(stderr, "fleet-config publish refused: confirmed preview hash does not match")
		return 3
	}
	published, err := persistFleetRelease(context.Background(), installation.OwnerDSNFile, release, previewHash, desired)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config publish failed; prior desired revision is unchanged")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{
		"status":             "fleet_config_published",
		"source_commit":      published.SourceCommit,
		"release_digest":     published.Digest,
		"skill_count":        published.SkillCount,
		"total_bytes":        published.TotalBytes,
		"desired_digest":     published.Digest,
		"desired_generation": published.Generation,
	})
}

func runFleetConfigStatus(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fleet-config status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" {
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config status refused: installation configuration is unavailable")
		return 1
	}
	desired, err := loadFleetDesired(context.Background(), installation.OwnerDSNFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "fleet-config status refused: desired revision is unavailable")
		return 1
	}
	state := "pending"
	if desired.Digest != "" {
		state = "current"
	}
	return writeJSON(stdout, stderr, map[string]any{
		"source_commit":      desired.SourceCommit,
		"release_digest":     desired.Digest,
		"desired_generation": desired.Generation,
		"skill_count":        desired.SkillCount,
		"total_bytes":        desired.TotalBytes,
		"state":              state,
	})
}

func fleetPublishPreviewHash(release fleetconfig.Release, desired punaropostgres.FleetDesired) string {
	var buf bytes.Buffer
	_, _ = buf.WriteString("fleet-config-publish-v1\n")
	_, _ = buf.WriteString(release.SourceCommit)
	_ = buf.WriteByte('\n')
	_, _ = buf.WriteString(release.Digest)
	_ = buf.WriteByte('\n')
	_, _ = buf.WriteString(strconv.Itoa(release.SkillCount))
	_ = buf.WriteByte('\n')
	_, _ = buf.WriteString(strconv.FormatInt(release.TotalBytes, 10))
	_ = buf.WriteByte('\n')
	_, _ = buf.WriteString(desired.Digest)
	_ = buf.WriteByte('\n')
	_, _ = buf.WriteString(strconv.FormatInt(desired.Generation, 10))
	_ = buf.WriteByte('\n')
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func loadFleetConfigSource(directory string) (fleetConfigSource, error) {
	path := filepath.Join(directory, fleetConfigSourceName)
	body, err := os.ReadFile(path) // #nosec G304 -- operator installation file.
	if err != nil || len(body) == 0 || len(body) > maxFleetConfigSourceSize {
		return fleetConfigSource{}, errors.New("fleet-config source is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var source fleetConfigSource
	if err := decoder.Decode(&source); err != nil || source.Schema != 1 || !filepath.IsAbs(source.Repository) {
		return fleetConfigSource{}, errors.New("fleet-config source is invalid")
	}
	return source, nil
}

func materializeFleetCommitFromGit(repository, commit string) (fleetconfig.Release, error) {
	if _, err := fleetconfig.ParseCommitID(commit); err != nil {
		return fleetconfig.Release{}, err
	}
	kind := fleetGitCommand("-C", repository, "cat-file", "-t", commit)
	out, err := kind.Output()
	if err != nil || strings.TrimSpace(string(out)) != "commit" {
		return fleetconfig.Release{}, errors.New("commit is unavailable")
	}
	if err := boundFleetGitTree(repository, commit); err != nil {
		return fleetconfig.Release{}, err
	}
	dest, err := os.MkdirTemp("", "punaro-fleet-config-")
	if err != nil {
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	defer func() { _ = os.RemoveAll(dest) }()
	archive := fleetGitCommand("-C", repository, "archive", commit)
	extract := exec.CommandContext(context.Background(), "tar", "-x", "-C", dest) // #nosec G204 -- fixed tar argv, dest is MkdirTemp.
	extract.Stderr = io.Discard
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	extract.Stdin = io.LimitReader(pipe, 8<<20+1)
	if err := archive.Start(); err != nil {
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	if err := extract.Start(); err != nil {
		_ = archive.Process.Kill()
		_ = archive.Wait()
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	if err := extract.Wait(); err != nil {
		_ = archive.Process.Kill()
		_ = pipe.Close()
		_ = archive.Wait()
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	if err := archive.Wait(); err != nil {
		return fleetconfig.Release{}, errors.New("fleet-config checkout failed")
	}
	tree, err := fleetconfig.InspectRoot(dest)
	if err != nil {
		return fleetconfig.Release{}, err
	}
	return fleetconfig.Materialize(tree, commit)
}

func persistFleetReleaseDefault(ctx context.Context, ownerDSNFile string, release fleetconfig.Release, previewHash string, expected punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if err != nil {
		return punaropostgres.FleetDesired{}, err
	}
	defer func() { _ = admin.Close() }()
	return admin.PublishFleetRelease(ctx, release, previewHash, expected)
}

func fleetGitCommand(args ...string) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), "git", args...) // #nosec G204 -- fixed git argv, commit already parsed.
	cmd.Stderr = io.Discard
	cmd.Env = append(os.Environ(), "GIT_NO_REPLACE_OBJECTS=1", "GIT_ATTR_NOSYSTEM=1")
	return cmd
}

func boundFleetGitTree(repository, commit string) error {
	listed := fleetGitCommand("-C", repository, "ls-tree", "-r", "-l", "--full-tree", commit)
	stdout, err := listed.StdoutPipe()
	if err != nil {
		return errors.New("commit is unavailable")
	}
	if err := listed.Start(); err != nil {
		return errors.New("commit is unavailable")
	}
	stop := func() {
		_ = listed.Process.Kill()
		_ = listed.Wait()
	}
	scanner := bufio.NewScanner(stdout)
	var files int
	var total int64
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		meta, _, ok := strings.Cut(line, "\t")
		if !ok {
			stop()
			return errors.New("fleet-config git tree is too large")
		}
		fields := strings.Fields(meta)
		if len(fields) < 3 || fields[1] != "blob" || fields[0] == "120000" {
			stop()
			return errors.New("fleet-config source contains a special file")
		}
		if len(fields) < 4 {
			stop()
			return errors.New("fleet-config git tree is too large")
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > fleetconfig.MaxFileBytes {
			stop()
			return errors.New("fleet-config git tree is too large")
		}
		files++
		total += size
		if files > fleetconfig.MaxFiles || total > fleetconfig.MaxTotalBytes {
			stop()
			return errors.New("fleet-config git tree is too large")
		}
	}
	if err := scanner.Err(); err != nil {
		stop()
		return errors.New("commit is unavailable")
	}
	if err := listed.Wait(); err != nil {
		return errors.New("commit is unavailable")
	}
	if files < 1 || total < 1 {
		return errors.New("fleet-config git tree is too large")
	}
	return nil
}

func loadStoredFleetReleaseDefault(ctx context.Context, ownerDSNFile, commit string) (fleetconfig.Release, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if err != nil {
		return fleetconfig.Release{}, err
	}
	defer func() { _ = admin.Close() }()
	return admin.LoadFleetReleaseByCommit(ctx, commit)
}

func loadFleetDesiredDefault(ctx context.Context, ownerDSNFile string) (punaropostgres.FleetDesired, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if err != nil {
		return punaropostgres.FleetDesired{}, err
	}
	defer func() { _ = admin.Close() }()
	return admin.LoadFleetDesired(ctx)
}
