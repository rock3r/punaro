// Package bootstrap installs signed Punaro client artifacts from the fixed
// GitHub Releases origin. It verifies catalog and manifest signatures and
// exact artifact length/digest. It does not run children, open PostgreSQL, or
// read Punaro message content.
package bootstrap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

const (
	acceptedFile  = "accepted.json"
	currentSlot   = "current"
	previousSlot  = "previous"
	candidateSlot = "candidate"
	swapSlot      = "swap"
	slotRecord    = "slot.json"
	journalFile   = "journal.json"
	lockFile      = "bootstrap.lock"
)

// Request is one host-local update from a fixed origin.
type Request struct {
	Directory string
	Origin    string
	Keys      map[string]ed25519.PublicKey
	Release   string
	GOOS      string
	GOARCH    string
	Now       time.Time
	HTTP      fetcher
}

// Result is the published slot after a successful update.
type Result struct {
	Release   string
	Sequence  int64
	Manifest  string
	Installed []string
}

// State is the content-free view of local slots.
type State struct {
	Current          string
	CurrentSequence  int64
	Previous         string
	PreviousSequence int64
	CatalogSequence  int64
}

// Update fetches the signed catalog, honors only a listed release, and
// publishes matching platform artifacts into the current slot.
func Update(request Request) (Result, error) {
	if err := request.normalize(); err != nil {
		return Result{}, err
	}
	if err := prepareDirectory(request.Directory); err != nil {
		return Result{}, err
	}
	unlock, err := lockDirectory(request.Directory)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := recoverJournal(request.Directory); err != nil {
		return Result{}, err
	}
	accepted, err := loadAccepted(request.Directory)
	if err != nil {
		return Result{}, err
	}
	client := request.HTTP
	if client == nil {
		transport, err := newFetcher(request.Origin)
		if err != nil {
			return Result{}, err
		}
		client = transport
	}
	catalogBody, err := client.Get(punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, punarorelease.MaximumManifestBytes)
	if err != nil {
		return Result{}, err
	}
	catalogSig, err := client.Get(punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile, punarorelease.MaximumEnvelopeBytes)
	if err != nil {
		return Result{}, err
	}
	if err := verifyDocument(catalogBody, catalogSig, request.Keys); err != nil {
		return Result{}, err
	}
	catalog, err := punarorelease.ParseCatalog(catalogBody)
	if err != nil {
		return Result{}, err
	}
	if !catalog.Fresh(request.Now) {
		return Result{}, errors.New("release catalog is stale")
	}
	if accepted.CatalogSequence > 0 && catalog.Sequence < accepted.CatalogSequence {
		return Result{}, errors.New("release catalog sequence downgrade")
	}
	wanted := request.Release
	if wanted == "" {
		wanted = catalog.CurrentRelease
	}
	var listed punarorelease.CatalogRelease
	found := false
	for _, entry := range catalog.Releases {
		if entry.Release == wanted {
			listed = entry
			found = true
			break
		}
	}
	if !found {
		return Result{}, errors.New("requested release is not in the catalog")
	}
	if !catalog.Allows(listed.Release, listed.Sequence, listed.ManifestSHA256) {
		return Result{}, errors.New("catalog does not allow the release")
	}
	if err := writeJournal(request.Directory, journal{Schema: 1, Phase: "staging", Release: listed.Release, Sequence: listed.Sequence, ManifestSHA256: listed.ManifestSHA256}); err != nil {
		return Result{}, err
	}
	manifestBody, err := client.Get(listed.ManifestPath, listed.ManifestLength)
	if err != nil {
		return Result{}, err
	}
	if int64(len(manifestBody)) != listed.ManifestLength {
		return Result{}, errors.New("release manifest length mismatch")
	}
	sum := sha256.Sum256(manifestBody)
	if hex.EncodeToString(sum[:]) != listed.ManifestSHA256 {
		return Result{}, errors.New("release manifest digest mismatch")
	}
	manifestSig, err := client.Get(listed.Release+"/"+punarorelease.ReleaseSignatureFile, punarorelease.MaximumEnvelopeBytes)
	if err != nil {
		return Result{}, err
	}
	if err := verifyDocument(manifestBody, manifestSig, request.Keys); err != nil {
		return Result{}, err
	}
	manifest, err := punarorelease.ParseReleaseManifest(manifestBody)
	if err != nil {
		return Result{}, err
	}
	if !catalog.Allows(manifest.Release, manifest.Sequence, listed.ManifestSHA256) {
		return Result{}, errors.New("catalog does not allow the release")
	}
	if accepted.ReleaseSequence > 0 && manifest.Sequence < accepted.ReleaseSequence {
		return Result{}, errors.New("release sequence downgrade")
	}
	artifacts := platformArtifacts(manifest.Artifacts, request.GOOS, request.GOARCH)
	if len(artifacts) == 0 {
		return Result{}, errors.New("release has no artifacts for this platform")
	}
	candidate := filepath.Join(request.Directory, candidateSlot)
	if err := os.RemoveAll(candidate); err != nil {
		return Result{}, err
	}
	if err := os.Mkdir(candidate, 0o700); err != nil {
		return Result{}, err
	}
	var installed []string
	for _, artifact := range artifacts {
		body, err := client.Get(artifact.Path, artifact.Length)
		if err != nil {
			return Result{}, err
		}
		if int64(len(body)) != artifact.Length {
			return Result{}, errors.New("release artifact length mismatch")
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 {
			return Result{}, errors.New("release artifact digest mismatch")
		}
		name := filepath.Base(artifact.Path)
		if name != artifactName(artifact.Component, artifact.OS, artifact.Arch) {
			return Result{}, errors.New("release artifact name is invalid")
		}
		if artifact.Mode != 0o755 {
			return Result{}, errors.New("release artifact mode is invalid")
		}
		if err := writeAtomic(filepath.Join(candidate, name), body, 0o755); err != nil {
			return Result{}, err
		}
		installed = append(installed, name)
	}
	published := acceptedState{
		Schema:          1,
		Release:         manifest.Release,
		ReleaseSequence: manifest.Sequence,
		CatalogSequence: catalog.Sequence,
		ManifestSHA256:  listed.ManifestSHA256,
	}
	if err := writeJournal(request.Directory, journal{
		Schema:          1,
		Phase:           "publishing",
		Release:         published.Release,
		Sequence:        published.ReleaseSequence,
		CatalogSequence: published.CatalogSequence,
		ManifestSHA256:  published.ManifestSHA256,
	}); err != nil {
		return Result{}, err
	}
	if err := publishSlot(request.Directory, published.Release, published.ReleaseSequence, published.ManifestSHA256); err != nil {
		return Result{}, err
	}
	if err := finishPublication(request.Directory, published); err != nil {
		return Result{}, err
	}
	return Result{Release: manifest.Release, Sequence: manifest.Sequence, Manifest: listed.ManifestSHA256, Installed: installed}, nil
}

func (request *Request) normalize() error {
	if request.Directory == "" || !filepath.IsAbs(request.Directory) {
		return errors.New("bootstrap directory is invalid")
	}
	if len(request.Keys) == 0 {
		return errors.New("bootstrap has no embedded release keys")
	}
	if request.Origin == "" {
		request.Origin = punarorelease.GitHubReleaseOrigin
	}
	if request.GOOS == "" {
		request.GOOS = runtime.GOOS
	}
	if request.GOARCH == "" {
		request.GOARCH = runtime.GOARCH
	}
	if request.Now.IsZero() {
		request.Now = time.Now().UTC()
	}
	return nil
}

func verifyDocument(document, signature []byte, keys map[string]ed25519.PublicKey) error {
	envelope, err := punarorelease.ParseEnvelope(signature)
	if err != nil {
		return err
	}
	return punarorelease.Verify(document, envelope, keys)
}

func platformArtifacts(artifacts []punarorelease.Artifact, goos, goarch string) []punarorelease.Artifact {
	var matched []punarorelease.Artifact
	for _, artifact := range artifacts {
		if artifact.OS == goos && artifact.Arch == goarch {
			matched = append(matched, artifact)
		}
	}
	return matched
}

func artifactName(component, goos, goarch string) string {
	name := component + "-" + goos + "-" + goarch
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}
