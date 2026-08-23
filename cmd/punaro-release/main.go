// punaro-release assembles, signs, and verifies the public GitHub Releases
// catalog and manifest. It never fetches artifacts or talks to GitHub.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rock3r/punaro/internal/operator"
	"github.com/rock3r/punaro/internal/plugindiagnostic"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

const productionPostgresMajor = 18

var publicationNow = func() time.Time { return time.Now().UTC() }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: punaro-release assemble|build-facts|validate|publication-check|keygen|sign|verify")
	}
	switch args[0] {
	case "assemble":
		return runAssemble(args[1:])
	case "build-facts":
		facts, err := buildFacts(args[1:])
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(facts)
	case "validate":
		return runValidate(args[1:])
	case "publication-check":
		return runPublicationCheck(args[1:])
	case "keygen":
		return runKeygen(args[1:])
	case "sign":
		return runSign(args[1:])
	case "verify":
		return runVerify(args[1:])
	default:
		return errors.New("usage: punaro-release assemble|build-facts|validate|publication-check|keygen|sign|verify")
	}
}

type releaseBuildFacts struct {
	Release                 string `json:"release"`
	ComposeSHA256           string `json:"compose_sha256"`
	MigrationManifestSHA256 string `json:"migration_manifest_sha256"`
	SkillSetSHA256          string `json:"skill_set_sha256"`
}

func buildFacts(args []string) (releaseBuildFacts, error) {
	flags := flag.NewFlagSet("punaro-release build-facts", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	releaseName := flags.String("release", "", "product release name")
	pluginRoot := flags.String("plugin-root", "", "portable Punaro plugin root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *releaseName == "" || *pluginRoot == "" {
		return releaseBuildFacts{}, errors.New("release build facts are invalid")
	}
	version, err := plugindiagnostic.Version(*pluginRoot)
	if err != nil || *releaseName != "v"+version {
		return releaseBuildFacts{}, errors.New("release build facts are invalid")
	}
	skillDigest, err := plugindiagnostic.SkillSetDigest(filepath.Join(*pluginRoot, "skills"))
	if err != nil {
		return releaseBuildFacts{}, errors.New("release build facts are invalid")
	}
	return releaseBuildFacts{Release: *releaseName, ComposeSHA256: operator.ComposeManifestSHA256(), MigrationManifestSHA256: punaropostgres.MigrationManifestSHA256(), SkillSetSHA256: skillDigest}, nil
}

func runAssemble(args []string) error {
	flags := flag.NewFlagSet("punaro-release assemble", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "directory of native artifacts")
	releaseName := flags.String("release", "", "product release name")
	sequence := flags.Int64("sequence", 0, "monotonic release sequence")
	catalogSequence := flags.Int64("catalog-sequence", 0, "monotonic catalog sequence")
	publishedAt := flags.String("published-at", "", "UTC publication time")
	expiresAt := flags.String("expires-at", "", "UTC catalog expiry")
	image := flags.String("image", "", "optional digest-pinned gateway image")
	minSafe := flags.Int64("minimum-safe-sequence", 0, "lowest sequence still safe for automatic updates")
	minBootstrap := flags.String("minimum-bootstrap-release", "", "oldest bootstrap that may install this release")
	if err := flags.Parse(args); err != nil {
		return errors.New("release assembly is invalid")
	}
	if flags.NArg() != 0 || *dir == "" || *releaseName == "" || *sequence < 1 || *catalogSequence < 1 {
		return errors.New("release assembly is invalid")
	}
	published, expires, err := assembleTimes(*publishedAt, *expiresAt)
	if err != nil {
		return err
	}
	schema := currentSchemaRange()
	minimumSafe := *minSafe
	if minimumSafe == 0 {
		minimumSafe = *sequence
	}
	bootstrapRelease := *minBootstrap
	if bootstrapRelease == "" {
		bootstrapRelease = *releaseName
	}
	_, err = punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory:               *dir,
		Release:                 *releaseName,
		Sequence:                *sequence,
		PublishedAt:             published,
		ExpiresAt:               expires,
		MinimumSafeSequence:     minimumSafe,
		CatalogSequence:         *catalogSequence,
		Image:                   *image,
		ComposeSHA256:           operator.ComposeManifestSHA256(),
		MigrationManifestSHA256: punaropostgres.MigrationManifestSHA256(),
		Database:                schema,
		PostgreSQLMajor:         productionPostgresMajor,
		GatewayProtocol:         punarorelease.ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: bootstrapRelease,
	})
	return err
}

func runValidate(args []string) error {
	flags := flag.NewFlagSet("punaro-release validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "directory containing assembled documents")
	releaseName := flags.String("release", "", "expected product release name")
	if err := flags.Parse(args); err != nil {
		return errors.New("release validation is invalid")
	}
	if flags.NArg() != 0 || *dir == "" {
		return errors.New("release validation is invalid")
	}
	manifestBody, err := os.ReadFile(filepath.Join(*dir, punarorelease.ReleaseManifestFile)) // #nosec G304 -- explicit assembled directory.
	if err != nil {
		return errors.New("release validation is invalid")
	}
	catalogBody, err := os.ReadFile(filepath.Join(*dir, punarorelease.CatalogFile)) // #nosec G304 -- explicit assembled directory.
	if err != nil {
		return errors.New("release validation is invalid")
	}
	manifest, err := punarorelease.ParseReleaseManifest(manifestBody)
	if err != nil {
		return err
	}
	if *releaseName != "" && manifest.Release != *releaseName {
		return errors.New("release validation is invalid")
	}
	catalog, err := punarorelease.ParseCatalog(catalogBody)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(manifestBody)
	if !catalog.Allows(manifest.Release, manifest.Sequence, hex.EncodeToString(sum[:])) {
		return errors.New("catalog does not allow the assembled manifest")
	}
	return nil
}

func runPublicationCheck(args []string) error {
	flags := flag.NewFlagSet("punaro-release publication-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	catalogFile := flags.String("catalog", "", "candidate signed catalog document")
	previousFile := flags.String("previous-catalog", "", "optional verified live catalog document")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *catalogFile == "" {
		return errors.New("release publication check is invalid")
	}
	candidateBody, err := os.ReadFile(*catalogFile) // #nosec G304 -- explicit operator-supplied catalog path.
	if err != nil || len(candidateBody) > punarorelease.MaximumManifestBytes {
		return errors.New("release publication check is invalid")
	}
	candidate, err := punarorelease.ParseCatalog(candidateBody)
	if err != nil {
		return errors.New("release publication check is invalid")
	}
	var previous *punarorelease.Catalog
	if *previousFile != "" {
		previousBody, readErr := os.ReadFile(*previousFile) // #nosec G304 -- explicit verified live catalog path.
		if readErr != nil || len(previousBody) > punarorelease.MaximumManifestBytes {
			return errors.New("release publication check is invalid")
		}
		parsed, parseErr := punarorelease.ParseCatalog(previousBody)
		if parseErr != nil {
			return errors.New("release publication check is invalid")
		}
		previous = &parsed
	}
	return validatePublicationCatalog(candidate, previous, publicationNow())
}

func validatePublicationCatalog(candidate punarorelease.Catalog, previous *punarorelease.Catalog, now time.Time) error {
	if !candidate.Fresh(now) {
		return errors.New("candidate release catalog is not currently fresh")
	}
	if previous != nil && candidate.Sequence <= previous.Sequence {
		return errors.New("candidate release catalog sequence does not advance the live catalog")
	}
	return nil
}

func runKeygen(args []string) error {
	flags := flag.NewFlagSet("punaro-release keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyID := flags.String("key-id", "", "release key ID")
	privateFile := flags.String("private-key-file", "", "new private key path (must not exist)")
	publicFile := flags.String("public-key-file", "", "new public key set path (must not exist)")
	if err := flags.Parse(args); err != nil {
		return errors.New("release keygen is invalid")
	}
	if flags.NArg() != 0 || *keyID == "" || *privateFile == "" || *publicFile == "" {
		return errors.New("release keygen is invalid")
	}
	if err := requireAbsentFile(*privateFile); err != nil {
		return err
	}
	if err := requireAbsentFile(*publicFile); err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	publicBody, err := punarorelease.EncodePublicKeys(*keyID, public)
	if err != nil {
		return err
	}
	if err := writeExclusiveFile(*privateFile, punarorelease.EncodePrivateKey(private), 0o600); err != nil {
		return err
	}
	if err := writeExclusiveFile(*publicFile, publicBody, 0o644); err != nil {
		_ = os.Remove(*privateFile)
		return err
	}
	return nil
}

func runSign(args []string) error {
	flags := flag.NewFlagSet("punaro-release sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyID := flags.String("key-id", "", "release key ID")
	keyFile := flags.String("key-file", "", "offline private key file")
	input := flags.String("in", "", "document to sign")
	existing := flags.String("signature", "", "existing envelope to append to")
	keysFile := flags.String("keys-file", "", "public keys that must already verify --signature")
	output := flags.String("out", "", "detached signature path (must not exist)")
	if err := flags.Parse(args); err != nil {
		return errors.New("release signing is invalid")
	}
	if flags.NArg() != 0 || *keyID == "" || *keyFile == "" || *input == "" || *output == "" {
		return errors.New("release signing is invalid")
	}
	if *existing != "" && *keysFile == "" {
		return errors.New("release signing is invalid")
	}
	privateBody, err := os.ReadFile(*keyFile) // #nosec G304 -- explicit offline signing key path.
	if err != nil {
		return errors.New("release signing is invalid")
	}
	private, err := punarorelease.ParsePrivateKey(privateBody)
	if err != nil {
		return err
	}
	document, err := os.ReadFile(*input) // #nosec G304 -- explicit local document path.
	if err != nil {
		return errors.New("release signing is invalid")
	}
	var envelope punarorelease.Envelope
	if *existing != "" {
		prior, err := os.ReadFile(*existing) // #nosec G304 -- explicit local signature path.
		if err != nil {
			return errors.New("release signing is invalid")
		}
		parsed, err := punarorelease.ParseEnvelope(prior)
		if err != nil {
			return err
		}
		keysBody, err := os.ReadFile(*keysFile) // #nosec G304 -- explicit public key set path.
		if err != nil {
			return errors.New("release signing is invalid")
		}
		keys, err := punarorelease.ParsePublicKeys(keysBody)
		if err != nil {
			return err
		}
		if err := punarorelease.Verify(document, parsed, keys); err != nil {
			return err
		}
		envelope, err = punarorelease.AppendSignature(parsed, document, *keyID, private)
		if err != nil {
			return err
		}
	} else {
		envelope, err = punarorelease.Sign(document, *keyID, private)
		if err != nil {
			return err
		}
	}
	body, err := punarorelease.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return writeExclusiveFile(*output, body, 0o644)
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("punaro-release verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keysFile := flags.String("keys-file", "", "public key set")
	documentPath := flags.String("document", "", "signed document")
	signaturePath := flags.String("signature", "", "detached signature")
	if err := flags.Parse(args); err != nil {
		return errors.New("release verification is invalid")
	}
	if flags.NArg() != 0 || *keysFile == "" || *documentPath == "" || *signaturePath == "" {
		return errors.New("release verification is invalid")
	}
	keysBody, err := os.ReadFile(*keysFile) // #nosec G304 -- explicit public key set path.
	if err != nil {
		return errors.New("release verification is invalid")
	}
	keys, err := punarorelease.ParsePublicKeys(keysBody)
	if err != nil {
		return err
	}
	document, err := os.ReadFile(*documentPath) // #nosec G304 -- explicit local document path.
	if err != nil {
		return errors.New("release verification is invalid")
	}
	signature, err := os.ReadFile(*signaturePath) // #nosec G304 -- explicit local signature path.
	if err != nil {
		return errors.New("release verification is invalid")
	}
	envelope, err := punarorelease.ParseEnvelope(signature)
	if err != nil {
		return err
	}
	return punarorelease.Verify(document, envelope, keys)
}

func assembleTimes(publishedAt, expiresAt string) (time.Time, time.Time, error) {
	now := time.Now().UTC().Truncate(time.Second)
	published := now
	if publishedAt != "" {
		parsed, err := time.Parse(time.RFC3339, publishedAt)
		if err != nil || parsed.Format("2006-01-02T15:04:05Z") != publishedAt {
			return time.Time{}, time.Time{}, errors.New("release assembly is invalid")
		}
		published = parsed.UTC()
	}
	expires := published.Add(7 * 24 * time.Hour)
	if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil || parsed.Format("2006-01-02T15:04:05Z") != expiresAt {
			return time.Time{}, time.Time{}, errors.New("release assembly is invalid")
		}
		expires = parsed.UTC()
	}
	return published, expires, nil
}

func currentSchemaRange() punarorelease.SchemaRange {
	manifest := punaropostgres.CurrentManifest()
	return punarorelease.SchemaRange{
		Min:           manifest.MinSupported,
		Max:           manifest.MaxSupported,
		Target:        manifest.MaxSupported,
		RollbackFloor: manifest.MinSupported,
	}
}

func requireAbsentFile(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return errors.New("release output already exists")
	}
	if !os.IsNotExist(err) {
		return errors.New("release keygen is invalid")
	}
	return nil
}

func writeExclusiveFile(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- explicit new local output path.
	if err != nil {
		return errors.New("release output already exists")
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
