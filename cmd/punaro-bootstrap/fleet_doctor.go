package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	if value == "" || len(*values) >= punarodiagnostic.MaximumChecks {
		return errors.New("too many fleet inputs")
	}
	*values = append(*values, value)
	return nil
}

func runFleetDoctor(args []string, stdout, stderr io.Writer) int {
	return runFleetDoctorAt(args, stdout, stderr, time.Now().UTC())
}

func runFleetDoctorAt(args []string, stdout, stderr io.Writer, now time.Time) int {
	flags := flag.NewFlagSet("punaro-bootstrap fleet-doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var reports, expected repeatedFlag
	flags.Var(&reports, "report", "local doctor JSON file (repeatable)")
	flags.Var(&expected, "expect", "required machine/component identity (repeatable)")
	catalogPath := flags.String("catalog", "", "verified catalog JSON file")
	catalogSignaturePath := flags.String("catalog-signature", "", "detached catalog signature")
	releaseRoot := flags.String("release-root", "", "local root containing release manifest directories")
	keysFile := flags.String("keys-file", "", "release public key set")
	if flags.Parse(args) != nil || flags.NArg() != 0 || len(reports) == 0 || len(expected) == 0 || *catalogPath == "" || *catalogSignaturePath == "" || *releaseRoot == "" || *keysFile == "" {
		return 2
	}
	keys, err := loadKeys(*keysFile)
	if err != nil {
		return writeFleetFailure(stderr)
	}
	catalogBody, err := readFleetFile(*catalogPath, punarorelease.MaximumManifestBytes)
	if err != nil {
		return writeFleetFailure(stderr)
	}
	catalogSignatureBody, err := readFleetFile(*catalogSignaturePath, punarorelease.MaximumEnvelopeBytes)
	if err != nil {
		return writeFleetFailure(stderr)
	}
	envelope, err := punarorelease.ParseEnvelope(catalogSignatureBody)
	if err != nil || punarorelease.Verify(catalogBody, envelope, keys) != nil {
		return writeFleetFailure(stderr)
	}
	catalog, err := punarorelease.ParseCatalog(catalogBody)
	if err != nil || !catalog.Fresh(now) {
		return writeFleetFailure(stderr)
	}

	policy := punarodiagnostic.FleetPolicy{CatalogSequence: catalog.Sequence, Catalog: map[string]int64{}, SupportedFrom: map[string][]string{}}
	var current punarorelease.ReleaseManifest
	for _, entry := range catalog.Releases {
		manifestPath := filepath.Join(*releaseRoot, filepath.FromSlash(entry.ManifestPath))
		manifestBody, readErr := readFleetFile(manifestPath, punarorelease.MaximumManifestBytes)
		if readErr != nil || int64(len(manifestBody)) != entry.ManifestLength {
			return writeFleetFailure(stderr)
		}
		digest := sha256.Sum256(manifestBody)
		if hex.EncodeToString(digest[:]) != entry.ManifestSHA256 {
			return writeFleetFailure(stderr)
		}
		signaturePath := filepath.Join(*releaseRoot, entry.Release, punarorelease.ReleaseSignatureFile)
		signatureBody, readErr := readFleetFile(signaturePath, punarorelease.MaximumEnvelopeBytes)
		if readErr != nil {
			return writeFleetFailure(stderr)
		}
		manifestEnvelope, parseErr := punarorelease.ParseEnvelope(signatureBody)
		if parseErr != nil || punarorelease.Verify(manifestBody, manifestEnvelope, keys) != nil {
			return writeFleetFailure(stderr)
		}
		manifest, parseErr := punarorelease.ParseReleaseManifest(manifestBody)
		if parseErr != nil || manifest.Release != entry.Release || manifest.Sequence != entry.Sequence {
			return writeFleetFailure(stderr)
		}
		if catalog.Allows(entry.Release, entry.Sequence, entry.ManifestSHA256) {
			policy.Catalog[entry.Release] = entry.Sequence
		}
		policy.SupportedFrom[entry.Release] = append([]string(nil), manifest.SupportedFrom...)
		if entry.Release == catalog.CurrentRelease {
			current = manifest
		}
	}
	if current.Release == "" {
		return writeFleetFailure(stderr)
	}
	policy.ClientProtocolMin, policy.ClientProtocolMax = current.ClientProtocol.Min, current.ClientProtocol.Max
	policy.GatewayProtocolMin, policy.GatewayProtocolMax = current.GatewayProtocol.Min, current.GatewayProtocol.Max
	policy.SchemaMin, policy.SchemaMax = current.Database.Min, current.Database.Max
	for _, raw := range expected {
		machine, component, found := strings.Cut(raw, "/")
		if !found || strings.Contains(component, "/") {
			return 2
		}
		policy.Expected = append(policy.Expected, punarodiagnostic.FleetTarget{MachineID: machine, Component: punarodiagnostic.Component(component)})
	}

	decoded := make([]punarodiagnostic.Report, 0, len(reports))
	for _, path := range reports {
		body, readErr := readFleetFile(path, punarodiagnostic.MaximumReportBytes)
		if readErr != nil {
			return writeFleetFailure(stderr)
		}
		report, decodeErr := punarodiagnostic.Decode(bytes.NewReader(body))
		if decodeErr != nil {
			return writeFleetFailure(stderr)
		}
		decoded = append(decoded, report)
	}
	report, err := punarodiagnostic.AggregateFleet(decoded, policy)
	if err != nil {
		return writeFleetFailure(stderr)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil {
		return writeFleetFailure(stderr)
	}
	return punarodiagnostic.ExitCode(report)
}

func readFleetFile(path string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid fleet input")
	}
	info, err := os.Lstat(path) // #nosec G703 -- explicit local fleet input.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > int64(maximum) {
		return nil, errors.New("invalid fleet input")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated explicit local input.
	if err != nil {
		return nil, errors.New("invalid fleet input")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(body) == 0 || len(body) > maximum {
		return nil, errors.New("invalid fleet input")
	}
	return body, nil
}

func writeFleetFailure(stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "punaro-bootstrap fleet-doctor failed: verified diagnostic inputs unavailable")
	return 2
}
