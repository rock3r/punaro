// Package release validates local target-release metadata. Validation binds
// exact artifact digests and compatibility boundaries; it does not fetch
// artifacts, access a network, or claim signature or provenance verification.
package release

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// MaximumMetadataBytes bounds one target-release metadata document.
const MaximumMetadataBytes = 64 << 10

var (
	releaseNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	imageRepositoryPattern = regexp.MustCompile(`^(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?))*(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
)

// Environment is the exact installed boundary against which a target release
// is evaluated. Parse rejects PostgreSQL major drift and schema downgrades.
type Environment struct {
	CurrentSchema   int64
	PostgreSQLMajor int
}

// SchemaRange declares the schema compatibility and migration boundary of one
// release. RollbackFloor is metadata for the later recovery planner; Parse
// validates its canonical relationship but does not promise in-place rollback.
type SchemaRange struct {
	Min           int64 `json:"min"`
	Max           int64 `json:"max"`
	Target        int64 `json:"target"`
	RollbackFloor int64 `json:"rollback_floor"`
}

// Metadata binds one named release to immutable local artifact hashes and an
// exact database compatibility boundary.
type Metadata struct {
	Release                 string      `json:"release"`
	Image                   string      `json:"image"`
	Schema                  SchemaRange `json:"schema"`
	PostgreSQLMajor         int         `json:"postgres_major"`
	ReleaseSHA256           string      `json:"release_sha256"`
	ComposeSHA256           string      `json:"compose_sha256"`
	MigrationManifestSHA256 string      `json:"migration_manifest_sha256"`
}

// Parse strictly parses and validates one bounded target-release metadata
// document against the current installation. It performs no I/O or trust
// verification beyond the supplied bytes.
func Parse(body []byte, environment Environment) (Metadata, error) {
	if len(body) == 0 || len(body) > MaximumMetadataBytes {
		return Metadata{}, errors.New("release metadata is invalid")
	}
	if err := rejectDuplicateFields(body); err != nil {
		return Metadata{}, errors.New("release metadata is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var metadata Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, errors.New("release metadata is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("release metadata is invalid")
	}
	if metadata.validate(environment) != nil {
		return Metadata{}, errors.New("release metadata is invalid")
	}
	return metadata, nil
}

func (metadata Metadata) validate(environment Environment) error {
	if !releaseNamePattern.MatchString(metadata.Release) || !validImageDigest(metadata.Image) || !validSHA256(metadata.ReleaseSHA256) || !validSHA256(metadata.ComposeSHA256) || !validSHA256(metadata.MigrationManifestSHA256) {
		return errors.New("invalid release binding")
	}
	_, imageDigest, _ := strings.Cut(metadata.Image, "@sha256:")
	if metadata.ReleaseSHA256 != imageDigest {
		return errors.New("release artifact does not match image")
	}
	schema := metadata.Schema
	if schema.Min < 1 || schema.Max < schema.Min || schema.Target < schema.Min || schema.Target > schema.Max || schema.RollbackFloor < schema.Min || schema.RollbackFloor > schema.Target {
		return errors.New("invalid schema boundary")
	}
	if metadata.PostgreSQLMajor < 1 || environment.PostgreSQLMajor != metadata.PostgreSQLMajor {
		return errors.New("PostgreSQL major mismatch")
	}
	if environment.CurrentSchema < schema.Min || environment.CurrentSchema > schema.Target {
		return errors.New("schema target is incompatible")
	}
	return nil
}

func validImageDigest(value string) bool {
	repository, digest, found := strings.Cut(value, "@sha256:")
	return found && imageRepositoryPattern.MatchString(repository) && validSHA256(digest)
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func rejectDuplicateFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := visit(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid object")
			}
		case '[':
			for decoder.More() {
				if err := visit(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := visit(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}
