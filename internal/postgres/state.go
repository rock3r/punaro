// Package postgres owns Punaro's opt-in PostgreSQL platform substrate.
// Ordinary runtime inspection is deliberately read-only; schema changes are
// available only through the explicit migrator entry point.
package postgres

import (
	"errors"
	"fmt"
	"sort"
)

// Classification is the binary's compatibility decision for one schema snapshot.
type Classification string

// Schema compatibility classifications are content-free operator diagnostics.
const (
	Pristine        Classification = "pristine"
	Compatible      Classification = "compatible"
	UpgradeRequired Classification = "upgrade_required"
	Newer           Classification = "newer"
	Dirty           Classification = "dirty"
	Incompatible    Classification = "incompatible"
)

// Migration is one immutable ordered embedded schema change.
type Migration struct {
	Version            int64
	Name               string
	Checksum           string
	CompatibilityFloor int64
	SQL                string
}

// Manifest declares migration history and the binary compatibility window.
type Manifest struct {
	MinSupported int64
	MaxSupported int64
	Migrations   []Migration
}

// Validate rejects incomplete, non-contiguous, or impossible manifests.
func (m Manifest) Validate() error {
	if len(m.Migrations) == 0 || m.MinSupported < 1 || m.MaxSupported < m.MinSupported || m.MaxSupported > int64(len(m.Migrations)) {
		return errors.New("invalid PostgreSQL migration manifest")
	}
	for i, migration := range m.Migrations {
		version := int64(i + 1)
		if migration.Version != version || migration.Name == "" || migration.Checksum == "" || migration.CompatibilityFloor < 1 || migration.CompatibilityFloor > version {
			return errors.New("invalid PostgreSQL migration manifest")
		}
	}
	return nil
}

// AppliedMigration is one database-recorded migration history entry.
type AppliedMigration struct {
	Version            int64
	Name               string
	Checksum           string
	CompatibilityFloor int64
	Status             string
}

// Snapshot is the read-only evidence used to classify a database schema.
type Snapshot struct {
	OwnedSchemaCount      int
	TrackingExists        bool
	BaseObjectsPresent    bool
	CurrentObjectsPresent bool
	Records               []AppliedMigration
}

const controlPlaneSchemaVersion int64 = 2

// SchemaState contains a content-free classification and highest version.
type SchemaState struct {
	Classification Classification
	Version        int64
}

// Ready succeeds only for a schema compatible with this binary.
func (s SchemaState) Ready() error {
	if s.Classification != Compatible {
		return fmt.Errorf("PostgreSQL schema is %s; run the documented administrative recovery action", s.Classification)
	}
	return nil
}

// Classify deterministically compares a database snapshot with a manifest.
func Classify(snapshot Snapshot, manifest Manifest) SchemaState {
	if manifest.Validate() != nil {
		return SchemaState{Classification: Incompatible}
	}
	if !snapshot.TrackingExists {
		if snapshot.OwnedSchemaCount == 0 {
			return SchemaState{Classification: Pristine}
		}
		return SchemaState{Classification: Incompatible}
	}
	if len(snapshot.Records) == 0 {
		return SchemaState{Classification: Incompatible}
	}
	records := append([]AppliedMigration(nil), snapshot.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].Version < records[j].Version })
	for i, record := range records {
		version := int64(i + 1)
		if record.Version != version {
			return SchemaState{Classification: Incompatible, Version: records[len(records)-1].Version}
		}
		if record.Status == "applying" {
			return SchemaState{Classification: Dirty, Version: record.Version}
		}
		if record.Status != "applied" || record.CompatibilityFloor < 1 || record.CompatibilityFloor > record.Version {
			return SchemaState{Classification: Incompatible, Version: record.Version}
		}
		if record.Version <= int64(len(manifest.Migrations)) {
			known := manifest.Migrations[record.Version-1]
			if record.Name != known.Name || record.Checksum != known.Checksum || record.CompatibilityFloor != known.CompatibilityFloor {
				return SchemaState{Classification: Incompatible, Version: record.Version}
			}
		}
	}
	if snapshot.OwnedSchemaCount != 6 || !snapshot.BaseObjectsPresent {
		return SchemaState{Classification: Incompatible}
	}
	version := records[len(records)-1].Version
	switch {
	case version > manifest.MaxSupported:
		return SchemaState{Classification: Newer, Version: version}
	case version < manifest.MinSupported:
		return SchemaState{Classification: UpgradeRequired, Version: version}
	case version >= controlPlaneSchemaVersion && !snapshot.CurrentObjectsPresent:
		return SchemaState{Classification: Incompatible, Version: version}
	default:
		return SchemaState{Classification: Compatible, Version: version}
	}
}
