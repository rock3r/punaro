package postgres

import (
	"errors"
	"testing"
)

func TestUpdateRequestValidation(t *testing.T) {
	valid := UpdateRequest{
		UpdateID:                "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		SourceRelease:           "v0.6.0",
		TargetRelease:           "v0.7.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SourceSchema:            6,
		TargetSchema:            7,
		SchemaMin:               6,
		SchemaMax:               7,
		RollbackFloor:           6,
		PostgresMajor:           17,
		ReleaseSHA256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ComposeSHA256:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		MigrationManifestSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*UpdateRequest){
		"invalid id":        func(r *UpdateRequest) { r.UpdateID = "not-a-uuid" },
		"same release":      func(r *UpdateRequest) { r.TargetRelease = r.SourceRelease },
		"unpinned target":   func(r *UpdateRequest) { r.TargetImage = "ghcr.io/rock3r/punaro:latest" },
		"schema downgrade":  func(r *UpdateRequest) { r.TargetSchema = r.SourceSchema - 1 },
		"postgres too old":  func(r *UpdateRequest) { r.PostgresMajor = 13 },
		"unbounded release": func(r *UpdateRequest) { r.TargetRelease = string(make([]byte, 129)) },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if request.Validate() == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestUpdatePhaseTransitionsAreFailClosed(t *testing.T) {
	allowed := []struct {
		from UpdatePhase
		to   UpdatePhase
	}{
		{UpdateFenced, UpdateWritersStopped},
		{UpdateWritersStopped, UpdateBackupVerified},
		{UpdateBackupVerified, UpdateMigrationStarted},
		{UpdateBackupVerified, UpdateAborted},
		{UpdateMigrationStarted, UpdateMigrated},
		{UpdateMigrated, UpdateCandidateReady},
		{UpdateCandidateReady, UpdateDoctorPassed},
		{UpdateDoctorPassed, UpdateConfigPublished},
		{UpdateConfigPublished, UpdateCommitted},
		{UpdateFenced, UpdateAborted},
		{UpdateWritersStopped, UpdateAborted},
		{UpdateMigrationStarted, UpdateRecoveryRequired},
		{UpdateMigrated, UpdateRecoveryRequired},
		{UpdateRecoveryRequired, UpdateRecoveryReady},
		{UpdateRecoveryReady, UpdateRecoveryDoctor},
		{UpdateRecoveryDoctor, UpdateRecoveryConfig},
		{UpdateRecoveryConfig, UpdateRecovered},
	}
	for _, transition := range allowed {
		if err := validateUpdateTransition(transition.from, transition.to); err != nil {
			t.Fatalf("transition %s -> %s rejected: %v", transition.from, transition.to, err)
		}
	}
	for _, transition := range [][2]UpdatePhase{
		{UpdateFenced, UpdateMigrationStarted},
		{UpdateMigrated, UpdateCommitted},
		{UpdateCommitted, UpdateFenced},
		{UpdateAborted, UpdateFenced},
		{"unknown", UpdateCommitted},
	} {
		if err := validateUpdateTransition(transition[0], transition[1]); !errors.Is(err, ErrInvalidUpdateTransition) {
			t.Fatalf("transition %s -> %s error=%v", transition[0], transition[1], err)
		}
	}
}

func TestBackupMarkerBindsExactUpdateBoundary(t *testing.T) {
	marker := UpdateBackupMarker{
		UpdateID:           "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		BackupID:           "019b4eb0-5317-79a6-a0de-fd97719910fb",
		InstallationID:     "4e02b0e5-1934-4dda-9c4a-767c120c2fac",
		TimelineID:         "797476ad-8fdc-4c05-b144-3ccbb92b54bf",
		ChangeSequence:     42,
		SourceSchema:       6,
		TargetRelease:      "v0.7.0",
		TargetImageDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExportedSnapshotID: "00000003-0000001B-1",
		ManifestSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if err := marker.Validate(); err != nil {
		t.Fatalf("valid marker rejected: %v", err)
	}
	marker.ChangeSequence = -1
	if marker.Validate() == nil {
		t.Fatal("negative backup boundary accepted")
	}
}

func TestOrdinaryMigratorNeverPerformsUpgrade(t *testing.T) {
	if migrationAuthorizationRequired(SchemaState{Classification: Pristine}) {
		t.Fatal("pristine initialization unexpectedly requires update authorization")
	}
	if !migrationAuthorizationRequired(SchemaState{Classification: UpgradeRequired, Version: 5}) {
		t.Fatal("existing schema upgrade did not require update authorization")
	}
	if migrationAuthorizationRequired(SchemaState{Classification: Compatible, Version: 6}) {
		t.Fatal("compatible no-op migration unexpectedly requires authorization")
	}
}

func TestUpdateMigrationAuthorizationValidation(t *testing.T) {
	valid := UpdateMigrationAuthorization{
		UpdateID:           "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		BackupID:           "019b4eb0-5317-79a6-a0de-fd97719910fb",
		TargetRelease:      "v0.7.0",
		TargetImage:        "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TargetSchema:       6,
		ExportedSnapshotID: "00000003-0000001B-1",
		ManifestSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid migration authorization rejected: %v", err)
	}
	valid.BackupID = "invalid"
	if valid.Validate() == nil {
		t.Fatal("invalid migration authorization accepted")
	}
}

func TestAdministrationAllowsOnlyExactActiveBridge(t *testing.T) {
	if !administrationSchemaAllowed(SchemaState{Classification: Compatible, Version: 6}, false, false) {
		t.Fatal("compatible administration rejected")
	}
	bridge := SchemaState{Classification: UpgradeRequired, Version: 5}
	if !administrationSchemaAllowed(bridge, true, true) {
		t.Fatal("active exact bridge rejected")
	}
	if administrationSchemaAllowed(bridge, false, true) || administrationSchemaAllowed(bridge, true, false) {
		t.Fatal("incomplete bridge evidence accepted")
	}
}
