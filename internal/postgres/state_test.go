package postgres

import "testing"

func TestClassifySchemaState(t *testing.T) {
	manifest := Manifest{
		MinSupported: 2,
		MaxSupported: 3,
		Migrations: []Migration{
			{Version: 1, Name: "bootstrap", Checksum: "one", CompatibilityFloor: 1},
			{Version: 2, Name: "second", Checksum: "two", CompatibilityFloor: 2},
			{Version: 3, Name: "third", Checksum: "three", CompatibilityFloor: 2},
		},
	}
	applied := func(version int64, name, checksum string, floor int64) AppliedMigration {
		return AppliedMigration{Version: version, Name: name, Checksum: checksum, CompatibilityFloor: floor, Status: "applied"}
	}
	tracked := func(records ...AppliedMigration) Snapshot {
		return Snapshot{OwnedSchemaCount: 6, TrackingExists: true, BaseObjectsPresent: true, CurrentObjectsPresent: true, Records: records}
	}
	tests := []struct {
		name     string
		snapshot Snapshot
		want     Classification
	}{
		{name: "pristine", snapshot: Snapshot{}, want: Pristine},
		{name: "partial bootstrap", snapshot: Snapshot{OwnedSchemaCount: 1}, want: Incompatible},
		{name: "empty tracker", snapshot: Snapshot{OwnedSchemaCount: 6, TrackingExists: true, BaseObjectsPresent: true, CurrentObjectsPresent: true}, want: Incompatible},
		{name: "missing required schema", snapshot: Snapshot{OwnedSchemaCount: 5, TrackingExists: true, BaseObjectsPresent: true, CurrentObjectsPresent: true, Records: []AppliedMigration{applied(1, "bootstrap", "one", 1)}}, want: Incompatible},
		{name: "missing required object", snapshot: Snapshot{OwnedSchemaCount: 6, TrackingExists: true, Records: []AppliedMigration{applied(1, "bootstrap", "one", 1)}}, want: Incompatible},
		{name: "upgrade required without future objects", snapshot: Snapshot{OwnedSchemaCount: 6, TrackingExists: true, BaseObjectsPresent: true, Records: []AppliedMigration{applied(1, "bootstrap", "one", 1)}}, want: UpgradeRequired},
		{name: "compatible", snapshot: tracked(applied(1, "bootstrap", "one", 1), applied(2, "second", "two", 2)), want: Compatible},
		{name: "compatible history missing current object", snapshot: Snapshot{OwnedSchemaCount: 6, TrackingExists: true, BaseObjectsPresent: true, Records: []AppliedMigration{applied(1, "bootstrap", "one", 1), applied(2, "second", "two", 2)}}, want: Incompatible},
		{name: "compatible latest", snapshot: tracked(applied(1, "bootstrap", "one", 1), applied(2, "second", "two", 2), applied(3, "third", "three", 2)), want: Compatible},
		{name: "newer", snapshot: tracked(applied(1, "bootstrap", "one", 1), applied(2, "second", "two", 2), applied(3, "third", "three", 2), applied(4, "future", "unknown", 3)), want: Newer},
		{name: "dirty", snapshot: tracked(AppliedMigration{Version: 1, Name: "bootstrap", Checksum: "one", CompatibilityFloor: 1, Status: "applying"}), want: Dirty},
		{name: "gap", snapshot: tracked(applied(2, "second", "two", 2)), want: Incompatible},
		{name: "checksum mismatch", snapshot: tracked(applied(1, "bootstrap", "tampered", 1)), want: Incompatible},
		{name: "name mismatch", snapshot: tracked(applied(1, "renamed", "one", 1)), want: Incompatible},
		{name: "floor mismatch", snapshot: tracked(applied(1, "bootstrap", "one", 9)), want: Incompatible},
		{name: "malformed status", snapshot: tracked(AppliedMigration{Version: 1, Name: "bootstrap", Checksum: "one", CompatibilityFloor: 1, Status: "mystery"}), want: Incompatible},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.snapshot, manifest); got.Classification != tt.want {
				t.Fatalf("Classify() = %s, want %s", got.Classification, tt.want)
			}
		})
	}
}

func TestManifestValidationRejectsMutableOrNonContiguousHistory(t *testing.T) {
	tests := []Manifest{
		{},
		{MinSupported: 1, MaxSupported: 1, Migrations: []Migration{{Version: 2, Name: "bad", Checksum: "x", CompatibilityFloor: 1}}},
		{MinSupported: 1, MaxSupported: 1, Migrations: []Migration{{Version: 1, Name: "", Checksum: "x", CompatibilityFloor: 1}}},
		{MinSupported: 1, MaxSupported: 1, Migrations: []Migration{{Version: 1, Name: "bad", Checksum: "", CompatibilityFloor: 1}}},
		{MinSupported: 2, MaxSupported: 1, Migrations: []Migration{{Version: 1, Name: "bad", Checksum: "x", CompatibilityFloor: 1}}},
	}
	for i, manifest := range tests {
		if err := manifest.Validate(); err == nil {
			t.Errorf("case %d: Validate() succeeded, want error", i)
		}
	}
}

func TestCurrentManifestRequiresControlPlaneSchema(t *testing.T) {
	manifest := CurrentManifest()
	if manifest.MinSupported != 10 || manifest.MaxSupported != 14 || len(manifest.Migrations) != 14 {
		t.Fatalf("manifest=%#v, want exact v10-v14 compatibility window", manifest)
	}
	for index, migration := range manifest.Migrations {
		want := int64(index + 1)
		switch want {
		case 9:
			want = 8
		case 10:
			want = 9
		case 11:
			want = 10
		case 12, 13:
			want = 10
		case 14:
			want = 10
		}
		if migration.CompatibilityFloor != want {
			t.Fatalf("migration %d floor=%d, want %d", index+1, migration.CompatibilityFloor, want)
		}
	}
}

func TestCompatibleSchemaCanStillHavePendingMigrations(t *testing.T) {
	manifest := CurrentManifest()
	if !migrationPending(SchemaState{Classification: Compatible, Version: 9}, manifest) {
		t.Fatal("compatible v9 schema must still apply the pending v10 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 10}, manifest) {
		t.Fatal("compatible v10 schema must still apply the pending v11 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 11}, manifest) {
		t.Fatal("compatible v11 schema must still apply the pending v12 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 12}, manifest) {
		t.Fatal("compatible v12 schema must still apply the pending v13 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 13}, manifest) {
		t.Fatal("compatible v13 schema must still apply the pending v14 migration")
	}
	if migrationPending(SchemaState{Classification: Compatible, Version: 14}, manifest) {
		t.Fatal("current v14 schema reported a pending migration")
	}
}
