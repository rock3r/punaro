package postgres

import (
	"strings"
	"testing"
)

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
	if manifest.MinSupported != 10 || manifest.MaxSupported != 58 || len(manifest.Migrations) != 58 {
		t.Fatalf("manifest=%#v, want exact v58 compatibility window", manifest)
	}
	embedding := manifest.Migrations[23]
	if embedding.Version != 24 || embedding.Name != "024_memory_embedding_worker_control" ||
		embedding.CompatibilityFloor != 10 || !strings.Contains(embedding.SQL, "CREATE FUNCTION brain.claim_embedding_jobs") {
		t.Fatalf("unexpected embedding-worker migration: %#v", embedding)
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
		case 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58:
			want = 10
		}
		if migration.CompatibilityFloor != want {
			t.Fatalf("migration %d floor=%d, want %d", index+1, migration.CompatibilityFloor, want)
		}
	}
}

func TestMemoryLexicalMigrationRefusesUnboundedInlineRewrite(t *testing.T) {
	migration := CurrentManifest().Migrations[18]
	for _, required := range []string{
		"FOR document_bytes IN",
		"octet_length(document::text)",
		"existing_revisions > 100000",
		"existing_document_bytes > 268435456",
		"ERRCODE = '54000'",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Fatalf("lexical migration missing inline-rewrite ceiling %q", required)
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
	if !migrationPending(SchemaState{Classification: Compatible, Version: 14}, manifest) {
		t.Fatal("compatible v14 schema must still apply the pending v15 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 15}, manifest) {
		t.Fatal("compatible v15 schema must still apply the pending v16 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 16}, manifest) {
		t.Fatal("compatible v16 schema must still apply the pending v17 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 17}, manifest) {
		t.Fatal("compatible v17 schema must still apply the pending v18 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 18}, manifest) {
		t.Fatal("compatible v18 schema must still apply the pending v19 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 19}, manifest) {
		t.Fatal("compatible v19 schema must still apply the pending v20 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 20}, manifest) {
		t.Fatal("compatible v20 schema must still apply the pending v21 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 21}, manifest) {
		t.Fatal("compatible v21 schema must still apply the pending v22 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 22}, manifest) {
		t.Fatal("compatible v22 schema must still apply the pending v23 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 23}, manifest) {
		t.Fatal("compatible v23 schema must still apply the pending v24 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 24}, manifest) {
		t.Fatal("compatible v24 schema must still apply the pending v25 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 25}, manifest) {
		t.Fatal("compatible v25 schema must still apply the pending v26 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 26}, manifest) {
		t.Fatal("compatible v26 schema must still apply the pending v27 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 27}, manifest) {
		t.Fatal("compatible v27 schema must still apply the pending v28 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 28}, manifest) {
		t.Fatal("compatible v28 schema must still apply the pending v29 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 29}, manifest) {
		t.Fatal("compatible v29 schema must still apply the pending v30 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 30}, manifest) {
		t.Fatal("compatible v30 schema must still apply the pending v31 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 31}, manifest) {
		t.Fatal("compatible v31 schema must still apply the pending v32 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 32}, manifest) {
		t.Fatal("compatible v32 schema must still apply pending migrations")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 34}, manifest) {
		t.Fatal("compatible v34 schema must still apply the pending v35 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 35}, manifest) {
		t.Fatal("compatible v35 schema must still apply the pending v36 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 36}, manifest) {
		t.Fatal("compatible v36 schema must still apply the pending v37 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 37}, manifest) {
		t.Fatal("compatible v37 schema must still apply the pending v38 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 38}, manifest) {
		t.Fatal("compatible v38 schema must still apply the pending v39 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 39}, manifest) {
		t.Fatal("compatible v39 schema must still apply the pending v40 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 41}, manifest) {
		t.Fatal("compatible v41 schema must still apply the pending v42 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 42}, manifest) {
		t.Fatal("compatible v42 schema must still apply the pending v43 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 43}, manifest) {
		t.Fatal("compatible v43 schema must still apply the pending v44 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 44}, manifest) {
		t.Fatal("compatible v44 schema must still apply the pending v45 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 45}, manifest) {
		t.Fatal("compatible v45 schema must still apply the pending v46 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 46}, manifest) {
		t.Fatal("compatible v46 schema must still apply the pending v47 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 47}, manifest) {
		t.Fatal("compatible v47 schema must still apply the pending v48 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 48}, manifest) {
		t.Fatal("compatible v48 schema must still apply the pending v49 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 49}, manifest) {
		t.Fatal("compatible v49 schema must still apply the pending v50 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 50}, manifest) {
		t.Fatal("compatible v50 schema must still apply the pending v51 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 51}, manifest) {
		t.Fatal("compatible v51 schema must still apply the pending v52 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 52}, manifest) {
		t.Fatal("compatible v52 schema must still apply the pending v53 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 53}, manifest) {
		t.Fatal("compatible v53 schema must still apply the pending v54 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 54}, manifest) {
		t.Fatal("compatible v54 schema must still apply the pending v55 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 55}, manifest) {
		t.Fatal("compatible v55 schema must still apply the pending v56 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 56}, manifest) {
		t.Fatal("compatible v56 schema must still apply the pending v57 migration")
	}
	if !migrationPending(SchemaState{Classification: Compatible, Version: 57}, manifest) {
		t.Fatal("compatible v57 schema must still apply the pending v58 migration")
	}
	if migrationPending(SchemaState{Classification: Compatible, Version: 58}, manifest) {
		t.Fatal("current v58 schema reported a pending migration")
	}
}
