package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/secretguard"
)

func testCanonicalBrainSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name    string
		apply   string
		restore string
	}{
		{
			name:    "memory table ownership",
			apply:   `ALTER TABLE brain.memory_tombstones OWNER TO punaro_app`,
			restore: `ALTER TABLE brain.memory_tombstones OWNER TO punaro_owner; REVOKE ALL ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory change delete privilege",
			apply:   `GRANT DELETE ON brain.memory_changes TO punaro_app`,
			restore: `REVOKE DELETE ON brain.memory_changes FROM punaro_app`,
		},
		{
			name:    "memory scope maintain privilege",
			apply:   `GRANT MAINTAIN ON brain.scopes TO punaro_app`,
			restore: `REVOKE MAINTAIN ON brain.scopes FROM punaro_app`,
		},
		{
			name:    "memory scope missing insert privilege",
			apply:   `REVOKE INSERT ON brain.scopes FROM punaro_app`,
			restore: `GRANT INSERT ON brain.scopes TO punaro_app`,
		},
		{
			name:    "memory revision column update privilege",
			apply:   `GRANT UPDATE (document) ON brain.memory_revisions TO punaro_app`,
			restore: `REVOKE UPDATE (document) ON brain.memory_revisions FROM punaro_app`,
		},
		{
			name:    "memory change column references privilege",
			apply:   `GRANT REFERENCES (scope_id) ON brain.memory_changes TO punaro_app`,
			restore: `REVOKE REFERENCES (scope_id) ON brain.memory_changes FROM punaro_app`,
		},
		{
			name:    "memory tombstone read privilege",
			apply:   `GRANT SELECT ON brain.memory_tombstones TO punaro_app`,
			restore: `REVOKE SELECT ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory tombstone public read privilege",
			apply:   `GRANT SELECT ON brain.memory_tombstones TO PUBLIC`,
			restore: `REVOKE SELECT ON brain.memory_tombstones FROM PUBLIC`,
		},
		{
			name:    "memory tombstone insert privilege",
			apply:   `GRANT INSERT ON brain.memory_tombstones TO punaro_app`,
			restore: `REVOKE INSERT ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory scope select grant option",
			apply:   `GRANT SELECT ON brain.scopes TO punaro_app WITH GRANT OPTION`,
			restore: `REVOKE GRANT OPTION FOR SELECT ON brain.scopes FROM punaro_app`,
		},
		{
			name:    "memory mutation fence",
			apply:   `ALTER TABLE brain.memory_items DISABLE TRIGGER application_mutation_fence`,
			restore: `ALTER TABLE brain.memory_items ENABLE TRIGGER application_mutation_fence`,
		},
		{
			name:    "memory scope state index",
			apply:   `DROP INDEX brain.memory_items_scope_state`,
			restore: `CREATE INDEX memory_items_scope_state ON brain.memory_items (scope_id,state,id)`,
		},
		{
			name:    "memory purge public execute",
			apply:   `GRANT EXECUTE ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) TO PUBLIC`,
			restore: `REVOKE EXECUTE ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) FROM PUBLIC`,
		},
		{
			name:    "memory state constraint",
			apply:   `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_state_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_state_check CHECK (state IS NOT NULL)`,
			restore: `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_state_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_state_check CHECK (state IN ('active','archived'))`,
		},
		{
			name:    "memory document constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_document_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_document_check CHECK (jsonb_typeof(document) IS NOT NULL)`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_document_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_document_check CHECK (jsonb_typeof(document)='object' AND octet_length(document::text)<=262144)`,
		},
		{
			name:    "memory hash constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_content_sha256_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_content_sha256_check CHECK (octet_length(content_sha256)>=1)`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_content_sha256_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_content_sha256_check CHECK (octet_length(content_sha256)=32)`,
		},
		{
			name:    "memory operation constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_operation_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_operation_check CHECK (operation IN ('create','evidence_create','update','archive','restore','unexpected'))`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_operation_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_operation_check CHECK (operation IN ('create','evidence_create','update','archive','restore'))`,
		},
		{
			name:    "memory scope foreign key",
			apply:   `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_scope_id_fkey; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES relay.projects(id)`,
			restore: `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_scope_id_fkey; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES brain.scopes(id)`,
		},
	} {
		t.Run("readiness rejects "+drift.name+" drift", func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			driftErr := app.Ready(ctx)
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatal(err)
			}
			if driftErr == nil {
				t.Fatalf("readiness accepted %s drift", drift.name)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover after %s drift: %v", drift.name, err)
			}
		})
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_logical_key_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_logical_key_check CHECK (logical_key IS NULL OR (char_length(logical_key) >= 1 AND char_length(logical_key) <= 128 AND octet_length(logical_key) <= 512 AND logical_key !~ '[[:cntrl:]]'))`); err != nil {
		t.Fatal(err)
	}
	restoredConstraintErr := app.Ready(ctx)
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_logical_key_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_logical_key_check CHECK (logical_key IS NULL OR (char_length(logical_key) BETWEEN 1 AND 128 AND octet_length(logical_key) <= 512 AND logical_key !~ '[[:cntrl:]]'))`); err != nil {
		t.Fatal(err)
	}
	if restoredConstraintErr != nil {
		t.Fatalf("readiness rejected dump/restore-normalized logical-key constraint: %v", restoredConstraintErr)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after logical-key constraint restoration: %v", err)
	}
	var purgeDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('brain.purge_memory(uuid,uuid,uuid,bigint)'::regprocedure)`).Scan(&purgeDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION brain.purge_memory(
requested_principal uuid, requested_project uuid, requested_item uuid, expected_revision bigint
) RETURNS TABLE (scope_id uuid,revision bigint,timeline_id uuid,change_sequence bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $function$ BEGIN RETURN; END $function$`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted replacement memory purge routine")
	}
	if _, err := ownerDB.ExecContext(ctx, purgeDefinition); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after memory purge routine restoration: %v", err)
	}
}

func testMemoryEvidenceSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"source public read", `GRANT SELECT ON brain.memory_sources TO PUBLIC`, `REVOKE SELECT ON brain.memory_sources FROM PUBLIC`},
		{"edge delete", `GRANT DELETE ON brain.memory_edges TO punaro_app`, `REVOKE DELETE ON brain.memory_edges FROM punaro_app`},
		{"source fence", `ALTER TABLE brain.memory_sources DISABLE TRIGGER application_mutation_fence`, `ALTER TABLE brain.memory_sources ENABLE TRIGGER application_mutation_fence`},
		{"source row security", `ALTER TABLE brain.memory_sources ENABLE ROW LEVEL SECURITY`, `ALTER TABLE brain.memory_sources DISABLE ROW LEVEL SECURITY`},
		{"source index", `DROP INDEX brain.memory_sources_live_resource`, `CREATE INDEX memory_sources_live_resource ON brain.memory_sources (source_project_id,kind,source_resource_id,source_revision) WHERE mode='live'`},
		{"layer constraint", `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_layer_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_layer_check CHECK (layer IS NOT NULL)`, `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_layer_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_layer_check CHECK (layer IN ('curated','evidence'))`},
		{"source shape constraint", `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_shape_check; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_shape_check CHECK (mode IS NOT NULL)`, `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_shape_check; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_shape_check CHECK ((mode='copied' AND source_project_id IS NULL AND source_resource_id IS NULL AND source_revision IS NULL AND reference_sha256 IS NOT NULL) OR (mode='live' AND source_project_id IS NOT NULL AND source_resource_id IS NOT NULL AND reference_sha256 IS NULL AND ((kind='memory' AND source_revision IS NOT NULL) OR (kind IN ('message','attachment') AND source_revision IS NULL))))`},
		{"source project FK action", `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_source_project_id_fkey; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_source_project_id_fkey FOREIGN KEY (source_project_id) REFERENCES relay.projects(id) ON DELETE CASCADE`, `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_source_project_id_fkey; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_source_project_id_fkey FOREIGN KEY (source_project_id) REFERENCES relay.projects(id)`},
		{"source project FK update", `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_source_project_id_fkey; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_source_project_id_fkey FOREIGN KEY (source_project_id) REFERENCES relay.projects(id) ON UPDATE CASCADE`, `ALTER TABLE brain.memory_sources DROP CONSTRAINT memory_sources_source_project_id_fkey; ALTER TABLE brain.memory_sources ADD CONSTRAINT memory_sources_source_project_id_fkey FOREIGN KEY (source_project_id) REFERENCES relay.projects(id)`},
		{"edge target FK action", `ALTER TABLE brain.memory_edges DROP CONSTRAINT memory_edges_to_revision_fkey; ALTER TABLE brain.memory_edges ADD CONSTRAINT memory_edges_to_revision_fkey FOREIGN KEY (to_item_id,to_revision) REFERENCES brain.memory_revisions(item_id,revision)`, `ALTER TABLE brain.memory_edges DROP CONSTRAINT memory_edges_to_revision_fkey; ALTER TABLE brain.memory_edges ADD CONSTRAINT memory_edges_to_revision_fkey FOREIGN KEY (to_item_id,to_revision) REFERENCES brain.memory_revisions(item_id,revision) ON DELETE CASCADE`},
	} {
		t.Run("evidence "+drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatal("readiness accepted memory-evidence drift")
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatalf("restore memory-evidence drift: %v", err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover: %v", err)
			}
		})
	}
}

func testMemoryEvidenceIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "evidence actor")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "evidence reader")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "evidence outsider")
	if err != nil {
		t.Fatal(err)
	}
	var targetProject, sourceProject, otherProject string
	for name, destination := range map[string]*string{"evidence target": &targetProject, "evidence source": &sourceProject, "evidence other": &otherProject} {
		if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ($1,$2) RETURNING id::text`, name, actor.ID).Scan(destination); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []struct {
		principal, project string
		capability         Capability
	}{
		{actor.ID, targetProject, CapabilityMemoryRead}, {actor.ID, targetProject, CapabilityMemoryWrite}, {actor.ID, targetProject, CapabilityMemoryPurge},
		{actor.ID, targetProject, CapabilityMemoryAdminister},
		{actor.ID, sourceProject, CapabilityMemoryRead}, {actor.ID, sourceProject, CapabilityMemoryWrite},
		{actor.ID, sourceProject, CapabilityMemoryPurge},
		{actor.ID, sourceProject, CapabilityConversationReceive}, {actor.ID, sourceProject, CapabilityAttachmentDownload},
		{actor.ID, otherProject, CapabilityMemoryRead}, {actor.ID, otherProject, CapabilityMemoryWrite},
		{reader.ID, targetProject, CapabilityMemoryRead}, {reader.ID, sourceProject, CapabilityMemoryRead},
		{reader.ID, sourceProject, CapabilityConversationReceive}, {reader.ID, sourceProject, CapabilityAttachmentDownload},
		{outsider.ID, targetProject, CapabilityMemoryRead}, {outsider.ID, targetProject, CapabilityMemoryWrite},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, grant.principal, grant.project, grant.capability); err != nil {
			t.Fatal(err)
		}
	}
	target, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: targetProject, IdempotencyKey: "17171717-1717-4717-8717-171717171701",
		LogicalKey: "evidence.target", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"status":"accepted"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherMemory, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: otherProject, IdempotencyKey: "17171717-1717-4717-8717-171717171709",
		LogicalKey: "evidence.other", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"status":"other"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceMemory, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: sourceProject, IdempotencyKey: "17171717-1717-4717-8717-171717171702",
		LogicalKey: "evidence.source", Kind: "observation", Trust: "observed", Document: json.RawMessage(`{"fact":"bounded"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var timelineID string
	if err := ownerDB.QueryRowContext(ctx, `SELECT timeline_id::text FROM jobs.server_state WHERE singleton`).Scan(&timelineID); err != nil {
		t.Fatal(err)
	}
	actorEndpoint, readerEndpoint := "agent/evidence/actor", "agent/evidence/reader"
	actorLookup, readerLookup := "17171717-1717-4717-8717-171717171711", "17171717-1717-4717-8717-171717171712"
	for _, endpoint := range []struct{ name, principal, lookup, digest string }{
		{actorEndpoint, actor.ID, actorLookup, strings.Repeat("11", 32)},
		{readerEndpoint, reader.ID, readerLookup, strings.Repeat("22", 32)},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.device_credentials(lookup_id,principal_id,label,secret_digest) VALUES ($1,$2,$3,decode($4,'hex'))`, endpoint.lookup, endpoint.principal, endpoint.name, endpoint.digest); err != nil {
			t.Fatal(err)
		}
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.mail_endpoints(endpoint,machine_id,lease_until) VALUES ($1,$2,statement_timestamp()+interval '1 day')`, endpoint.name, endpoint.name); err != nil {
			t.Fatal(err)
		}
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.endpoint_principals(endpoint,machine_id,principal_id,credential_lookup_id,credential_generation,ownership_generation) VALUES ($1,$2,$3,$4,1,1)`, endpoint.name, endpoint.name, endpoint.principal, endpoint.lookup); err != nil {
			t.Fatal(err)
		}
	}
	var conversationID, messageID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.mail_conversations(next_sequence) VALUES (1) RETURNING id::text`).Scan(&conversationID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities) VALUES ($1,$2,7),($1,$3,7)`, conversationID, actorEndpoint, readerEndpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.conversation_projects(conversation_id,project_id,bound_by) VALUES ($1,$2,$3)`, conversationID, sourceProject, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.mail_messages(conversation_id,sequence,from_endpoint,body,created_at) VALUES ($1,1,$2,'bounded message',statement_timestamp()) RETURNING id::text`, conversationID, actorEndpoint).Scan(&messageID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint) VALUES ($1,$2)`, messageID, readerEndpoint); err != nil {
		t.Fatal(err)
	}
	artifactID := "17171717-1717-4717-8717-171717171720"
	artifactSHA := strings.Repeat("33", 32)
	storagePath := "ready/" + artifactID + ".blob"
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.ready_blob_manifest(storage_path,size_bytes,sha256) VALUES ($1,7,$2)`, storagePath, artifactSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.uploads(artifact_id,project_id,principal_id,timeline_id,idempotency_key,request_sha256,size_bytes,sha256,display_name,media_type,state,expires_at,ready_at)
VALUES ($1,$2,$3,$4,$5,$6,7,$6,'evidence.txt','text/plain','ready',statement_timestamp()+interval '1 day',statement_timestamp())`, artifactID, sourceProject, actor.ID, timelineID, "17171717-1717-4717-8717-171717171721", artifactSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.ready_artifacts(artifact_id,storage_path) VALUES ($1,$2)`, artifactID, storagePath); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.message_artifacts(message_id,ordinal,artifact_id,sender_principal_id) VALUES ($1,0,$2,$3)`, messageID, artifactID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.recipient_grants(artifact_id,recipient_principal_id,message_id) VALUES ($1,$2,$3)`, artifactID, reader.ID, messageID); err != nil {
		t.Fatal(err)
	}
	readEffects := func() [7]int64 {
		var effects [7]int64
		if err := ownerDB.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM brain.memory_items),(SELECT count(*) FROM brain.memory_revisions),
(SELECT count(*) FROM brain.memory_sources),(SELECT count(*) FROM brain.memory_edges),
(SELECT count(*) FROM relay.idempotency_records),(SELECT change_sequence FROM jobs.server_state WHERE singleton),
(SELECT sum(content_generation) FROM relay.projects)`).Scan(&effects[0], &effects[1], &effects[2], &effects[3], &effects[4], &effects[5], &effects[6]); err != nil {
			t.Fatal(err)
		}
		return effects
	}
	assertRejectedAtomically := func(name string, rejected MemoryEvidenceCreateRequest) {
		t.Helper()
		before := readEffects()
		if _, err := app.CreateMemoryEvidence(ctx, rejected); err == nil {
			t.Fatalf("%s evidence unexpectedly created", name)
		}
		if after := readEffects(); after != before {
			t.Fatalf("%s rejection changed state: before=%v after=%v", name, before, after)
		}
	}
	baseRejected := MemoryEvidenceCreateRequest{
		PrincipalID: actor.ID, ProjectID: targetProject, LogicalKey: "evidence.rejected", Kind: "evidence.excerpt", Trust: "observed",
		Document: json.RawMessage(`{"excerpt":"bounded"}`),
	}
	for index, source := range []MemoryEvidenceSourceInput{
		{Mode: MemorySourceLive, Kind: MemorySourceMessage, ProjectID: sourceProject, ResourceID: "17171717-1717-4717-8717-171717171731"},
		{Mode: MemorySourceLive, Kind: MemorySourceAttachment, ProjectID: sourceProject, ResourceID: "17171717-1717-4717-8717-171717171732"},
		{Mode: MemorySourceLive, Kind: MemorySourceMemory, ProjectID: sourceProject, ResourceID: sourceMemory.ItemID, ResourceRevision: sourceMemory.Revision + 1},
	} {
		rejected := baseRejected
		rejected.IdempotencyKey = []string{"17171717-1717-4717-8717-171717171733", "17171717-1717-4717-8717-171717171734", "17171717-1717-4717-8717-171717171735"}[index]
		rejected.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("55", 32)}, source}
		assertRejectedAtomically("missing "+string(source.Kind), rejected)
	}
	crossProject := baseRejected
	crossProject.IdempotencyKey = "17171717-1717-4717-8717-171717171736"
	crossProject.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("56", 32)}}
	crossProject.Claims = []MemoryEvidenceClaimInput{{Type: MemoryEdgeSupports, TargetItemID: otherMemory.ItemID, TargetRevision: otherMemory.Revision}}
	assertRejectedAtomically("cross-project claim", crossProject)
	missingClaim := baseRejected
	missingClaim.IdempotencyKey = "17171717-1717-4717-8717-171717171740"
	missingClaim.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("58", 32)}}
	missingClaim.Claims = []MemoryEvidenceClaimInput{{Type: MemoryEdgeSupports, TargetItemID: "17171717-1717-4717-8717-171717171741", TargetRevision: 1}}
	assertRejectedAtomically("missing claim", missingClaim)
	claimQuarantineFingerprint := strings.Repeat("59", 32)
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_quarantines(item_id,detected_revision,rule_version,rule_id,field_path,value_fingerprint,quarantined_by)
VALUES ($1,$2,1,'sensitive-field','/status',decode($3,'hex'),$4)`, target.ItemID, target.Revision, claimQuarantineFingerprint, actor.ID); err != nil {
		t.Fatal(err)
	}
	quarantinedClaim := baseRejected
	quarantinedClaim.IdempotencyKey = "17171717-1717-4717-8717-171717171742"
	quarantinedClaim.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("5a", 32)}}
	quarantinedClaim.Claims = []MemoryEvidenceClaimInput{{Type: MemoryEdgeSupports, TargetItemID: target.ItemID, TargetRevision: target.Revision}}
	assertRejectedAtomically("quarantined claim", quarantinedClaim)
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp() WHERE item_id=$1 AND released_at IS NULL`, target.ItemID, actor.ID); err != nil {
		t.Fatal(err)
	}
	secretRejected := baseRejected
	secretRejected.IdempotencyKey = "17171717-1717-4717-8717-171717171737"
	secretRejected.Document = json.RawMessage(`{"token":"resolved-evidence-value-123"}`)
	secretRejected.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("57", 32)}}
	assertRejectedAtomically("guarded secret", secretRejected)
	revocationRequest := baseRejected
	revocationRequest.IdempotencyKey = "17171717-1717-4717-8717-171717171747"
	revocationRequest.Sources = []MemoryEvidenceSourceInput{{Mode: MemorySourceLive, Kind: MemorySourceMessage, ProjectID: sourceProject, ResourceID: messageID}}
	revocationTx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revocationTx.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='conversation.receive' AND revoked_at IS NULL`, actor.ID, sourceProject); err != nil {
		_ = revocationTx.Rollback()
		t.Fatal(err)
	}
	revocationBefore := readEffects()
	revocationDone := make(chan error, 1)
	go func() {
		_, createErr := app.CreateMemoryEvidence(ctx, revocationRequest)
		revocationDone <- createErr
	}()
	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'
  AND query LIKE 'SELECT capability_grant.id::text%FOR SHARE OF principal, capability_grant')`).Scan(&waiting); err != nil {
			_ = revocationTx.Rollback()
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case createErr := <-revocationDone:
			_ = revocationTx.Rollback()
			t.Fatalf("evidence create escaped grant revocation lock: %v", createErr)
		default:
		}
		if time.Now().After(waitDeadline) {
			_ = revocationTx.Rollback()
			t.Fatal("evidence create did not reach the grant revocation lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := revocationTx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case createErr := <-revocationDone:
		if !errors.Is(createErr, ErrNotFound) {
			t.Fatalf("post-revocation evidence create error=%v", createErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("evidence create remained blocked after grant revocation")
	}
	if after := readEffects(); after != revocationBefore {
		t.Fatalf("revocation-race rejection changed evidence state: before=%v after=%v", revocationBefore, after)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'conversation.receive')`, actor.ID, sourceProject); err != nil {
		t.Fatal(err)
	}
	request := MemoryEvidenceCreateRequest{
		PrincipalID: actor.ID, ProjectID: targetProject, IdempotencyKey: "17171717-1717-4717-8717-171717171703",
		LogicalKey: "evidence.release", Kind: "evidence.excerpt", Trust: "observed", Document: json.RawMessage(`{"excerpt":"bounded source fact"}`),
		Sources: []MemoryEvidenceSourceInput{
			{Mode: MemorySourceCopied, Kind: MemorySourceExternal, ReferenceSHA256: strings.Repeat("44", 32)},
			{Mode: MemorySourceLive, Kind: MemorySourceMessage, ProjectID: sourceProject, ResourceID: messageID},
			{Mode: MemorySourceLive, Kind: MemorySourceAttachment, ProjectID: sourceProject, ResourceID: artifactID},
			{Mode: MemorySourceLive, Kind: MemorySourceMemory, ProjectID: sourceProject, ResourceID: sourceMemory.ItemID, ResourceRevision: sourceMemory.Revision},
		},
		Claims: []MemoryEvidenceClaimInput{{Type: MemoryEdgeSupports, TargetItemID: target.ItemID, TargetRevision: target.Revision}},
	}
	created, err := app.CreateMemoryEvidence(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := app.CreateMemoryEvidence(ctx, request); err != nil || retry != created {
		t.Fatalf("evidence idempotent retry=%#v err=%v", retry, err)
	}
	changed := request
	changed.Document = json.RawMessage(`{"excerpt":"changed"}`)
	if _, err := app.CreateMemoryEvidence(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed evidence retry error=%v", err)
	}
	for name, principal := range map[string]string{"creator": actor.ID, "recipient": reader.ID} {
		got, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: principal, ProjectID: targetProject, ItemID: created.ItemID})
		if err != nil || got.Item.Layer != MemoryLayerEvidence || len(got.Sources) != 4 || len(got.Claims) != 1 {
			t.Fatalf("%s evidence=%#v err=%v", name, got, err)
		}
		for _, source := range got.Sources {
			if source.Redacted {
				t.Fatalf("%s source unexpectedly redacted: %#v", name, source)
			}
		}
	}
	sourceArchived, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{PrincipalID: actor.ID, ProjectID: sourceProject, ItemID: sourceMemory.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171738", ExpectedETag: sourceMemory.ETag, Archived: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID}); err != nil || got.Sources[3].Redacted {
		t.Fatalf("archived readable memory source=%#v err=%v", got, err)
	}
	sourceRestored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{PrincipalID: actor.ID, ProjectID: sourceProject, ItemID: sourceMemory.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171739", ExpectedETag: sourceArchived.ETag, Archived: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM attachment.recipient_grants WHERE artifact_id=$1 AND recipient_principal_id=$2`, artifactID, reader.ID); err != nil {
		t.Fatal(err)
	}
	recipientRedacted, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: reader.ID, ProjectID: targetProject, ItemID: created.ItemID})
	if err != nil || !recipientRedacted.Sources[2].Redacted || recipientRedacted.Sources[1].Redacted || recipientRedacted.Sources[3].Redacted {
		t.Fatalf("recipient-grant redaction=%#v err=%v", recipientRedacted, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.recipient_grants(artifact_id,recipient_principal_id,message_id) VALUES ($1,$2,$3)`, artifactID, reader.ID, messageID); err != nil {
		t.Fatal(err)
	}
	redacted, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: outsider.ID, ProjectID: targetProject, ItemID: created.ItemID})
	if err != nil || len(redacted.Sources) != 4 || redacted.Sources[0].Redacted {
		t.Fatalf("outsider evidence=%#v err=%v", redacted, err)
	}
	for _, source := range redacted.Sources[1:] {
		if !source.Redacted || source.Kind != "" || source.ProjectID != "" || source.ResourceID != "" {
			t.Fatalf("live source was not fully redacted: %#v", source)
		}
	}
	quarantineFingerprint := strings.Repeat("66", 32)
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_quarantines(item_id,detected_revision,rule_version,rule_id,field_path,value_fingerprint,quarantined_by)
VALUES ($1,$2,1,'sensitive-field','/fact',decode($3,'hex'),$4)`, sourceMemory.ItemID, sourceMemory.Revision, quarantineFingerprint, actor.ID); err != nil {
		t.Fatal(err)
	}
	sourceQuarantined, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID})
	if err != nil || !sourceQuarantined.Sources[3].Redacted || sourceQuarantined.Sources[1].Redacted || sourceQuarantined.Sources[2].Redacted {
		t.Fatalf("quarantined-source redaction=%#v err=%v", sourceQuarantined, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp() WHERE item_id=$1 AND released_at IS NULL`, sourceMemory.ItemID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{PrincipalID: actor.ID, ProjectID: sourceProject, ItemID: sourceMemory.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171743", ExpectedETag: sourceRestored.ETag}); err != nil {
		t.Fatal(err)
	}
	purgedSource, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID})
	if err != nil || !purgedSource.Sources[3].Redacted || purgedSource.Sources[1].Redacted || purgedSource.Sources[2].Redacted {
		t.Fatalf("purged-source redaction=%#v err=%v", purgedSource, err)
	}
	if item, err := app.GetMemory(ctx, actor.ID, targetProject, created.ItemID); err != nil || item.Layer != MemoryLayerEvidence {
		t.Fatalf("canonical evidence get=%#v err=%v", item, err)
	}
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171704",
		ExpectedETag: created.ETag, LogicalKey: "evidence.release", Kind: "evidence.excerpt", Trust: "observed", Document: json.RawMessage(`{"excerpt":"mutated"}`),
	}); !errors.Is(err, ErrImmutableMemoryEvidence) {
		t.Fatalf("ordinary evidence update error=%v", err)
	}
	archived, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171705", ExpectedETag: created.ETag, Archived: true})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171706", ExpectedETag: archived.ETag, Archived: false})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID}); err != nil || got.Item.Revision != restored.Revision || len(got.Sources) != 4 || len(got.Claims) != 1 {
		t.Fatalf("restored evidence=%#v err=%v", got, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_quarantines(item_id,detected_revision,rule_version,rule_id,field_path,value_fingerprint,quarantined_by)
VALUES ($1,$2,1,'sensitive-field','/excerpt',decode($3,'hex'),$4)`, created.ItemID, restored.Revision, quarantineFingerprint, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined evidence get error=%v", err)
	}
	review, err := app.ReviewMemorySecretQuarantine(ctx, actor.ID, targetProject, created.ItemID)
	if err != nil || review.Item.Layer != MemoryLayerEvidence {
		t.Fatalf("quarantined evidence review=%#v err=%v", review, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp() WHERE item_id=$1 AND released_at IS NULL`, created.ItemID, actor.ID); err != nil {
		t.Fatal(err)
	}
	unauthorizedWrite := request
	unauthorizedWrite.PrincipalID = reader.ID
	unauthorizedWrite.IdempotencyKey = "17171717-1717-4717-8717-171717171707"
	unauthorizedWrite.LogicalKey = "evidence.unauthorized-write"
	unauthorizedWrite.Claims = nil
	unauthorizedWrite.Sources = unauthorizedWrite.Sources[:1]
	assertRejectedAtomically("unauthorized target write", unauthorizedWrite)
	for index, source := range request.Sources[1:] {
		if source.Kind == MemorySourceMemory {
			source.ProjectID, source.ResourceID, source.ResourceRevision = otherProject, otherMemory.ItemID, otherMemory.Revision
		}
		unauthorized := request
		unauthorized.PrincipalID = outsider.ID
		unauthorized.IdempotencyKey = []string{"17171717-1717-4717-8717-171717171744", "17171717-1717-4717-8717-171717171745", "17171717-1717-4717-8717-171717171746"}[index]
		unauthorized.LogicalKey = "evidence.unauthorized-" + string(source.Kind)
		unauthorized.Claims = nil
		unauthorized.Sources = []MemoryEvidenceSourceInput{source}
		assertRejectedAtomically("unauthorized "+string(source.Kind), unauthorized)
	}
	for _, capability := range []Capability{CapabilityConversationReceive, CapabilityAttachmentDownload, CapabilityMemoryRead} {
		if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability=$3 AND revoked_at IS NULL`, reader.ID, sourceProject, capability); err != nil {
			t.Fatal(err)
		}
	}
	afterRevocation, err := app.GetMemoryEvidence(ctx, MemoryEvidenceGetRequest{PrincipalID: reader.ID, ProjectID: targetProject, ItemID: created.ItemID})
	if err != nil || afterRevocation.Sources[0].Redacted {
		t.Fatalf("post-revocation evidence=%#v err=%v", afterRevocation, err)
	}
	for _, source := range afterRevocation.Sources[1:] {
		if !source.Redacted {
			t.Fatalf("revoked source remained visible: %#v", source)
		}
	}
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{PrincipalID: actor.ID, ProjectID: targetProject, ItemID: created.ItemID, IdempotencyKey: "17171717-1717-4717-8717-171717171708", ExpectedETag: restored.ETag}); err != nil {
		t.Fatal(err)
	}
	var provenance int
	if err := ownerDB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM brain.memory_sources WHERE item_id=$1)+(SELECT count(*) FROM brain.memory_edges WHERE from_item_id=$1)`, created.ItemID).Scan(&provenance); err != nil || provenance != 0 {
		t.Fatalf("purged evidence provenance=%d err=%v", provenance, err)
	}
	var metadataLeaked bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM audit.events AS event WHERE event.target_id=$1 AND to_jsonb(event)::text LIKE '%bounded source fact%')
OR EXISTS (SELECT 1 FROM brain.memory_changes AS change WHERE change.item_id=$1 AND to_jsonb(change)::text LIKE '%bounded source fact%')
OR EXISTS (SELECT 1 FROM relay.idempotency_records WHERE resource_id=$1 AND result::text LIKE '%bounded source fact%')`, created.ItemID).Scan(&metadataLeaked); err != nil || metadataLeaked {
		t.Fatalf("evidence metadata leaked content=%v err=%v", metadataLeaked, err)
	}
}

func testSecretGuardSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"guard state owner", `ALTER TABLE brain.secret_guard_state OWNER TO punaro_app`, `ALTER TABLE brain.secret_guard_state OWNER TO punaro_owner; REVOKE ALL ON brain.secret_guard_state FROM punaro_app; GRANT SELECT ON brain.secret_guard_state TO punaro_app`},
		{"rule digest", `UPDATE brain.secret_guard_state SET rule_digest=decode(repeat('00',32),'hex') WHERE singleton`, `UPDATE brain.secret_guard_state SET rule_digest=decode('39fb102e3a58faf1e5b7d0045caed1c2110da2f622102c088aeef16f775dfa22','hex') WHERE singleton`},
		{"extra delete", `GRANT DELETE ON brain.secret_exceptions TO punaro_app`, `REVOKE DELETE ON brain.secret_exceptions FROM punaro_app`},
		{"extra column update", `GRANT UPDATE (rule_id) ON brain.secret_exceptions TO punaro_app`, `REVOKE UPDATE (rule_id) ON brain.secret_exceptions FROM punaro_app`},
		{"public select", `GRANT SELECT ON brain.secret_exceptions TO PUBLIC`, `REVOKE SELECT ON brain.secret_exceptions FROM PUBLIC`},
		{"grant option", `GRANT SELECT ON brain.secret_guard_state TO punaro_app WITH GRANT OPTION`, `REVOKE GRANT OPTION FOR SELECT ON brain.secret_guard_state FROM punaro_app`},
		{"disabled fence", `ALTER TABLE brain.secret_exceptions DISABLE TRIGGER application_mutation_fence`, `ALTER TABLE brain.secret_exceptions ENABLE TRIGGER application_mutation_fence`},
		{"row security", `ALTER TABLE brain.secret_exceptions ENABLE ROW LEVEL SECURITY`, `ALTER TABLE brain.secret_exceptions DISABLE ROW LEVEL SECURITY`},
		{"project FK update action", `ALTER TABLE brain.secret_exceptions DROP CONSTRAINT secret_exceptions_project_id_fkey; ALTER TABLE brain.secret_exceptions ADD CONSTRAINT secret_exceptions_project_id_fkey FOREIGN KEY (project_id) REFERENCES relay.projects(id) ON UPDATE CASCADE`, `ALTER TABLE brain.secret_exceptions DROP CONSTRAINT secret_exceptions_project_id_fkey; ALTER TABLE brain.secret_exceptions ADD CONSTRAINT secret_exceptions_project_id_fkey FOREIGN KEY (project_id) REFERENCES relay.projects(id)`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatal("readiness accepted secret-guard drift")
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatalf("restore secret-guard drift: %v", err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover: %v", err)
			}
		})
	}
}

func testMemoryQuarantineSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"extra delete", `GRANT DELETE ON brain.memory_quarantines TO punaro_app`, `REVOKE DELETE ON brain.memory_quarantines FROM punaro_app`},
		{"disabled fence", `ALTER TABLE brain.memory_secret_scans DISABLE TRIGGER application_mutation_fence`, `ALTER TABLE brain.memory_secret_scans ENABLE TRIGGER application_mutation_fence`},
		{"missing history index", `DROP INDEX brain.memory_quarantines_item_history`, `CREATE INDEX memory_quarantines_item_history ON brain.memory_quarantines (item_id, quarantined_at, id)`},
		{"unexpected column", `ALTER TABLE brain.secret_project_state ADD COLUMN unsafe text`, `ALTER TABLE brain.secret_project_state DROP COLUMN unsafe`},
		{"row security", `ALTER TABLE brain.memory_quarantines ENABLE ROW LEVEL SECURITY`, `ALTER TABLE brain.memory_quarantines DISABLE ROW LEVEL SECURITY`},
		{"scan primary key", `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_pkey; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_pkey UNIQUE (item_id,revision)`, `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_pkey; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_pkey PRIMARY KEY (item_id)`},
		{"released principal FK action", `ALTER TABLE brain.memory_quarantines DROP CONSTRAINT memory_quarantines_released_by_fkey; ALTER TABLE brain.memory_quarantines ADD CONSTRAINT memory_quarantines_released_by_fkey FOREIGN KEY (released_by) REFERENCES auth.principals(id) ON UPDATE CASCADE`, `ALTER TABLE brain.memory_quarantines DROP CONSTRAINT memory_quarantines_released_by_fkey; ALTER TABLE brain.memory_quarantines ADD CONSTRAINT memory_quarantines_released_by_fkey FOREIGN KEY (released_by) REFERENCES auth.principals(id)`},
		{"permissive scan generation", `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_generation_check; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_generation_check CHECK (exception_generation >= 0 OR true)`, `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_generation_check; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_generation_check CHECK (exception_generation >= 0)`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatal("readiness accepted memory-quarantine drift")
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatalf("restore memory-quarantine drift: %v", err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover: %v", err)
			}
		})
	}
}

func testCanonicalBrainIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory actor")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory reader")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory outsider")
	if err != nil {
		t.Fatal(err)
	}
	var projectID, otherProjectID, retiredProjectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('brain project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('other brain project',$1) RETURNING id::text`, actor.ID).Scan(&otherProjectID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by,merged_into,merged_at) VALUES ('retired brain project',$1,$2,statement_timestamp()) RETURNING id::text`, actor.ID, projectID).Scan(&retiredProjectID); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		principal  string
		project    string
		capability Capability
	}{
		{actor.ID, projectID, CapabilityMemoryRead},
		{actor.ID, projectID, CapabilityMemoryWrite},
		{actor.ID, projectID, CapabilityMemoryPurge},
		{actor.ID, projectID, CapabilityMemoryAdminister},
		{reader.ID, projectID, CapabilityMemoryRead},
		{reader.ID, projectID, CapabilityMemoryWrite},
		{actor.ID, otherProjectID, CapabilityMemoryRead},
		{actor.ID, otherProjectID, CapabilityMemoryWrite},
		{actor.ID, otherProjectID, CapabilityMemoryAdminister},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, grant.principal, grant.project, grant.capability); err != nil {
			t.Fatal(err)
		}
	}
	allProjectsReader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "all-project memory reader")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,capability) VALUES ($1,'all_projects','memory.read')`, allProjectsReader.ID); err != nil {
		t.Fatal(err)
	}
	start, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secretDocument := json.RawMessage(`{"token":"resolved-value-123"}`)
	secretCreate := MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: projectID,
		IdempotencyKey: "15151515-1515-4515-8515-151515151501",
		Kind:           "preference", Trust: "curated", Document: secretDocument,
	}
	beforeSecretRejection := readSecretGuardEffects(ctx, t, ownerDB)
	_, err = app.CreateMemory(ctx, secretCreate)
	var rejection MemorySecretRejection
	if !errors.As(err, &rejection) || rejection.Finding.RuleID != secretguard.RuleSensitiveField || rejection.Finding.FieldPath != "/token" || strings.Contains(err.Error(), "resolved-value-123") {
		t.Fatalf("secret create rejection=%#v err=%v", rejection, err)
	}
	sensitiveFinding := rejection.Finding
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("rejected secret create effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	otherProjectException, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: otherProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151513",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !otherProjectException.Active {
		t.Fatalf("approve other-project exception: %v", err)
	}
	var exceptionOnlyProjectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('exception-only brain project',$1) RETURNING id::text`, actor.ID).Scan(&exceptionOnlyProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, exceptionOnlyProjectID, CapabilityMemoryAdminister); err != nil {
		t.Fatal(err)
	}
	retainedException, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: exceptionOnlyProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151517",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !retainedException.Active {
		t.Fatalf("approve exception-only project exception=%#v err=%v", retainedException, err)
	}
	var exceptionOnlyHasScope bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM brain.scopes WHERE project_id=$1)`, exceptionOnlyProjectID).Scan(&exceptionOnlyHasScope); err != nil || exceptionOnlyHasScope {
		t.Fatalf("exception-only project scope=%v err=%v", exceptionOnlyHasScope, err)
	}
	assertExceptionMergeFence := func(state string) {
		t.Helper()
		mergeTx, beginErr := beginMutation(ctx, app.db)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = mergeTx.Rollback() }()
		if _, _, _, _, _, _, mergeErr := projectMergeCounts(ctx, mergeTx, actor.ID, exceptionOnlyProjectID, projectID); !errors.Is(mergeErr, ErrProjectMergeBrainState) {
			t.Fatalf("%s exception-only merge fence error=%v", state, mergeErr)
		}
	}
	assertExceptionMergeFence("active")
	retainedException, err = app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
		PrincipalID: actor.ID, ProjectID: exceptionOnlyProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151518", ExceptionID: retainedException.ExceptionID,
	})
	if err != nil || retainedException.Active {
		t.Fatalf("revoke exception-only project exception=%#v err=%v", retainedException, err)
	}
	assertExceptionMergeFence("revoked")
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151514"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("other-project exception allowed secret: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("other-project rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	wrongPath := sensitiveFinding
	wrongPath.FieldPath = "/other"
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151502",
		RuleID: wrongPath.RuleID, FieldPath: wrongPath.FieldPath, RuleVersion: wrongPath.RuleVersion, Fingerprint: wrongPath.Fingerprint,
	}); err != nil {
		t.Fatalf("approve wrong-path exception: %v", err)
	}
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151503"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("wrong-path exception allowed secret: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("wrong-path rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: outsider.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151507",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized exception approval error=%v", err)
	}
	raceFindings, err := secretguard.ScanDocument([]byte(`{"password":"concurrent-value"}`))
	if err != nil || len(raceFindings) != 1 {
		t.Fatalf("concurrent exception finding=%#v err=%v", raceFindings, err)
	}
	type exceptionResult struct {
		result MemorySecretExceptionResult
		err    error
	}
	exceptionResults := make(chan exceptionResult, 2)
	for _, key := range []string{"15151515-1515-4515-8515-151515151509", "15151515-1515-4515-8515-151515151510"} {
		go func() {
			result, approveErr := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
				PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key,
				RuleID: raceFindings[0].RuleID, FieldPath: raceFindings[0].FieldPath, RuleVersion: raceFindings[0].RuleVersion, Fingerprint: raceFindings[0].Fingerprint,
			})
			exceptionResults <- exceptionResult{result, approveErr}
		}()
	}
	firstException, secondException := <-exceptionResults, <-exceptionResults
	if firstException.err != nil || secondException.err != nil || firstException.result != secondException.result || !firstException.result.Active {
		t.Fatalf("concurrent exception approvals=%#v/%#v", firstException, secondException)
	}
	multiDocument := json.RawMessage(`{"value":"-----BEGIN PRIVATE KEY-----\nmaterial\nghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}`)
	multiFindings, err := secretguard.ScanDocument(multiDocument)
	if err != nil || len(multiFindings) != 2 {
		t.Fatalf("multi-rule finding=%#v err=%v", multiFindings, err)
	}
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151511",
		RuleID: multiFindings[0].RuleID, FieldPath: multiFindings[0].FieldPath, RuleVersion: multiFindings[0].RuleVersion, Fingerprint: multiFindings[0].Fingerprint,
	}); err != nil {
		t.Fatalf("approve first multi-rule finding: %v", err)
	}
	multiCreate := secretCreate
	multiCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151512"
	multiCreate.Document = multiDocument
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, multiCreate); !errors.As(err, &rejection) || rejection.Finding.RuleID != secretguard.RuleBearerToken {
		t.Fatalf("excepted first rule hid second finding: rejection=%#v err=%v", rejection, err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("multi-rule rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	exception, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151504",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !exception.Active {
		t.Fatalf("approve exact exception=%#v err=%v", exception, err)
	}
	otherProjectCreate := secretCreate
	otherProjectCreate.ProjectID = otherProjectID
	otherProjectCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151505"
	if _, err := app.CreateMemory(ctx, otherProjectCreate); err != nil {
		t.Fatalf("exact exception did not allow create: %v", err)
	}
	guardTx, err := app.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := guardMemoryDocument(ctx, guardTx, projectID, secretDocument); err != nil {
		_ = guardTx.Rollback()
		t.Fatalf("lock exact exception for writer transaction: %v", err)
	}
	revokeDone := make(chan exceptionResult, 1)
	go func() {
		result, revokeErr := app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
			PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151506", ExceptionID: exception.ExceptionID,
		})
		revokeDone <- exceptionResult{result: result, err: revokeErr}
	}()
	waitDeadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'
  AND query LIKE 'SELECT revoked_at IS NULL FROM brain.secret_exceptions%FOR UPDATE')`).Scan(&waiting); err != nil {
			_ = guardTx.Rollback()
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-revokeDone:
			_ = guardTx.Rollback()
			t.Fatalf("revocation escaped the in-flight writer exception lock: %#v", result)
		default:
		}
		if time.Now().After(waitDeadline) {
			_ = guardTx.Rollback()
			t.Fatal("revocation did not wait for the in-flight writer exception lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := guardTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var revoked MemorySecretExceptionResult
	select {
	case result := <-revokeDone:
		revoked, err = result.result, result.err
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not finish after the writer transaction committed")
	}
	if err != nil || revoked.Active || revoked.ExceptionID != exception.ExceptionID {
		t.Fatalf("revoke exception=%#v err=%v", revoked, err)
	}
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151515"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("revoked exception allowed later publication: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("post-revoke rejection effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	create := MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: projectID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141401",
		LogicalKey:     "agent.preference", Kind: "preference", Trust: "curated",
		Document: json.RawMessage(`{"title":"Use focused tests","enabled":true,"numeric":1e0}`),
	}
	type createResult struct {
		result MemoryMutationResult
		err    error
	}
	started := make(chan struct{})
	results := make(chan createResult, 2)
	for range 2 {
		go func() {
			<-started
			result, createErr := app.CreateMemory(ctx, create)
			results <- createResult{result: result, err: createErr}
		}()
	}
	close(started)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.result != second.result {
		t.Fatalf("concurrent memory create=%#v/%#v", first, second)
	}
	created := first.result
	if created.Revision != 1 || created.State != MemoryActive || created.ETag == "" {
		t.Fatalf("created memory=%#v", created)
	}
	secretUpdate := MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "15151515-1515-4515-8515-151515151508", ExpectedETag: created.ETag,
		LogicalKey: create.LogicalKey, Kind: create.Kind, Trust: create.Trust, Document: secretDocument,
	}
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.UpdateMemory(ctx, secretUpdate); !errors.As(err, &rejection) {
		t.Fatalf("secret update rejection=%v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("rejected secret update effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	if retry, err := app.CreateMemory(ctx, create); err != nil || retry != created {
		t.Fatalf("exact create retry=%#v err=%v", retry, err)
	}
	changedCreate := create
	changedCreate.Document = json.RawMessage(`{"title":"changed retry"}`)
	if _, err := app.CreateMemory(ctx, changedCreate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed create retry error=%v", err)
	}
	logicalConflict := create
	logicalConflict.IdempotencyKey = "14141414-1414-4414-8414-141414141402"
	if _, err := app.CreateMemory(ctx, logicalConflict); !errors.Is(err, ErrMemoryLogicalKeyConflict) {
		t.Fatalf("logical-key conflict error=%v", err)
	}
	otherScope := create
	otherScope.ProjectID = otherProjectID
	otherScope.IdempotencyKey = "14141414-1414-4414-8414-141414141403"
	if _, err := app.CreateMemory(ctx, otherScope); err != nil {
		t.Fatalf("same logical key in another project failed: %v", err)
	}

	item, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID)
	documentHash := sha256.Sum256(item.Document)
	if err != nil || item.ETag != created.ETag || item.Revision != 1 || item.ContentSHA256 != hex.EncodeToString(documentHash[:]) {
		t.Fatalf("memory get=%#v err=%v", item, err)
	}
	var decodedDocument map[string]any
	if json.Unmarshal(item.Document, &decodedDocument) != nil || decodedDocument["title"] != "Use focused tests" || decodedDocument["numeric"] != float64(1) {
		t.Fatalf("memory document changed semantics: %s", item.Document)
	}
	if _, err := app.GetMemory(ctx, outsider.ID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized get error=%v", err)
	}
	if _, err := app.GetMemory(ctx, reader.ID, otherProjectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project get error=%v", err)
	}
	testMemorySecretQuarantine(ctx, t, app, ownerDB, actor.ID, reader.ID, outsider.ID)
	for name, deniedCreate := range map[string]MemoryCreateRequest{
		"unauthorized": {
			PrincipalID: outsider.ID, ProjectID: projectID, IdempotencyKey: "14141414-1414-4414-8414-141414141421",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"denied"}`),
		},
		"missing project": {
			PrincipalID: actor.ID, ProjectID: "14141414-1414-4414-8414-141414141499", IdempotencyKey: "14141414-1414-4414-8414-141414141422",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"missing"}`),
		},
		"retired project": {
			PrincipalID: actor.ID, ProjectID: retiredProjectID, IdempotencyKey: "14141414-1414-4414-8414-141414141423",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"retired"}`),
		},
	} {
		if _, err := app.CreateMemory(ctx, deniedCreate); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s create disclosed project state: %v", name, err)
		}
	}

	update := MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141404", ExpectedETag: created.ETag,
		LogicalKey: "agent.preference", Kind: "preference", Trust: "reviewed",
		Document: json.RawMessage(`{"title":"Second canonical revision"}`),
	}
	updated, err := app.UpdateMemory(ctx, update)
	if err != nil || updated.Revision != 2 || updated.ETag == created.ETag {
		t.Fatalf("memory update=%#v err=%v", updated, err)
	}
	if retry, err := app.UpdateMemory(ctx, update); err != nil || retry != updated {
		t.Fatalf("exact update retry=%#v err=%v", retry, err)
	}
	changedUpdate := update
	changedUpdate.Document = json.RawMessage(`{"title":"changed update retry"}`)
	if _, err := app.UpdateMemory(ctx, changedUpdate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed update retry error=%v", err)
	}
	stale := update
	stale.IdempotencyKey = "14141414-1414-4414-8414-141414141405"
	stale.Document = json.RawMessage(`{"title":"must not persist"}`)
	beforeStale := readBrainEffects(ctx, t, ownerDB, created.ItemID, stale.IdempotencyKey, projectID)
	if _, err := app.UpdateMemory(ctx, stale); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale update error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, stale.IdempotencyKey, projectID, beforeStale)
	var revisionCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1`, created.ItemID).Scan(&revisionCount); err != nil || revisionCount != 2 {
		t.Fatalf("stale update revision count=%d err=%v", revisionCount, err)
	}

	archiveRequest := MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141406", ExpectedETag: updated.ETag, Archived: true,
	}
	archived, err := app.ArchiveMemory(ctx, archiveRequest)
	if err != nil || archived.Revision != 3 || archived.State != MemoryArchived {
		t.Fatalf("archive=%#v err=%v", archived, err)
	}
	if retry, err := app.ArchiveMemory(ctx, archiveRequest); err != nil || retry != archived {
		t.Fatalf("exact archive retry=%#v err=%v", retry, err)
	}
	changedArchive := archiveRequest
	changedArchive.Archived = false
	if _, err := app.ArchiveMemory(ctx, changedArchive); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed archive retry error=%v", err)
	}
	staleArchive := archiveRequest
	staleArchive.IdempotencyKey = "14141414-1414-4414-8414-141414141412"
	staleArchive.Archived = false
	beforeStale = readBrainEffects(ctx, t, ownerDB, created.ItemID, staleArchive.IdempotencyKey, projectID)
	if _, err := app.ArchiveMemory(ctx, staleArchive); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale archive error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, staleArchive.IdempotencyKey, projectID, beforeStale)
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: reader.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141407", ExpectedETag: archived.ETag,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("writer without purge delete error=%v", err)
	}
	restored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141408", ExpectedETag: archived.ETag, Archived: false,
	})
	if err != nil || restored.Revision != 4 || restored.State != MemoryActive {
		t.Fatalf("restore=%#v err=%v", restored, err)
	}
	abandonedTimeline := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	abandonedSequence := restored.ChangeSequence + 1000
	abandonedTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := abandonedTx.ExecContext(ctx, `INSERT INTO brain.memory_changes
(timeline_id,change_sequence,scope_id,item_id,operation,revision)
SELECT $1,$2,scope_id,id,'restore',current_revision FROM brain.memory_items WHERE id=$3`, abandonedTimeline, abandonedSequence, created.ItemID); err != nil {
		_ = abandonedTx.Rollback()
		t.Fatal(err)
	}
	if err := abandonedTx.Commit(); err != nil {
		t.Fatal(err)
	}
	timelineItem, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID)
	if err != nil || timelineItem.ChangeSequence != restored.ChangeSequence {
		t.Fatalf("current-timeline memory get=%#v want sequence=%d err=%v", timelineItem, restored.ChangeSequence, err)
	}
	cleanupAbandonedTx, err := beginMutation(ctx, ownerDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanupAbandonedTx.ExecContext(ctx, `DELETE FROM brain.memory_changes WHERE timeline_id=$1 AND change_sequence=$2`, abandonedTimeline, abandonedSequence); err != nil {
		_ = cleanupAbandonedTx.Rollback()
		t.Fatal(err)
	}
	if err := cleanupAbandonedTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var restoreAuditAction string
	if err := ownerDB.QueryRowContext(ctx, `SELECT action FROM audit.events WHERE target_id=$1 ORDER BY event_id DESC LIMIT 1`, created.ItemID).Scan(&restoreAuditAction); err != nil || restoreAuditAction != string(AuditMemoryRestore) {
		t.Fatalf("restore audit action=%q err=%v", restoreAuditAction, err)
	}
	noOpRestore := MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141413", ExpectedETag: restored.ETag, Archived: false,
	}
	unrelatedBeforeNoOp := otherScope
	unrelatedBeforeNoOp.IdempotencyKey = "14141414-1414-4414-8414-141414141416"
	unrelatedBeforeNoOp.LogicalKey = "unrelated.noop.sequence"
	unrelatedBeforeNoOp.Document = json.RawMessage(`{"title":"unrelated global sequence"}`)
	if _, err := app.CreateMemory(ctx, unrelatedBeforeNoOp); err != nil {
		t.Fatalf("unrelated activity before no-op: %v", err)
	}
	beforeNoOp := readBrainEffects(ctx, t, ownerDB, created.ItemID, noOpRestore.IdempotencyKey, projectID)
	if result, err := app.ArchiveMemory(ctx, noOpRestore); err != nil || result.Revision != restored.Revision || result.ETag != restored.ETag || result.ChangeSequence != restored.ChangeSequence {
		t.Fatalf("same-state restore=%#v err=%v", result, err)
	}
	afterNoOp := readBrainEffects(ctx, t, ownerDB, created.ItemID, noOpRestore.IdempotencyKey, projectID)
	expectedNoOp := beforeNoOp
	expectedNoOp.idempotency++
	if afterNoOp != expectedNoOp {
		t.Fatalf("same-state restore effects before=%#v after=%#v", beforeNoOp, afterNoOp)
	}
	func() {
		beforeRotation, err := app.InstallationState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rotatedTimeline := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.server_state SET timeline_id=$1 WHERE singleton`, rotatedTimeline); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, restoreErr := ownerDB.ExecContext(ctx, `UPDATE jobs.server_state SET timeline_id=$1 WHERE singleton`, beforeRotation.TimelineID); restoreErr != nil {
				t.Fatalf("restore brain test timeline: %v", restoreErr)
			}
		}()
		originNoOp := noOpRestore
		originNoOp.IdempotencyKey = "14141414-1414-4414-8414-141414141417"
		origin, err := app.ArchiveMemory(ctx, originNoOp)
		if err != nil || origin.Revision != restored.Revision || origin.ETag != restored.ETag || origin.ChangeSequence != 0 {
			t.Fatalf("timeline-origin no-op=%#v err=%v", origin, err)
		}
		if replay, err := app.ArchiveMemory(ctx, originNoOp); err != nil || replay != origin {
			t.Fatalf("timeline-origin no-op replay=%#v want=%#v err=%v", replay, origin, err)
		}
	}()
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141409", ExpectedETag: archived.ETag,
		Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"stale after restore"}`),
	}); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("pre-restore ETag update error=%v", err)
	}
	staleDelete := MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141414", ExpectedETag: archived.ETag,
	}
	beforeStale = readBrainEffects(ctx, t, ownerDB, created.ItemID, staleDelete.IdempotencyKey, projectID)
	if _, err := app.DeleteMemory(ctx, staleDelete); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale delete error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, staleDelete.IdempotencyKey, projectID, beforeStale)
	stateForACL, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directTombstoneTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	_, directTombstoneErr := directTombstoneTx.ExecContext(ctx, `INSERT INTO brain.memory_tombstones
(item_id,scope_id,deleted_by,timeline_id,change_sequence)
SELECT id,scope_id,$2,$3,$4 FROM brain.memory_items WHERE id=$1`, created.ItemID, actor.ID, stateForACL.TimelineID, restored.ChangeSequence)
	_ = directTombstoneTx.Rollback()
	if directTombstoneErr == nil {
		t.Fatal("application role inserted a memory tombstone directly")
	}
	var appTombstoneCount int
	if err := app.db.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_tombstones`).Scan(&appTombstoneCount); err == nil {
		t.Fatalf("application role read memory tombstones directly: count=%d", appTombstoneCount)
	}

	page, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: start, Limit: 2})
	if err != nil || len(page.Changes) != 2 || !page.More || page.Changes[0].Type != MemoryChangeCreate || page.Changes[1].Type != MemoryChangeUpdate {
		t.Fatalf("first memory change page=%#v err=%v", page, err)
	}
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: outsider.ID, ProjectID: projectID, Cursor: start, Limit: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized feed error=%v", err)
	}
	badOutsiderCursor := start
	badOutsiderCursor.TimelineID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: outsider.ID, ProjectID: projectID, Cursor: badOutsiderCursor, Limit: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized malformed cursor leaked state: %v", err)
	}
	allProjectPage, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: allProjectsReader.ID, ProjectID: projectID, Cursor: start, Limit: 2})
	if err != nil || len(allProjectPage.Changes) != 2 {
		t.Fatalf("all-project feed=%#v err=%v", allProjectPage, err)
	}
	allChanges := append([]MemoryChange(nil), page.Changes...)
	cursor := page.Cursor
	for page.More {
		page, err = app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: cursor, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		allChanges = append(allChanges, page.Changes...)
		cursor = page.Cursor
	}
	if len(allChanges) != 4 || allChanges[0].Type != MemoryChangeCreate || allChanges[1].Type != MemoryChangeUpdate || allChanges[2].Type != MemoryChangeArchive || allChanges[3].Type != MemoryChangeRestore {
		t.Fatalf("complete memory changes=%#v", allChanges)
	}
	gapSeen := false
	for index := 1; index < len(allChanges); index++ {
		if allChanges[index].ChangeSequence <= allChanges[index-1].ChangeSequence {
			t.Fatalf("non-monotonic memory changes=%#v", allChanges)
		}
		gapSeen = gapSeen || allChanges[index].ChangeSequence > allChanges[index-1].ChangeSequence+1
	}
	if !gapSeen {
		t.Fatal("project feed did not preserve the expected unrelated-project global sequence gap")
	}
	current, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	future := current
	future.ChangeSequence++
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: future, Limit: 2}); !errors.Is(err, ErrCursorFromFuture) {
		t.Fatalf("future feed cursor error=%v", err)
	}
	wrongTimeline := current
	wrongTimeline.TimelineID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: wrongTimeline, Limit: 2}); !errors.Is(err, ErrCursorTimelineChanged) {
		t.Fatalf("wrong timeline feed error=%v", err)
	}
	wrongInstallation := current
	wrongInstallation.InstallationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: wrongInstallation, Limit: 2}); !errors.Is(err, ErrCursorTimelineChanged) {
		t.Fatalf("wrong installation feed error=%v", err)
	}
	for _, limit := range []int{0, maxMemoryChangePage + 1} {
		if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: current, Limit: limit}); err == nil {
			t.Fatalf("invalid feed limit %d accepted", limit)
		}
	}
	mergeTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, _, err := projectMergeCounts(ctx, mergeTx, actor.ID, projectID, otherProjectID); !errors.Is(err, ErrProjectMergeBrainState) {
		_ = mergeTx.Rollback()
		t.Fatalf("live memory merge fence error=%v", err)
	}
	_ = mergeTx.Rollback()

	deleted, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: restored.ETag,
	})
	if err != nil || deleted.ETag != "" || deleted.State != "" || deleted.Revision != restored.Revision {
		t.Fatalf("delete=%#v err=%v", deleted, err)
	}
	changedDelete := MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: archived.ETag,
	}
	if _, err := app.DeleteMemory(ctx, changedDelete); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed delete retry error=%v", err)
	}
	if _, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get error=%v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1`, created.ItemID).Scan(&revisionCount); err != nil || revisionCount != 0 {
		t.Fatalf("purged revision count=%d err=%v", revisionCount, err)
	}
	var tombstoneCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_tombstones WHERE item_id=$1`, created.ItemID).Scan(&tombstoneCount); err != nil || tombstoneCount != 1 {
		t.Fatalf("memory tombstone count=%d err=%v", tombstoneCount, err)
	}
	mergeTx, err = beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, _, err := projectMergeCounts(ctx, mergeTx, actor.ID, projectID, otherProjectID); !errors.Is(err, ErrProjectMergeBrainState) {
		_ = mergeTx.Rollback()
		t.Fatalf("retained history merge fence error=%v", err)
	}
	_ = mergeTx.Rollback()
	var leaked bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM brain.memory_changes WHERE item_id=$1 AND (operation LIKE '%Second canonical revision%' OR scope_id::text LIKE '%Second canonical revision%'))
OR EXISTS (SELECT 1 FROM audit.events WHERE target_id=$1 AND (action LIKE '%Second canonical revision%' OR target_kind LIKE '%Second canonical revision%'))
OR EXISTS (SELECT 1 FROM relay.idempotency_records WHERE resource_id=$1 AND (result::text LIKE '%Second canonical revision%' OR result::text LIKE '%agent.preference%'))`, created.ItemID).Scan(&leaked); err != nil || leaked {
		t.Fatalf("hard-delete metadata leaked content=%v err=%v", leaked, err)
	}
	directCreate := create
	directCreate.IdempotencyKey = "14141414-1414-4414-8414-141414141415"
	directCreate.LogicalKey = "direct.purge"
	directCreate.Document = json.RawMessage(`{"title":"direct routine evidence"}`)
	directItem, err := app.CreateMemory(ctx, directCreate)
	if err != nil {
		t.Fatal(err)
	}
	directBefore, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	var directScope, directTimeline string
	var directRevision, directSequence int64
	if err := directTx.QueryRowContext(ctx, `SELECT scope_id::text,revision,timeline_id::text,change_sequence
FROM brain.purge_memory($1::uuid,$2::uuid,$3::uuid,$4)`, actor.ID, projectID, directItem.ItemID, directItem.Revision).Scan(&directScope, &directRevision, &directTimeline, &directSequence); err != nil {
		_ = directTx.Rollback()
		t.Fatalf("direct purge routine failed: %v", err)
	}
	if err := directTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if directRevision != directItem.Revision || directTimeline != directBefore.TimelineID || directSequence != directBefore.ChangeSequence+1 || !validOpaqueID(directScope) {
		t.Fatalf("direct purge evidence scope=%q revision=%d timeline=%q sequence=%d before=%#v", directScope, directRevision, directTimeline, directSequence, directBefore)
	}
	var directEvidence int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_tombstones WHERE item_id=$1)
 +(SELECT count(*) FROM brain.memory_changes WHERE item_id=$1 AND operation='delete')
 +(SELECT count(*) FROM audit.events WHERE target_id=$1 AND action='memory.delete')`, directItem.ItemID).Scan(&directEvidence); err != nil || directEvidence != 3 {
		t.Fatalf("direct purge evidence count=%d err=%v", directEvidence, err)
	}
	var purgeGrantID string
	if err := ownerDB.QueryRowContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp()
WHERE principal_id=$1 AND project_id=$2 AND capability='memory.purge' AND revoked_at IS NULL RETURNING id::text`, actor.ID, projectID).Scan(&purgeGrantID); err != nil {
		t.Fatal(err)
	}
	if retry, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: restored.ETag,
	}); err != nil || retry != deleted {
		t.Fatalf("delete retry after revocation=%#v err=%v", retry, err)
	}
	reuse := create
	reuse.IdempotencyKey = "14141414-1414-4414-8414-141414141411"
	if _, err := app.CreateMemory(ctx, reuse); err != nil {
		t.Fatalf("hard delete did not release logical key: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE brain.memory_revisions SET document='{}'::jsonb WHERE item_id=$1`, created.ItemID); err == nil {
		t.Fatal("application role mutated an immutable memory revision")
	}
}

func testMemorySecretQuarantine(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB, actorID, readerID, outsiderID string) {
	t.Helper()
	var projectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('quarantine brain project',$1) RETURNING id::text`, actorID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		principal  string
		capability Capability
	}{
		{actorID, CapabilityMemoryRead},
		{actorID, CapabilityMemoryWrite},
		{actorID, CapabilityMemoryAdminister},
		{readerID, CapabilityMemoryRead},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, grant.principal, projectID, grant.capability); err != nil {
			t.Fatal(err)
		}
	}
	created, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161601",
		LogicalKey: "legacy.secret", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"legacy safe value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161610",
		LogicalKey: "legacy.second", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"second legacy safe value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyDocument := `{"token":"resolved-legacy-value-123"}`
	var legacyStoredDocument string
	if err := ownerDB.QueryRowContext(ctx, `SELECT $1::jsonb::text`, legacyDocument).Scan(&legacyStoredDocument); err != nil {
		t.Fatal(err)
	}
	legacyDocumentHash := sha256.Sum256([]byte(legacyStoredDocument))
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET document=$2::jsonb,content_sha256=$3
WHERE item_id=$1 AND revision=1`, created.ItemID, legacyDocument, legacyDocumentHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM brain.memory_secret_scans WHERE item_id=$1`, created.ItemID); err != nil {
		t.Fatal(err)
	}
	secondLegacyDocument := `{"password":"second-legacy-value-456"}`
	var secondLegacyStoredDocument string
	if err := ownerDB.QueryRowContext(ctx, `SELECT $1::jsonb::text`, secondLegacyDocument).Scan(&secondLegacyStoredDocument); err != nil {
		t.Fatal(err)
	}
	secondLegacyDocumentHash := sha256.Sum256([]byte(secondLegacyStoredDocument))
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET document=$2::jsonb,content_sha256=$3
WHERE item_id=$1 AND revision=1`, second.ItemID, secondLegacyDocument, secondLegacyDocumentHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM brain.memory_secret_scans WHERE item_id=$1`, second.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=decode(repeat('00',32),'hex') WHERE item_id=$1 AND revision=1`, second.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161615", Limit: 2,
	}); err == nil || strings.Contains(err.Error(), "second-legacy") {
		t.Fatalf("corrupt-candidate rescan error=%v", err)
	}
	var failedBatchEffects int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_quarantines AS quarantine JOIN brain.memory_items AS item ON item.id=quarantine.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1)
+ (SELECT count(*) FROM brain.memory_secret_scans AS scan JOIN brain.memory_items AS item ON item.id=scan.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1)
+ (SELECT count(*) FROM relay.idempotency_records WHERE key='16161616-1616-4616-8616-161616161615')`, projectID).Scan(&failedBatchEffects); err != nil || failedBatchEffects != 0 {
		t.Fatalf("failed rescan batch effects=%d err=%v", failedBatchEffects, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=$2 WHERE item_id=$1 AND revision=1`, second.ItemID, secondLegacyDocumentHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: readerID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161611", Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized secret rescan error=%v", err)
	}
	request := MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161602", Limit: 1,
	}
	result, err := app.RescanMemorySecrets(ctx, request)
	if err != nil || result.Scanned != 1 || result.Quarantined != 1 || result.Released != 0 || !result.Remaining {
		t.Fatalf("secret rescan=%#v err=%v", result, err)
	}
	if retry, err := app.RescanMemorySecrets(ctx, request); err != nil || retry != result {
		t.Fatalf("secret rescan retry=%#v err=%v", retry, err)
	}
	changedRequest := request
	changedRequest.Limit = 2
	if _, err := app.RescanMemorySecrets(ctx, changedRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed secret rescan retry error=%v", err)
	}
	secondBatch, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161612", Limit: 1,
	})
	if err != nil || secondBatch.Scanned != 1 || secondBatch.Quarantined != 1 || secondBatch.Released != 0 || secondBatch.Remaining {
		t.Fatalf("second secret rescan batch=%#v err=%v", secondBatch, err)
	}
	if encoded, _ := json.Marshal(result); strings.Contains(string(encoded), "resolved-legacy") {
		t.Fatalf("secret rescan result leaked content: %s", encoded)
	}
	if _, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined ordinary get error=%v", err)
	}
	if _, err := app.ReviewMemorySecretQuarantine(ctx, outsiderID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized quarantine review error=%v", err)
	}
	review, err := app.ReviewMemorySecretQuarantine(ctx, actorID, projectID, created.ItemID)
	var reviewedDocument map[string]any
	if err != nil || json.Unmarshal(review.Item.Document, &reviewedDocument) != nil || !review.Active || review.Item.ItemID != created.ItemID || reviewedDocument["token"] != "resolved-legacy-value-123" || review.Finding.RuleID != secretguard.RuleSensitiveField || review.Finding.FieldPath != "/token" {
		t.Fatalf("quarantine review=%#v err=%v", review, err)
	}
	secondReview, err := app.ReviewMemorySecretQuarantine(ctx, actorID, projectID, second.ItemID)
	if err != nil {
		t.Fatalf("second quarantine review: %v", err)
	}
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: second.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161613", ExpectedETag: secondReview.Item.ETag,
		LogicalKey: "legacy.second", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"second clean replacement"}`),
	}); err != nil {
		t.Fatalf("clean second quarantined item: %v", err)
	}
	noOp, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161614", Limit: 2,
	})
	if err != nil || noOp.Scanned != 0 || noOp.Quarantined != 0 || noOp.Released != 0 || noOp.Remaining {
		t.Fatalf("completed no-op rescan=%#v err=%v", noOp, err)
	}
	archived, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161603", ExpectedETag: review.Item.ETag, Archived: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("archive escaped quarantine: %v", err)
	}
	restored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161604", ExpectedETag: archived.ETag, Archived: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	exception, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161605",
		RuleID: review.Finding.RuleID, FieldPath: review.Finding.FieldPath, RuleVersion: review.Finding.RuleVersion, Fingerprint: review.Finding.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	released, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161606", Limit: 2,
	})
	if err != nil || released.Scanned != 2 || released.Quarantined != 0 || released.Released != 1 || released.Remaining {
		t.Fatalf("excepted rescan=%#v err=%v", released, err)
	}
	if item, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); err != nil || json.Unmarshal(item.Document, &reviewedDocument) != nil || reviewedDocument["token"] != "resolved-legacy-value-123" || item.Revision != restored.Revision {
		t.Fatalf("released ordinary get=%#v err=%v", item, err)
	}
	if _, err := app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161607", ExceptionID: exception.ExceptionID,
	}); err != nil {
		t.Fatal(err)
	}
	requarantined, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161608", Limit: 2,
	})
	if err != nil || requarantined.Scanned != 2 || requarantined.Quarantined != 1 || requarantined.Released != 0 || requarantined.Remaining {
		t.Fatalf("post-revoke rescan=%#v err=%v", requarantined, err)
	}
	cleaned, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161609", ExpectedETag: restored.ETag,
		LogicalKey: "legacy.secret", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"clean replacement"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if item, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); err != nil || json.Unmarshal(item.Document, &reviewedDocument) != nil || item.Revision != cleaned.Revision || reviewedDocument["title"] != "clean replacement" {
		t.Fatalf("clean update release=%#v err=%v", item, err)
	}
	var metadataLeaked bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM audit.events AS event WHERE event.project_id=$1 AND to_jsonb(event)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM relay.idempotency_records AS idempotency WHERE to_jsonb(idempotency)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM brain.memory_changes AS change JOIN brain.scopes AS scope ON scope.id=change.scope_id WHERE scope.project_id=$1 AND to_jsonb(change)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine JOIN brain.memory_items AS item ON item.id=quarantine.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1 AND to_jsonb(quarantine)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))`, projectID).Scan(&metadataLeaked); err != nil || metadataLeaked {
		t.Fatalf("quarantine metadata leaked content=%v err=%v", metadataLeaked, err)
	}
}

type brainEffects struct {
	revisions         int
	changes           int
	audits            int
	idempotency       int
	changeSequence    int64
	contentGeneration int64
}

func readBrainEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB, itemID, idempotencyKey, projectID string) brainEffects {
	t.Helper()
	var effects brainEffects
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1),
  (SELECT count(*) FROM brain.memory_changes WHERE item_id=$1),
  (SELECT count(*) FROM audit.events WHERE target_id=$1 AND action LIKE 'memory.%'),
	  (SELECT count(*) FROM relay.idempotency_records WHERE key=$2),
	  (SELECT change_sequence FROM jobs.server_state WHERE singleton),
	  (SELECT content_generation FROM relay.projects WHERE id=$3)`, itemID, idempotencyKey, projectID).Scan(&effects.revisions, &effects.changes, &effects.audits, &effects.idempotency, &effects.changeSequence, &effects.contentGeneration); err != nil {
		t.Fatal(err)
	}
	return effects
}

func assertBrainEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB, itemID, idempotencyKey, projectID string, want brainEffects) {
	t.Helper()
	if got := readBrainEffects(ctx, t, ownerDB, itemID, idempotencyKey, projectID); got != want {
		t.Fatalf("memory failure changed state: got=%#v want=%#v", got, want)
	}
}

type secretGuardEffects struct {
	items, revisions, changes, audits, idempotency, jobs, scopes int
	scans, quarantines, projectStates                            int
	changeSequence, contentGeneration                            int64
}

func readSecretGuardEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB) secretGuardEffects {
	t.Helper()
	var effects secretGuardEffects
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_items),
  (SELECT count(*) FROM brain.memory_revisions),
  (SELECT count(*) FROM brain.memory_changes),
  (SELECT count(*) FROM audit.events),
  (SELECT count(*) FROM relay.idempotency_records),
  (SELECT count(*) FROM jobs.outbox),
  (SELECT count(*) FROM brain.scopes),
  (SELECT count(*) FROM brain.memory_secret_scans),
  (SELECT count(*) FROM brain.memory_quarantines),
  (SELECT count(*) FROM brain.secret_project_state),
  (SELECT change_sequence FROM jobs.server_state WHERE singleton),
  (SELECT sum(content_generation) FROM relay.projects)`).Scan(
		&effects.items, &effects.revisions, &effects.changes, &effects.audits,
		&effects.idempotency, &effects.jobs, &effects.scopes,
		&effects.scans, &effects.quarantines, &effects.projectStates,
		&effects.changeSequence, &effects.contentGeneration,
	); err != nil {
		t.Fatal(err)
	}
	return effects
}
