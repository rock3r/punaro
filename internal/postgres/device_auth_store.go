package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrAlreadyInitialized reports that the installation already has an owner.
	ErrAlreadyInitialized = errors.New("installation ownership is already initialized")
	// ErrInvalidEnrollment reports a rejected enrollment without disclosing why.
	ErrInvalidEnrollment = errors.New("enrollment is not valid")
	// ErrUnauthenticated reports a rejected credential without disclosing why.
	ErrUnauthenticated = errors.New("device credential is not valid")
	// ErrCredentialChanged reports a stale credential-generation precondition.
	ErrCredentialChanged = errors.New("device credential generation changed")
)

const (
	bootstrapLockKey             int64 = 0x50756e61726f4f57
	enrollmentMutationLockKey    int64 = 0x50756e61726f454e
	maxPendingEnrollments              = 1000
	lastUsedWriteInterval              = 5 * time.Minute
	clientLifecycleSchemaVersion       = 44
)

// Administration is a direct, host-local schema-owner connection. It is never
// mounted on the public service and cannot be opened with the application role.
type Administration struct{ db *sql.DB }

// OpenAdministration opens the protected host-local owner connection.
func OpenAdministration(ctx context.Context, cfg Config) (*Administration, error) {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return nil, err
	}
	db, err := open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	var owner bool
	if err := db.QueryRowContext(ctx, `SELECT session_user = current_user AND current_user = 'punaro_owner'`).Scan(&owner); err != nil || !owner {
		_ = db.Close()
		return nil, errors.New("host-local administration requires the schema-owner role")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, errors.New("host-local administration cannot verify database roles")
	}
	if err := verifyMigrationRoles(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}
	snapshot, err := inspect(ctx, conn)
	_ = conn.Close()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	state := Classify(snapshot, CurrentManifest())
	bridgeControls, knownBridge := false, false
	if state.Classification == UpgradeRequired && state.Version == 5 {
		bridgeControls, err = updateControlsAvailable(ctx, db)
		if err == nil && bridgeControls {
			err = db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM jobs.update_transactions WHERE source_schema=5 AND target_schema=6)`).Scan(&knownBridge)
		}
	}
	if err != nil || !administrationSchemaAllowed(state, bridgeControls, knownBridge) {
		_ = db.Close()
		return nil, contentFreeMigrationError(state.Classification)
	}
	return &Administration{db: db}, nil
}

// Close releases the host-local owner connection pool.
func (a *Administration) Close() error { return a.db.Close() }

// ClientLifecycleRuntimeReady rejects compatible historical schemas before a
// daemon exposes lifecycle-dependent authentication or enrollment routes.
func (d *Database) ClientLifecycleRuntimeReady(ctx context.Context) error {
	state, err := d.SchemaState(ctx)
	if err != nil || state.Classification != Compatible || state.Version < clientLifecycleSchemaVersion {
		return errors.New("PostgreSQL client lifecycle schema is unavailable")
	}
	return nil
}

func (a *Administration) requireClientLifecycleSchema(ctx context.Context) error {
	var version int64
	if err := a.db.QueryRowContext(ctx, `SELECT COALESCE(max(version), 0) FROM jobs.schema_migrations WHERE status = 'applied'`).Scan(&version); err != nil || version < clientLifecycleSchemaVersion {
		return errors.New("client lifecycle schema is unavailable")
	}
	available, err := clientLifecycleObjectsAvailable(ctx, a.db)
	if err != nil || !available {
		return errors.New("client lifecycle schema is unavailable")
	}
	return nil
}

// InstallationOwner returns the existing singleton owner for host-local
// initialization recovery. It exposes no network route and no secret material.
func (a *Administration) InstallationOwner(ctx context.Context) (Principal, error) {
	var owner Principal
	err := a.db.QueryRowContext(ctx, `SELECT principal.id::text, principal.kind, principal.display_name
FROM auth.installation_owner AS installation
JOIN auth.principals AS principal ON principal.id = installation.principal_id
WHERE installation.singleton`).Scan(&owner.ID, &owner.Kind, &owner.DisplayName)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrNotFound
	}
	if err != nil {
		return Principal{}, errors.New("installation owner is unavailable")
	}
	return owner, nil
}

// InstallationState returns the owner-role view used to prove that host-local
// administration and the public application role target the same installation.
func (a *Administration) InstallationState(ctx context.Context) (InstallationState, error) {
	var state InstallationState
	err := a.db.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil {
		return InstallationState{}, errors.New("PostgreSQL installation metadata is unavailable")
	}
	return state, nil
}

// PendingEnrollment contains the one-time secret and exact confirmed grants.
// Callers must display/store Code once and must never log this value.
type PendingEnrollment struct {
	ID            string      `json:"enrollment_id"`
	ClientBinding string      `json:"client_binding"`
	Code          string      `json:"code"`
	ExpiresAt     time.Time   `json:"expires_at"`
	PreviewHash   string      `json:"preview_hash"`
	Grants        []GrantSpec `json:"grants"`
}

// DeviceCredential is returned once at redemption/rotation. Encoded is the
// canonical lookup-id plus caller-retained 256-bit secret.
type DeviceCredential struct {
	ClientID       string    `json:"client_id,omitempty"`
	MachineID      string    `json:"machine_id,omitempty"`
	EndpointPrefix string    `json:"endpoint_prefix,omitempty"`
	PrincipalID    string    `json:"principal_id"`
	LookupID       string    `json:"lookup_id"`
	Encoded        string    `json:"credential"`
	Generation     int64     `json:"generation"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
}

// DeviceRevocation is the fixed content-free result of a successful self-revocation.
type DeviceRevocation struct {
	Status string `json:"status"`
}

// AuthenticatedDevice is the generation fence carried by caches and sessions.
type AuthenticatedDevice struct {
	PrincipalID string
	LookupID    string
	Generation  int64
}

// DeviceCredentialMetadata is content-free operator inventory.
type DeviceCredentialMetadata struct {
	PrincipalID string    `json:"principal_id"`
	LookupID    string    `json:"lookup_id"`
	Label       string    `json:"label"`
	Generation  int64     `json:"generation"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	RotatedAt   time.Time `json:"rotated_at,omitzero"`
	RevokedAt   time.Time `json:"revoked_at,omitzero"`
}

// ClientMetadata is the bounded content-free owner inventory for one installed client.
type ClientMetadata struct {
	ClientID           string    `json:"client_id"`
	MachineID          string    `json:"machine_id"`
	EndpointPrefix     string    `json:"endpoint_prefix"`
	PrincipalID        string    `json:"principal_id"`
	CredentialLookupID string    `json:"credential_lookup_id"`
	Label              string    `json:"label"`
	Generation         int64     `json:"generation"`
	LifecycleState     string    `json:"lifecycle_state"`
	CreatedAt          time.Time `json:"created_at"`
	LastUsedAt         time.Time `json:"last_used_at,omitzero"`
	RevokedAt          time.Time `json:"revoked_at,omitzero"`
	RevocationReason   string    `json:"revocation_reason,omitempty"`
}

// RedeemEnrollment binds a one-time code to the exact approved client.
type RedeemEnrollment struct {
	EnrollmentID   string
	ClientBinding  string
	Code           string
	IdempotencyKey string
}

// PendingCredentialRotation is a short-lived internally generated rotation code.
type PendingCredentialRotation struct {
	LookupID           string    `json:"lookup_id"`
	ExpectedGeneration int64     `json:"expected_generation"`
	Code               string    `json:"code"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// RotateCredential completes one optimistic, retry-recoverable rotation.
type RotateCredential struct {
	LookupID           string
	ExpectedGeneration int64
	Code               string
}

// LegacyExchangeProof proves possession of the exact operator-registered Ed25519 key.
type LegacyExchangeProof struct {
	PublicKey ed25519.PublicKey
	Signature []byte
}

// BootstrapOwner atomically creates the only installation owner and its root
// project authority. The global lock makes concurrent initialization single-winner.
func (a *Administration) BootstrapOwner(ctx context.Context, label string) (Principal, error) {
	if !validDisplayName(label) {
		return Principal{}, errors.New("invalid owner")
	}
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return Principal{}, mutationStartError(err, "owner bootstrap cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockKey); err != nil {
		return Principal{}, errors.New("owner bootstrap cannot be serialized")
	}
	if err := lockGrantMutations(ctx, tx); err != nil {
		return Principal{}, err
	}
	if err := lockGlobalProjectACL(ctx, tx); err != nil {
		return Principal{}, err
	}
	var initialized bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.installation_owner)`).Scan(&initialized); err != nil {
		return Principal{}, errors.New("owner state is unavailable")
	}
	if initialized {
		return Principal{}, ErrAlreadyInitialized
	}
	var owner Principal
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.principals (kind, display_name) VALUES ('owner', $1) RETURNING id::text, kind, display_name`, label).Scan(&owner.ID, &owner.Kind, &owner.DisplayName); err != nil {
		return Principal{}, errors.New("owner could not be created")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth.installation_owner (principal_id) VALUES ($1)`, owner.ID); err != nil {
		return Principal{}, errors.New("owner could not be installed")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, capability) VALUES
($1, 'installation', 'project.create'), ($1, 'all_projects', 'project.administer')`, owner.ID); err != nil {
		return Principal{}, errors.New("owner authority could not be installed")
	}
	if err := advanceGrantGenerations(ctx, tx, ScopeAllProjects, ""); err != nil {
		return Principal{}, err
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: owner.ID, Action: AuditOwnerBootstrap, Outcome: AuditSucceeded, TargetKind: AuditTargetPrincipal, TargetID: owner.ID}); err != nil {
		return Principal{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return Principal{}, err
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, errors.New("owner bootstrap could not commit")
	}
	return owner, nil
}

// CreateEnrollment persists the exact preview only after its stable hash is confirmed.
func (a *Administration) CreateEnrollment(ctx context.Context, actorPrincipalID string, request EnrollmentRequest, confirmedPreviewHash string) (PendingEnrollment, error) {
	if !validOpaqueID(actorPrincipalID) || request.Validate() != nil {
		return PendingEnrollment{}, errors.New("invalid enrollment")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return PendingEnrollment{}, err
	}
	grants, previewHash, err := PreviewTrustedAgentEnrollment(request.ProjectIDs, request.AllProjects)
	if err != nil || subtle.ConstantTimeCompare([]byte(previewHash), []byte(confirmedPreviewHash)) != 1 {
		return PendingEnrollment{}, errors.New("enrollment preview was not confirmed")
	}
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return PendingEnrollment{}, errors.New("enrollment entropy is unavailable")
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	codeDigest := sha256.Sum256(codeBytes)
	previewDigest, _ := hex.DecodeString(previewHash)
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return PendingEnrollment{}, mutationStartError(err, "enrollment transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		if err != nil {
			return PendingEnrollment{}, err
		}
		return PendingEnrollment{}, ErrForbidden
	}
	if err := lockEnrollmentMutations(ctx, tx); err != nil {
		return PendingEnrollment{}, err
	}
	if err := pruneExpiredMachineEnrollment(ctx, tx, request.MachineID); err != nil {
		return PendingEnrollment{}, err
	}
	if err := pruneExpiredEnrollments(ctx, tx, 100); err != nil {
		return PendingEnrollment{}, err
	}
	var pendingCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM auth.pending_enrollments WHERE redeemed_at IS NULL AND invalidated_at IS NULL AND expires_at > statement_timestamp()`).Scan(&pendingCount); err != nil || pendingCount >= maxPendingEnrollments {
		return PendingEnrollment{}, errors.New("pending enrollment capacity is unavailable")
	}
	var bindingExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.pending_enrollments WHERE client_binding = $1 AND redeemed_at IS NULL AND invalidated_at IS NULL AND expires_at > statement_timestamp())`, request.ClientBinding).Scan(&bindingExists); err != nil || bindingExists {
		return PendingEnrollment{}, errors.New("client already has a pending enrollment")
	}
	var machineExists bool
	if err := tx.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM auth.client_installations WHERE machine_id = $1)
OR EXISTS (SELECT 1 FROM auth.pending_enrollments WHERE machine_id = $1 AND redeemed_at IS NULL AND invalidated_at IS NULL AND expires_at > statement_timestamp())`, request.MachineID).Scan(&machineExists); err != nil || machineExists {
		return PendingEnrollment{}, errors.New("machine already has an enrollment")
	}
	projectIDs := append([]string(nil), request.ProjectIDs...)
	sort.Strings(projectIDs)
	for _, projectID := range projectIDs {
		if _, err := lockDirectActiveProject(ctx, tx, projectID); err != nil {
			return PendingEnrollment{}, errors.New("enrollment project is unavailable")
		}
	}
	var pending PendingEnrollment
	pending.ClientBinding = request.ClientBinding
	pending.Code = code
	pending.PreviewHash = previewHash
	pending.Grants = grants
	if request.LegacyPrincipalID != "" {
		if err := lockLegacyMutations(ctx, tx); err != nil {
			return PendingEnrollment{}, err
		}
		var pendingLegacy bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE principal_id = $1 AND state = 'pending')`, request.LegacyPrincipalID).Scan(&pendingLegacy); err != nil || !pendingLegacy {
			return PendingEnrollment{}, errors.New("legacy machine is not eligible for exchange")
		}
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.pending_enrollments
(issuer_principal_id, client_binding, machine_id, label, code_digest, preview_hash, expires_at, credential_ttl_seconds, legacy_principal_id)
VALUES ($1, $2, $3, $4, $5, $6, statement_timestamp() + make_interval(secs => $7),
NULL, $8)
RETURNING id::text, expires_at`, actorPrincipalID, request.ClientBinding, request.MachineID, request.Label, codeDigest[:], previewDigest, int64(request.TTL/time.Second), nullableID(request.LegacyPrincipalID)).Scan(&pending.ID, &pending.ExpiresAt); err != nil {
		return PendingEnrollment{}, errors.New("pending enrollment could not be created")
	}
	for ordinal, grant := range grants {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth.pending_enrollment_grants (enrollment_id, ordinal, scope, project_id, capability) VALUES ($1, $2, $3, $4, $5)`, pending.ID, ordinal, grant.Scope, nullableID(grant.ProjectID), grant.Capability); err != nil {
			return PendingEnrollment{}, errors.New("enrollment grants could not be recorded")
		}
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditEnrollmentCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetEnrollment, TargetID: pending.ID}); err != nil {
		return PendingEnrollment{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return PendingEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return PendingEnrollment{}, errors.New("enrollment transaction could not commit")
	}
	return pending, nil
}

// RedeemEnrollment consumes one valid enrollment and atomically installs its credential and grants.
func (d *Database) RedeemEnrollment(ctx context.Context, redeem RedeemEnrollment) (DeviceCredential, error) {
	return d.redeemEnrollment(ctx, redeem, nil)
}

// RedeemLegacyEnrollment is called only after the existing Ed25519 verifier
// authenticated the exact registered legacy principal.
func (d *Database) RedeemLegacyEnrollment(ctx context.Context, proof LegacyExchangeProof, redeem RedeemEnrollment) (DeviceCredential, error) {
	if len(proof.PublicKey) != ed25519.PublicKeySize || len(proof.Signature) != ed25519.SignatureSize {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	return d.redeemEnrollment(ctx, redeem, &proof)
}

func (d *Database) redeemEnrollment(ctx context.Context, redeem RedeemEnrollment, legacyProof *LegacyExchangeProof) (DeviceCredential, error) {
	if !validOpaqueID(redeem.EnrollmentID) || !validOpaqueID(redeem.ClientBinding) || !validOpaqueID(redeem.IdempotencyKey) {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	codeBytes, err := base64.RawURLEncoding.Strict().DecodeString(redeem.Code)
	if err != nil || len(codeBytes) != 32 || base64.RawURLEncoding.EncodeToString(codeBytes) != redeem.Code {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	codeDigest := sha256.Sum256(codeBytes)
	credentialSecret := deriveEnrollmentCredentialSecret(redeem, codeBytes)
	secretDigest := sha256.Sum256(credentialSecret[:])
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return DeviceCredential{}, mutationStartError(err, "enrollment redemption cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockGrantMutations(ctx, tx); err != nil {
		return DeviceCredential{}, err
	}
	var storedCode []byte
	var storedBinding, machineID, label, issuer string
	var unexpired, active bool
	var redemptionKey, principalID, lookupID, requiredLegacy sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT code_digest, client_binding::text, label, issuer_principal_id::text,
expires_at > statement_timestamp(), invalidated_at IS NULL,
redemption_key::text, redeemed_principal_id::text, credential_lookup_id::text, legacy_principal_id::text, machine_id
FROM auth.pending_enrollments WHERE id = $1 FOR UPDATE`, redeem.EnrollmentID).Scan(&storedCode, &storedBinding, &label, &issuer, &unexpired, &active, &redemptionKey, &principalID, &lookupID, &requiredLegacy, &machineID)
	if err != nil || storedBinding != redeem.ClientBinding || subtle.ConstantTimeCompare(storedCode, codeDigest[:]) != 1 || requiredLegacy.Valid != (legacyProof != nil) {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	// Expiry prevents the first redemption, but a row already bound to this
	// idempotency key must remain recoverable after a lost response. An
	// invalidated enrollment remains unavailable in either state.
	if !active || (!unexpired && !redemptionKey.Valid) {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	if requiredLegacy.Valid {
		if err := lockLegacyMutations(ctx, tx); err != nil {
			return DeviceCredential{}, err
		}
		var registeredPublicKey []byte
		var legacyState string
		var migratedLookupID sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT public_key, state, migrated_credential_lookup_id::text FROM auth.legacy_machines WHERE principal_id = $1`, requiredLegacy.String).Scan(&registeredPublicKey, &legacyState, &migratedLookupID); err != nil || subtle.ConstantTimeCompare(registeredPublicKey, legacyProof.PublicKey) != 1 || !ed25519.Verify(legacyProof.PublicKey, legacyExchangeTranscript(redeem, codeDigest), legacyProof.Signature) {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
		if redemptionKey.Valid {
			if legacyState != string(LegacyMigrated) || !migratedLookupID.Valid || !lookupID.Valid || migratedLookupID.String != lookupID.String {
				return DeviceCredential{}, ErrInvalidEnrollment
			}
		} else if legacyState != string(LegacyPending) {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
	}
	if redemptionKey.Valid {
		if redemptionKey.String != redeem.IdempotencyKey {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
		var storedDigest []byte
		var generation int64
		var expiresAt sql.NullTime
		var clientID, installedMachineID, endpointPrefix string
		if err := tx.QueryRowContext(ctx, `SELECT credential.secret_digest, credential.generation, credential.expires_at,
client.id::text, client.machine_id, authority.endpoint_prefix
FROM auth.device_credentials AS credential
JOIN auth.principals AS principal ON principal.id = credential.principal_id
JOIN auth.client_installations AS client ON client.credential_lookup_id = credential.lookup_id
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
WHERE credential.lookup_id = $1 AND credential.principal_id = $2
AND credential.revoked_at IS NULL
AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
AND principal.disabled_at IS NULL AND client.lifecycle_state = 'active'`, lookupID.String, principalID.String).Scan(&storedDigest, &generation, &expiresAt, &clientID, &installedMachineID, &endpointPrefix); err != nil || subtle.ConstantTimeCompare(storedDigest, secretDigest[:]) != 1 {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
		return DeviceCredential{ClientID: clientID, MachineID: installedMachineID, EndpointPrefix: endpointPrefix, PrincipalID: principalID.String, LookupID: lookupID.String, Encoded: encodeDeviceCredential(lookupID.String, credentialSecret[:]), Generation: generation, ExpiresAt: expiresAt.Time}, nil
	}
	projectIDs, allProjects, err := lockPendingEnrollmentGrantTargets(ctx, tx, redeem.EnrollmentID)
	if err != nil {
		return DeviceCredential{}, err
	}
	if ok, err := lockInstallationOwner(ctx, tx, issuer); err != nil || !ok {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	lookupUUID, err := uuid.NewRandom()
	if err != nil {
		return DeviceCredential{}, errors.New("credential entropy is unavailable")
	}
	lookup := lookupUUID.String()
	encodedCredential := encodeDeviceCredential(lookup, credentialSecret[:])
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.principals (kind, display_name) VALUES ('device', $1) RETURNING id::text`, label).Scan(&principalID.String); err != nil {
		return DeviceCredential{}, errors.New("device principal could not be created")
	}
	principalID.Valid = true
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth.device_credentials (lookup_id, principal_id, label, secret_digest)
VALUES ($1, $2, $3, $4)`, lookup, principalID.String, label, secretDigest[:]); err != nil {
		return DeviceCredential{}, errors.New("device credential could not be created")
	}
	var clientID string
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.client_installations (machine_id, label, principal_id, credential_lookup_id)
VALUES ($1, $2, $3, $4) RETURNING id::text`, machineID, label, principalID.String, lookup).Scan(&clientID); err != nil {
		return DeviceCredential{}, errors.New("client installation could not be created")
	}
	endpointPrefix := "agent/" + machineID + "/"
	if _, err := tx.ExecContext(ctx, `INSERT INTO relay.client_endpoint_authority (client_id, endpoint_prefix) VALUES ($1, $2)`, clientID, endpointPrefix); err != nil {
		return DeviceCredential{}, errors.New("client endpoint authority could not be created")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, project_id, capability)
SELECT $2, scope, project_id, capability FROM auth.pending_enrollment_grants WHERE enrollment_id = $1 ORDER BY ordinal`, redeem.EnrollmentID, principalID.String); err != nil {
		return DeviceCredential{}, errors.New("device grants could not be installed")
	}
	for _, projectID := range projectIDs {
		if err := advanceGrantGenerations(ctx, tx, ScopeProject, projectID); err != nil {
			return DeviceCredential{}, err
		}
	}
	if allProjects {
		if err := advanceGrantGenerations(ctx, tx, ScopeAllProjects, ""); err != nil {
			return DeviceCredential{}, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth.pending_enrollments SET redeemed_at = statement_timestamp(), redemption_key = $2, redeemed_principal_id = $3, credential_lookup_id = $4 WHERE id = $1 AND redeemed_at IS NULL`, redeem.EnrollmentID, redeem.IdempotencyKey, principalID.String, lookup)
	if err != nil {
		return DeviceCredential{}, errors.New("enrollment could not be consumed")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	if requiredLegacy.Valid {
		var transitioned bool
		if err := tx.QueryRowContext(ctx, `SELECT transitioned FROM auth.complete_legacy_exchange($1, $2) AS result(transitioned)`, requiredLegacy.String, lookup).Scan(&transitioned); err != nil || !transitioned {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: principalID.String, Action: AuditEnrollmentRedeem, Outcome: AuditSucceeded, TargetKind: AuditTargetCredential, TargetID: lookup}); err != nil {
		return DeviceCredential{}, err
	}
	if requiredLegacy.Valid {
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: requiredLegacy.String, Action: AuditLegacyExchange, Outcome: AuditSucceeded, TargetKind: AuditTargetLegacyMachine, TargetID: requiredLegacy.String}); err != nil {
			return DeviceCredential{}, err
		}
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return DeviceCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceCredential{}, errors.New("enrollment redemption could not commit")
	}
	return DeviceCredential{ClientID: clientID, MachineID: machineID, EndpointPrefix: endpointPrefix, PrincipalID: principalID.String, LookupID: lookup, Encoded: encodedCredential, Generation: 1}, nil
}

// AuthenticateDevice validates one bearer credential without distinguishing failure causes.
func (d *Database) AuthenticateDevice(ctx context.Context, encoded string) (AuthenticatedDevice, error) {
	lookupID, secret, err := parseDeviceCredential(encoded)
	if err != nil {
		return AuthenticatedDevice{}, ErrUnauthenticated
	}
	digest := sha256.Sum256(secret)
	var stored []byte
	var principalID string
	var generation int64
	var active bool
	err = d.db.QueryRowContext(ctx, `SELECT credential.secret_digest, credential.principal_id::text, credential.generation,
credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
AND principal.disabled_at IS NULL AND client.lifecycle_state = 'active'
AND client.generation = credential.generation AND authority.generation = credential.generation
FROM auth.device_credentials AS credential
JOIN auth.principals AS principal ON principal.id = credential.principal_id
JOIN auth.client_installations AS client ON client.credential_lookup_id = credential.lookup_id
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
WHERE credential.lookup_id = $1`, lookupID).Scan(&stored, &principalID, &generation, &active)
	if err != nil || !active || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return AuthenticatedDevice{}, ErrUnauthenticated
	}
	_, _ = d.db.ExecContext(ctx, `UPDATE auth.device_credentials SET last_used_at = statement_timestamp()
WHERE lookup_id = $1 AND (last_used_at IS NULL OR last_used_at < statement_timestamp() - make_interval(secs => $2))`, lookupID, int64(lastUsedWriteInterval/time.Second))
	return AuthenticatedDevice{PrincipalID: principalID, LookupID: lookupID, Generation: generation}, nil
}

// DeviceSessionCurrent revalidates a cache/session generation against revocation and expiry.
func (d *Database) DeviceSessionCurrent(ctx context.Context, authenticated AuthenticatedDevice) (bool, error) {
	if !validOpaqueID(authenticated.PrincipalID) || !validOpaqueID(authenticated.LookupID) || authenticated.Generation < 1 {
		return false, nil
	}
	var current bool
	err := d.db.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM auth.device_credentials AS credential
JOIN auth.principals AS principal ON principal.id = credential.principal_id
JOIN auth.client_installations AS client ON client.credential_lookup_id = credential.lookup_id
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
WHERE credential.lookup_id = $1 AND credential.principal_id = $2 AND credential.generation = $3
AND credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
AND principal.disabled_at IS NULL AND client.lifecycle_state = 'active'
AND client.generation = credential.generation AND authority.generation = credential.generation)`, authenticated.LookupID, authenticated.PrincipalID, authenticated.Generation).Scan(&current)
	if err != nil {
		return false, errors.New("device session could not be revalidated")
	}
	return current, nil
}

// SelfRevokeDevice permanently revokes only the client authenticated by the
// supplied bearer credential. An already-revoked credential is accepted only
// for an exact retry of a self-revocation that previously committed.
func (d *Database) SelfRevokeDevice(ctx context.Context, encoded, idempotencyKey string) (DeviceRevocation, error) {
	lookupID, secret, err := parseDeviceCredential(encoded)
	if err != nil || !validOpaqueID(idempotencyKey) {
		return DeviceRevocation{}, ErrUnauthenticated
	}
	digest := sha256.Sum256(secret)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return DeviceRevocation{}, mutationStartError(err, "self-revocation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockEnrollmentMutations(ctx, tx); err != nil {
		return DeviceRevocation{}, err
	}
	var storedDigest []byte
	var principalID, clientID, lifecycleState string
	var credentialRevoked, principalDisabled bool
	var credentialUnexpired bool
	var credentialGeneration, clientGeneration, authorityGeneration int64
	var priorKey sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT credential.secret_digest, credential.principal_id::text,
credential.revoked_at IS NOT NULL, principal.disabled_at IS NOT NULL,
credential.expires_at IS NULL OR credential.expires_at > statement_timestamp(),
credential.generation, client.generation, authority.generation,
client.id::text, client.lifecycle_state, client.self_revoke_idempotency::text
FROM auth.device_credentials AS credential
JOIN auth.principals AS principal ON principal.id = credential.principal_id
JOIN auth.client_installations AS client ON client.credential_lookup_id = credential.lookup_id
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
WHERE credential.lookup_id = $1
FOR UPDATE OF credential, principal, client, authority`, lookupID).Scan(&storedDigest, &principalID, &credentialRevoked, &principalDisabled, &credentialUnexpired, &credentialGeneration, &clientGeneration, &authorityGeneration, &clientID, &lifecycleState, &priorKey)
	if err != nil || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return DeviceRevocation{}, ErrUnauthenticated
	}
	generationCurrent := credentialGeneration == clientGeneration && clientGeneration == authorityGeneration
	if credentialRevoked || lifecycleState == "revoked" || principalDisabled {
		if credentialRevoked && lifecycleState == "revoked" && generationCurrent && priorKey.Valid && priorKey.String == idempotencyKey {
			if err := tx.Commit(); err != nil {
				return DeviceRevocation{}, errors.New("self-revocation replay cannot commit")
			}
			return DeviceRevocation{Status: "revoked"}, nil
		}
		return DeviceRevocation{}, ErrUnauthenticated
	}
	if !credentialUnexpired || !generationCurrent {
		return DeviceRevocation{}, ErrUnauthenticated
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth.device_credentials
SET revoked_at = statement_timestamp(), generation = generation + 1
WHERE lookup_id = $1 AND revoked_at IS NULL`, lookupID)
	if err != nil {
		return DeviceRevocation{}, errors.New("credential could not be self-revoked")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return DeviceRevocation{}, ErrUnauthenticated
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth.principals SET auth_generation = auth_generation + 1 WHERE id = $1`, principalID); err != nil {
		return DeviceRevocation{}, errors.New("self-revocation principal fence could not be advanced")
	}
	result, err = tx.ExecContext(ctx, `UPDATE auth.client_installations
SET lifecycle_state = 'revoked', revoked_at = statement_timestamp(), revocation_reason = 'self',
    self_revoke_idempotency = $2, generation = generation + 1
WHERE id = $1 AND lifecycle_state = 'active'`, clientID, idempotencyKey)
	if err != nil {
		return DeviceRevocation{}, errors.New("client could not be self-revoked")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return DeviceRevocation{}, ErrUnauthenticated
	}
	if update, err := tx.ExecContext(ctx, `UPDATE relay.client_endpoint_authority SET generation = generation + 1 WHERE client_id = $1`, clientID); err != nil {
		return DeviceRevocation{}, errors.New("self-revocation endpoint fence could not be advanced")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return DeviceRevocation{}, errors.New("self-revocation endpoint authority is unavailable")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: principalID, Action: AuditCredentialRevoke, Outcome: AuditSucceeded, TargetKind: AuditTargetCredential, TargetID: lookupID}); err != nil {
		return DeviceRevocation{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return DeviceRevocation{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceRevocation{}, errors.New("self-revocation could not commit")
	}
	return DeviceRevocation{Status: "revoked"}, nil
}

// BeginDeviceCredentialRotation creates or replaces a pending rotation while
// leaving the current credential fully usable until completion.
func (a *Administration) BeginDeviceCredentialRotation(ctx context.Context, actorPrincipalID, lookupID string, expectedGeneration int64) (PendingCredentialRotation, error) {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(lookupID) || expectedGeneration < 1 {
		return PendingCredentialRotation{}, errors.New("invalid credential rotation")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return PendingCredentialRotation{}, err
	}
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return PendingCredentialRotation{}, errors.New("credential rotation entropy is unavailable")
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	digest := sha256.Sum256(codeBytes)
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return PendingCredentialRotation{}, mutationStartError(err, "credential rotation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return PendingCredentialRotation{}, ErrForbidden
	}
	var pending PendingCredentialRotation
	pending.LookupID, pending.ExpectedGeneration, pending.Code = lookupID, expectedGeneration, code
	err = tx.QueryRowContext(ctx, `UPDATE auth.device_credentials
SET rotation_code_digest = $3, rotation_expected_generation = $2,
    rotation_expires_at = statement_timestamp() + interval '10 minutes', rotation_completed_at = NULL
WHERE lookup_id = $1 AND generation = $2 AND revoked_at IS NULL
RETURNING rotation_expires_at`, lookupID, expectedGeneration, digest[:]).Scan(&pending.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingCredentialRotation{}, ErrCredentialChanged
	}
	if err != nil {
		return PendingCredentialRotation{}, errors.New("credential rotation could not be staged")
	}
	if err := tx.Commit(); err != nil {
		return PendingCredentialRotation{}, errors.New("credential rotation could not commit")
	}
	return pending, nil
}

// RotateDeviceCredential replaces the digest and advances the session fence atomically.
func (a *Administration) RotateDeviceCredential(ctx context.Context, actorPrincipalID string, rotate RotateCredential) (DeviceCredential, error) {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(rotate.LookupID) || rotate.ExpectedGeneration < 1 {
		return DeviceCredential{}, errors.New("invalid credential rotation")
	}
	codeBytes, err := base64.RawURLEncoding.Strict().DecodeString(rotate.Code)
	if err != nil || len(codeBytes) != 32 || base64.RawURLEncoding.EncodeToString(codeBytes) != rotate.Code {
		return DeviceCredential{}, errors.New("invalid credential rotation")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return DeviceCredential{}, err
	}
	codeDigest := sha256.Sum256(codeBytes)
	secret := deriveRotationCredentialSecret(rotate, codeBytes)
	digest := sha256.Sum256(secret[:])
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return DeviceCredential{}, mutationStartError(err, "credential rotation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return DeviceCredential{}, ErrForbidden
	}
	if err := lockEnrollmentMutations(ctx, tx); err != nil {
		return DeviceCredential{}, err
	}
	var result DeviceCredential
	result.LookupID = rotate.LookupID
	var expiry sql.NullTime
	var currentGeneration int64
	var storedCode []byte
	var storedExpected sql.NullInt64
	var rotationUsable bool
	var completed bool
	var revoked bool
	var clientGeneration, authorityGeneration int64
	err = tx.QueryRowContext(ctx, `SELECT credential.principal_id::text, credential.generation, credential.rotation_code_digest, credential.rotation_expected_generation,
COALESCE(rotation_expires_at > statement_timestamp(), false), rotation_completed_at IS NOT NULL, credential.revoked_at IS NOT NULL, credential.expires_at,
client.id::text, client.machine_id, authority.endpoint_prefix, client.generation, authority.generation
FROM auth.device_credentials AS credential
JOIN auth.client_installations AS client ON client.credential_lookup_id = credential.lookup_id
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
WHERE credential.lookup_id = $1 AND client.lifecycle_state = 'active'
FOR UPDATE OF credential, client, authority`, rotate.LookupID).Scan(&result.PrincipalID, &currentGeneration, &storedCode, &storedExpected, &rotationUsable, &completed, &revoked, &expiry, &result.ClientID, &result.MachineID, &result.EndpointPrefix, &clientGeneration, &authorityGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCredential{}, ErrNotFound
	}
	if err != nil {
		return DeviceCredential{}, errors.New("credential could not be locked")
	}
	result.ExpiresAt = expiry.Time
	if revoked || clientGeneration != currentGeneration || authorityGeneration != currentGeneration || !storedExpected.Valid || storedExpected.Int64 != rotate.ExpectedGeneration || subtle.ConstantTimeCompare(storedCode, codeDigest[:]) != 1 {
		return DeviceCredential{}, ErrCredentialChanged
	}
	if !rotationUsable {
		return DeviceCredential{}, ErrCredentialChanged
	}
	if completed {
		if currentGeneration != rotate.ExpectedGeneration+1 {
			return DeviceCredential{}, ErrCredentialChanged
		}
		result.Generation = currentGeneration
		result.Encoded = encodeDeviceCredential(rotate.LookupID, secret[:])
		return result, nil
	}
	if currentGeneration != rotate.ExpectedGeneration {
		return DeviceCredential{}, ErrCredentialChanged
	}
	err = tx.QueryRowContext(ctx, `UPDATE auth.device_credentials SET secret_digest = $2, generation = generation + 1,
rotated_at = statement_timestamp(), rotation_completed_at = statement_timestamp()
WHERE lookup_id = $1 AND revoked_at IS NULL AND generation = $3 AND rotation_completed_at IS NULL
RETURNING generation`, rotate.LookupID, digest[:], rotate.ExpectedGeneration).Scan(&result.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCredential{}, ErrCredentialChanged
	}
	if err != nil {
		return DeviceCredential{}, errors.New("credential could not be rotated")
	}
	result.Encoded = encodeDeviceCredential(rotate.LookupID, secret[:])
	if _, err := tx.ExecContext(ctx, `UPDATE auth.principals SET auth_generation = auth_generation + 1 WHERE id = $1`, result.PrincipalID); err != nil {
		return DeviceCredential{}, errors.New("credential fence could not be advanced")
	}
	if update, err := tx.ExecContext(ctx, `UPDATE auth.client_installations SET generation = $2 WHERE id = $1 AND generation = $3 AND lifecycle_state = 'active'`, result.ClientID, result.Generation, rotate.ExpectedGeneration); err != nil {
		return DeviceCredential{}, errors.New("client fence could not be advanced")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return DeviceCredential{}, ErrCredentialChanged
	}
	if update, err := tx.ExecContext(ctx, `UPDATE relay.client_endpoint_authority SET generation = $2 WHERE client_id = $1 AND generation = $3`, result.ClientID, result.Generation, rotate.ExpectedGeneration); err != nil {
		return DeviceCredential{}, errors.New("client endpoint fence could not be advanced")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return DeviceCredential{}, ErrCredentialChanged
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditCredentialRotate, Outcome: AuditSucceeded, TargetKind: AuditTargetCredential, TargetID: rotate.LookupID}); err != nil {
		return DeviceCredential{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return DeviceCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceCredential{}, errors.New("credential rotation could not commit")
	}
	return result, nil
}

// RevokeDeviceCredential permanently revokes one credential and advances its fence.
func (a *Administration) RevokeDeviceCredential(ctx context.Context, actorPrincipalID, lookupID string) error {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(lookupID) {
		return errors.New("invalid credential revocation")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return err
	}
	var clientID string
	err := a.db.QueryRowContext(ctx, `SELECT id::text FROM auth.client_installations WHERE credential_lookup_id = $1`, lookupID).Scan(&clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("credential client could not be resolved")
	}
	return a.RevokeClient(ctx, actorPrincipalID, clientID, "replaced")
}

// ListDeviceCredentials returns bounded metadata without secrets or digests.
func (a *Administration) ListDeviceCredentials(ctx context.Context, actorPrincipalID string, limit int) ([]DeviceCredentialMetadata, error) {
	if !validOpaqueID(actorPrincipalID) || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid credential inventory request")
	}
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, errors.New("credential inventory cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return nil, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT principal_id::text, lookup_id::text, label, generation, created_at, last_used_at, expires_at, rotated_at, revoked_at
FROM auth.device_credentials ORDER BY created_at, lookup_id LIMIT $1`, limit)
	if err != nil {
		return nil, errors.New("credential inventory is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var credentials []DeviceCredentialMetadata
	for rows.Next() {
		var item DeviceCredentialMetadata
		var lastUsed, expires, rotated, revoked sql.NullTime
		if err := rows.Scan(&item.PrincipalID, &item.LookupID, &item.Label, &item.Generation, &item.CreatedAt, &lastUsed, &expires, &rotated, &revoked); err != nil {
			return nil, errors.New("credential inventory is malformed")
		}
		item.LastUsedAt, item.ExpiresAt, item.RotatedAt, item.RevokedAt = lastUsed.Time, expires.Time, rotated.Time, revoked.Time
		credentials = append(credentials, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("credential inventory is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("credential inventory cannot commit")
	}
	return credentials, nil
}

// ListClients returns bounded server-authoritative client inventory without
// endpoint discovery, credential digests, or other content.
func (a *Administration) ListClients(ctx context.Context, actorPrincipalID string, limit int) ([]ClientMetadata, error) {
	if !validOpaqueID(actorPrincipalID) || limit < 1 || limit > 1000 {
		return nil, errors.New("invalid client inventory request")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return nil, err
	}
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, errors.New("client inventory cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return nil, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT client.id::text, client.machine_id, authority.endpoint_prefix,
client.principal_id::text, client.credential_lookup_id::text, client.label, client.generation,
client.lifecycle_state, client.created_at, credential.last_used_at, client.revoked_at, client.revocation_reason
FROM auth.client_installations AS client
JOIN relay.client_endpoint_authority AS authority ON authority.client_id = client.id
JOIN auth.device_credentials AS credential ON credential.lookup_id = client.credential_lookup_id
ORDER BY client.created_at, client.id LIMIT $1`, limit)
	if err != nil {
		return nil, errors.New("client inventory is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var clients []ClientMetadata
	for rows.Next() {
		var item ClientMetadata
		var lastUsed, revoked sql.NullTime
		var reason sql.NullString
		if err := rows.Scan(&item.ClientID, &item.MachineID, &item.EndpointPrefix, &item.PrincipalID, &item.CredentialLookupID, &item.Label, &item.Generation, &item.LifecycleState, &item.CreatedAt, &lastUsed, &revoked, &reason); err != nil {
			return nil, errors.New("client inventory is malformed")
		}
		item.LastUsedAt, item.RevokedAt, item.RevocationReason = lastUsed.Time, revoked.Time, reason.String
		clients = append(clients, item)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("client inventory is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("client inventory cannot commit")
	}
	return clients, nil
}

// RevokeClient permanently revokes one exact client and all of its current
// authority. Repeating an already-committed owner revocation is a no-op.
func (a *Administration) RevokeClient(ctx context.Context, actorPrincipalID, clientID, reason string) error {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(clientID) || !validOwnerRevocationReason(reason) {
		return errors.New("invalid client revocation")
	}
	if err := a.requireClientLifecycleSchema(ctx); err != nil {
		return err
	}
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return mutationStartError(err, "client revocation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return ErrForbidden
	}
	if err := lockEnrollmentMutations(ctx, tx); err != nil {
		return err
	}
	var principalID, lookupID, state string
	err = tx.QueryRowContext(ctx, `SELECT principal_id::text, credential_lookup_id::text, lifecycle_state
FROM auth.client_installations WHERE id = $1 FOR UPDATE`, clientID).Scan(&principalID, &lookupID, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("client could not be locked")
	}
	if state == "revoked" {
		if err := tx.Commit(); err != nil {
			return errors.New("client revocation replay cannot commit")
		}
		return nil
	}
	if update, err := tx.ExecContext(ctx, `UPDATE auth.device_credentials
SET revoked_at = COALESCE(revoked_at, statement_timestamp()), generation = generation + CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END
WHERE lookup_id = $1`, lookupID); err != nil {
		return errors.New("client credential could not be revoked")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("client credential is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth.principals SET auth_generation = auth_generation + 1 WHERE id = $1`, principalID); err != nil {
		return errors.New("client principal fence could not be advanced")
	}
	if update, err := tx.ExecContext(ctx, `UPDATE auth.client_installations
SET lifecycle_state = 'revoked', revoked_at = statement_timestamp(), revocation_reason = $2,
    self_revoke_idempotency = NULL, generation = generation + 1
WHERE id = $1 AND lifecycle_state = 'active'`, clientID, reason); err != nil {
		return errors.New("client could not be revoked")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("client state changed during revocation")
	}
	if update, err := tx.ExecContext(ctx, `UPDATE relay.client_endpoint_authority SET generation = generation + 1 WHERE client_id = $1`, clientID); err != nil {
		return errors.New("client endpoint fence could not be advanced")
	} else if count, countErr := update.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("client endpoint authority is unavailable")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditCredentialRevoke, Outcome: AuditSucceeded, TargetKind: AuditTargetCredential, TargetID: lookupID}); err != nil {
		return err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("client revocation could not commit")
	}
	return nil
}

func validOwnerRevocationReason(reason string) bool {
	return reason == "lost" || reason == "retired" || reason == "compromised" || reason == "replaced"
}

func lockInstallationOwner(ctx context.Context, tx *sql.Tx, principalID string) (bool, error) {
	var locked string
	err := tx.QueryRowContext(ctx, `SELECT owner.principal_id::text FROM auth.installation_owner AS owner
JOIN auth.principals AS principal ON principal.id = owner.principal_id
WHERE owner.singleton AND owner.principal_id = $1 AND principal.disabled_at IS NULL
FOR SHARE OF principal`, principalID).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("installation owner could not be verified")
	}
	return true, nil
}

func pruneExpiredEnrollments(ctx context.Context, tx *sql.Tx, limit int) error {
	var pruned int64
	err := tx.QueryRowContext(ctx, `WITH candidates AS (
	SELECT enrollment.id FROM auth.pending_enrollments AS enrollment
    WHERE enrollment.invalidated_at IS NOT NULL
       OR (enrollment.redeemed_at IS NULL AND enrollment.expires_at <= statement_timestamp())
       OR (enrollment.redeemed_at IS NOT NULL AND NOT EXISTS (
           SELECT 1
           FROM auth.device_credentials AS credential
           JOIN auth.principals AS principal ON principal.id = credential.principal_id
           WHERE credential.lookup_id = enrollment.credential_lookup_id
           AND credential.principal_id = enrollment.redeemed_principal_id
           AND credential.revoked_at IS NULL
           AND credential.rotated_at IS NULL
           AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
           AND principal.disabled_at IS NULL
       ))
    ORDER BY COALESCE(enrollment.redeemed_at, enrollment.expires_at), enrollment.id LIMIT $1 FOR UPDATE SKIP LOCKED
), deleted_enrollments AS (
    DELETE FROM auth.pending_enrollments AS enrollment USING candidates
    WHERE enrollment.id = candidates.id RETURNING enrollment.id
)
SELECT count(*) FROM deleted_enrollments`, limit).Scan(&pruned)
	if err != nil {
		return errors.New("expired enrollments could not be pruned")
	}
	return nil
}

func pruneExpiredMachineEnrollment(ctx context.Context, tx *sql.Tx, machineID string) error {
	result, err := tx.ExecContext(ctx, `DELETE FROM auth.pending_enrollments
WHERE machine_id = $1 AND redeemed_at IS NULL AND invalidated_at IS NULL
AND expires_at <= statement_timestamp()`, machineID)
	if err != nil {
		return errors.New("expired machine enrollment could not be pruned")
	}
	if count, err := result.RowsAffected(); err != nil || count > 1 {
		return errors.New("expired machine enrollment prune is inconsistent")
	}
	return nil
}

func lockEnrollmentMutations(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, enrollmentMutationLockKey); err != nil {
		return errors.New("enrollment mutation cannot be serialized")
	}
	return nil
}

func encodeDeviceCredential(lookupID string, secret []byte) string {
	return lookupID + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func legacyExchangeTranscript(redeem RedeemEnrollment, codeDigest [sha256.Size]byte) []byte {
	return []byte("punaro-legacy-exchange-v1\n" + redeem.EnrollmentID + "\n" + redeem.ClientBinding + "\n" + redeem.IdempotencyKey + "\n" + hex.EncodeToString(codeDigest[:]))
}

func deriveEnrollmentCredentialSecret(redeem RedeemEnrollment, code []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("punaro-device-enrollment-v1\n" + redeem.EnrollmentID + "\n" + redeem.ClientBinding + "\n"))
	_, _ = hash.Write(code)
	var secret [sha256.Size]byte
	copy(secret[:], hash.Sum(nil))
	return secret
}

func deriveRotationCredentialSecret(rotate RotateCredential, code []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("punaro-device-rotation-v1\n" + rotate.LookupID + "\n" + strconv.FormatInt(rotate.ExpectedGeneration, 10) + "\n"))
	_, _ = hash.Write(code)
	var secret [sha256.Size]byte
	copy(secret[:], hash.Sum(nil))
	return secret
}
