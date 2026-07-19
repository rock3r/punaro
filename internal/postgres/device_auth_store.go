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
	bootstrapLockKey          int64 = 0x50756e61726f4f57
	enrollmentMutationLockKey int64 = 0x50756e61726f454e
	maxPendingEnrollments           = 1000
	lastUsedWriteInterval           = 5 * time.Minute
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
	if state := Classify(snapshot, CurrentManifest()); state.Classification != Compatible {
		_ = db.Close()
		return nil, contentFreeMigrationError(state.Classification)
	}
	return &Administration{db: db}, nil
}

// Close releases the host-local owner connection pool.
func (a *Administration) Close() error { return a.db.Close() }

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
	PrincipalID string    `json:"principal_id"`
	LookupID    string    `json:"lookup_id"`
	Encoded     string    `json:"credential"`
	Generation  int64     `json:"generation"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
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
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
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
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, errors.New("owner bootstrap cannot start")
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
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingEnrollment{}, errors.New("enrollment transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		if err != nil {
			return PendingEnrollment{}, err
		}
		return PendingEnrollment{}, ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, enrollmentMutationLockKey); err != nil {
		return PendingEnrollment{}, errors.New("enrollment mutation cannot be serialized")
	}
	if err := pruneExpiredEnrollments(ctx, tx, 100); err != nil {
		return PendingEnrollment{}, err
	}
	var pendingCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM auth.pending_enrollments WHERE redeemed_at IS NULL AND expires_at > statement_timestamp()`).Scan(&pendingCount); err != nil || pendingCount >= maxPendingEnrollments {
		return PendingEnrollment{}, errors.New("pending enrollment capacity is unavailable")
	}
	var bindingExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.pending_enrollments WHERE client_binding = $1 AND redeemed_at IS NULL AND expires_at > statement_timestamp())`, request.ClientBinding).Scan(&bindingExists); err != nil || bindingExists {
		return PendingEnrollment{}, errors.New("client already has a pending enrollment")
	}
	for _, projectID := range request.ProjectIDs {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM relay.projects WHERE id = $1 AND merged_into IS NULL)`, projectID).Scan(&exists); err != nil || !exists {
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
	var credentialTTL any
	if request.CredentialTTL > 0 {
		credentialTTL = int64(request.CredentialTTL / time.Second)
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.pending_enrollments
(issuer_principal_id, client_binding, label, code_digest, preview_hash, expires_at, credential_ttl_seconds, legacy_principal_id)
VALUES ($1, $2, $3, $4, $5, statement_timestamp() + make_interval(secs => $6),
$7, $8)
RETURNING id::text, expires_at`, actorPrincipalID, request.ClientBinding, request.Label, codeDigest[:], previewDigest, int64(request.TTL/time.Second), credentialTTL, nullableID(request.LegacyPrincipalID)).Scan(&pending.ID, &pending.ExpiresAt); err != nil {
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
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceCredential{}, errors.New("enrollment redemption cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var storedCode []byte
	var storedBinding, label, issuer string
	var usable bool
	var redemptionKey, principalID, lookupID, requiredLegacy sql.NullString
	var credentialTTL sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT code_digest, client_binding::text, label, issuer_principal_id::text,
expires_at > statement_timestamp(), redemption_key::text, redeemed_principal_id::text, credential_lookup_id::text, credential_ttl_seconds, legacy_principal_id::text
FROM auth.pending_enrollments WHERE id = $1 FOR UPDATE`, redeem.EnrollmentID).Scan(&storedCode, &storedBinding, &label, &issuer, &usable, &redemptionKey, &principalID, &lookupID, &credentialTTL, &requiredLegacy)
	if err != nil || storedBinding != redeem.ClientBinding || subtle.ConstantTimeCompare(storedCode, codeDigest[:]) != 1 || requiredLegacy.Valid != (legacyProof != nil) {
		return DeviceCredential{}, ErrInvalidEnrollment
	}
	if !usable {
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
		if err := tx.QueryRowContext(ctx, `SELECT secret_digest, generation, expires_at FROM auth.device_credentials WHERE lookup_id = $1 AND principal_id = $2`, lookupID.String, principalID.String).Scan(&storedDigest, &generation, &expiresAt); err != nil || subtle.ConstantTimeCompare(storedDigest, secretDigest[:]) != 1 {
			return DeviceCredential{}, ErrInvalidEnrollment
		}
		return DeviceCredential{PrincipalID: principalID.String, LookupID: lookupID.String, Encoded: encodeDeviceCredential(lookupID.String, credentialSecret[:]), Generation: generation, ExpiresAt: expiresAt.Time}, nil
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
	var credentialExpiresAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.device_credentials (lookup_id, principal_id, label, secret_digest, expires_at)
VALUES ($1, $2, $3, $4, CASE WHEN $5::bigint IS NULL THEN NULL ELSE statement_timestamp() + make_interval(secs => $5) END)
RETURNING expires_at`, lookup, principalID.String, label, secretDigest[:], nullableInt64(credentialTTL)).Scan(&credentialExpiresAt); err != nil {
		return DeviceCredential{}, errors.New("device credential could not be created")
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
	return DeviceCredential{PrincipalID: principalID.String, LookupID: lookup, Encoded: encodedCredential, Generation: 1, ExpiresAt: credentialExpiresAt.Time}, nil
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
credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp()) AND principal.disabled_at IS NULL
FROM auth.device_credentials AS credential JOIN auth.principals AS principal ON principal.id = credential.principal_id
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
SELECT 1 FROM auth.device_credentials AS credential JOIN auth.principals AS principal ON principal.id = credential.principal_id
WHERE credential.lookup_id = $1 AND credential.principal_id = $2 AND credential.generation = $3
AND credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp()) AND principal.disabled_at IS NULL)`, authenticated.LookupID, authenticated.PrincipalID, authenticated.Generation).Scan(&current)
	if err != nil {
		return false, errors.New("device session could not be revalidated")
	}
	return current, nil
}

// BeginDeviceCredentialRotation creates or replaces a pending rotation while
// leaving the current credential fully usable until completion.
func (a *Administration) BeginDeviceCredentialRotation(ctx context.Context, actorPrincipalID, lookupID string, expectedGeneration int64) (PendingCredentialRotation, error) {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(lookupID) || expectedGeneration < 1 {
		return PendingCredentialRotation{}, errors.New("invalid credential rotation")
	}
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return PendingCredentialRotation{}, errors.New("credential rotation entropy is unavailable")
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	digest := sha256.Sum256(codeBytes)
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return PendingCredentialRotation{}, errors.New("credential rotation cannot start")
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
	codeDigest := sha256.Sum256(codeBytes)
	secret := deriveRotationCredentialSecret(rotate, codeBytes)
	digest := sha256.Sum256(secret[:])
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceCredential{}, errors.New("credential rotation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return DeviceCredential{}, ErrForbidden
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
	err = tx.QueryRowContext(ctx, `SELECT principal_id::text, generation, rotation_code_digest, rotation_expected_generation,
COALESCE(rotation_expires_at > statement_timestamp(), false), rotation_completed_at IS NOT NULL, revoked_at IS NOT NULL, expires_at
FROM auth.device_credentials WHERE lookup_id = $1 FOR UPDATE`, rotate.LookupID).Scan(&result.PrincipalID, &currentGeneration, &storedCode, &storedExpected, &rotationUsable, &completed, &revoked, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCredential{}, ErrNotFound
	}
	if err != nil {
		return DeviceCredential{}, errors.New("credential could not be locked")
	}
	result.ExpiresAt = expiry.Time
	if revoked || !storedExpected.Valid || storedExpected.Int64 != rotate.ExpectedGeneration || subtle.ConstantTimeCompare(storedCode, codeDigest[:]) != 1 {
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
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("credential revocation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return ErrForbidden
	}
	var principalID string
	err = tx.QueryRowContext(ctx, `UPDATE auth.device_credentials SET revoked_at = statement_timestamp(), generation = generation + 1
WHERE lookup_id = $1 AND revoked_at IS NULL RETURNING principal_id::text`, lookupID).Scan(&principalID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("credential could not be revoked")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth.principals SET auth_generation = auth_generation + 1 WHERE id = $1`, principalID); err != nil {
		return errors.New("credential fence could not be advanced")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditCredentialRevoke, Outcome: AuditSucceeded, TargetKind: AuditTargetCredential, TargetID: lookupID}); err != nil {
		return err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("credential revocation could not commit")
	}
	return nil
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
    SELECT id FROM auth.pending_enrollments
	WHERE expires_at <= statement_timestamp()
    ORDER BY expires_at, id LIMIT $1 FOR UPDATE SKIP LOCKED
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

func encodeDeviceCredential(lookupID string, secret []byte) string {
	return lookupID + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func nullableInt64(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
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
