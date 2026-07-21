package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
)

// LegacyMachineState is the closed Ed25519 migration inventory state.
type LegacyMachineState string

const (
	// LegacyPending is registered and eligible for one staged exchange.
	LegacyPending LegacyMachineState = "pending"
	// LegacyMigrated completed its staged exchange successfully.
	LegacyMigrated LegacyMachineState = "migrated"
	// LegacyRetired was explicitly removed from the intended migration set.
	LegacyRetired LegacyMachineState = "retired"
)

const legacyMutationLockKey int64 = 0x50756e61726f4c47

// LegacyMachine is content-free inventory; public keys and digests are omitted.
type LegacyMachine struct {
	PrincipalID string             `json:"principal_id"`
	Label       string             `json:"label"`
	State       LegacyMachineState `json:"state"`
}

// RegisterLegacyMachine records one intended current Ed25519 identity for staged exchange.
func (a *Administration) RegisterLegacyMachine(ctx context.Context, actorPrincipalID, label string, publicKey ed25519.PublicKey) (LegacyMachine, error) {
	if !validOpaqueID(actorPrincipalID) || !validDisplayName(label) || len(publicKey) != ed25519.PublicKeySize {
		return LegacyMachine{}, errors.New("invalid legacy machine")
	}
	digest := sha256.Sum256(publicKey)
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return LegacyMachine{}, mutationStartError(err, "legacy registration cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return LegacyMachine{}, ErrForbidden
	}
	// Lock in the same order as activation readiness. Once a mail cutover
	// epoch exists, no new intended legacy identity may appear between the
	// pre-retirement proof and PostgreSQL activation.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return LegacyMachine{}, errors.New("legacy registration cannot be serialized with mail cutover")
	}
	var cutoverActive bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM relay.mail_cutover_epochs WHERE phase IN ('importing','verified','active'))`).Scan(&cutoverActive); err != nil {
		return LegacyMachine{}, errors.New("legacy registration cannot inspect mail cutover")
	}
	if cutoverActive {
		return LegacyMachine{}, errors.New("legacy registration is unavailable during mail cutover")
	}
	if err := lockLegacyMutations(ctx, tx); err != nil {
		return LegacyMachine{}, err
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM auth.legacy_auth_state WHERE singleton FOR UPDATE`).Scan(&enabled); err != nil || !enabled {
		return LegacyMachine{}, errors.New("legacy authentication is disabled")
	}
	var machine LegacyMachine
	machine.Label = label
	machine.State = LegacyPending
	if err := tx.QueryRowContext(ctx, `INSERT INTO auth.principals (kind, display_name) VALUES ('legacy_machine', $1) RETURNING id::text`, label).Scan(&machine.PrincipalID); err != nil {
		return LegacyMachine{}, errors.New("legacy principal could not be created")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth.legacy_machines (principal_id, public_key, public_key_digest) VALUES ($1, $2, $3)`, machine.PrincipalID, []byte(publicKey), digest[:]); err != nil {
		return LegacyMachine{}, errors.New("legacy machine could not be registered")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditLegacyRegister, Outcome: AuditSucceeded, TargetKind: AuditTargetLegacyMachine, TargetID: machine.PrincipalID}); err != nil {
		return LegacyMachine{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return LegacyMachine{}, err
	}
	if err := tx.Commit(); err != nil {
		return LegacyMachine{}, errors.New("legacy registration could not commit")
	}
	return machine, nil
}

// ResolveLegacyMachine maps a key only after the existing Ed25519 request
// verifier has authenticated it. It never treats a friendly machine label as authority.
func (d *Database) ResolveLegacyMachine(ctx context.Context, publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrUnauthenticated
	}
	digest := sha256.Sum256(publicKey)
	var principalID string
	var enabled bool
	err := d.db.QueryRowContext(ctx, `SELECT machine.principal_id::text, state.enabled
FROM auth.legacy_machines AS machine
JOIN auth.principals AS principal ON principal.id = machine.principal_id
CROSS JOIN auth.legacy_auth_state AS state
WHERE machine.public_key_digest = $1 AND machine.public_key = $2 AND machine.state <> 'retired' AND principal.disabled_at IS NULL AND state.singleton`, digest[:], []byte(publicKey)).Scan(&principalID, &enabled)
	if err != nil || !enabled {
		return "", ErrUnauthenticated
	}
	return principalID, nil
}

// ResolveMigratedLegacyPublicKey maps a currently valid device session back to
// the exact Ed25519 enrollment it replaced. The public key is an opaque join
// handle into the daemon's static machine configuration; endpoint authority is
// never copied into PostgreSQL or reconstructed from labels and principal IDs.
func (d *Database) ResolveMigratedLegacyPublicKey(ctx context.Context, authenticated AuthenticatedDevice) (ed25519.PublicKey, error) {
	if !validOpaqueID(authenticated.PrincipalID) || !validOpaqueID(authenticated.LookupID) || authenticated.Generation < 1 {
		return nil, ErrUnauthenticated
	}
	var publicKey []byte
	err := d.db.QueryRowContext(ctx, `SELECT machine.public_key
FROM auth.legacy_machines AS machine
JOIN auth.device_credentials AS credential ON credential.lookup_id = machine.migrated_credential_lookup_id
JOIN auth.principals AS principal ON principal.id = credential.principal_id
WHERE machine.state = 'migrated'
  AND credential.lookup_id = $1 AND credential.principal_id = $2 AND credential.generation = $3
  AND credential.revoked_at IS NULL
  AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
  AND principal.disabled_at IS NULL`, authenticated.LookupID, authenticated.PrincipalID, authenticated.Generation).Scan(&publicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrUnauthenticated
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

// ListLegacyMachines returns bounded content-free migration inventory.
func (a *Administration) ListLegacyMachines(ctx context.Context, actorPrincipalID string) ([]LegacyMachine, error) {
	if !validOpaqueID(actorPrincipalID) {
		return nil, errors.New("invalid legacy inventory request")
	}
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, errors.New("legacy inventory cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return nil, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT machine.principal_id::text, principal.display_name, machine.state
FROM auth.legacy_machines AS machine JOIN auth.principals AS principal ON principal.id = machine.principal_id
ORDER BY machine.created_at, machine.principal_id LIMIT 1000`)
	if err != nil {
		return nil, errors.New("legacy inventory is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var machines []LegacyMachine
	for rows.Next() {
		var machine LegacyMachine
		if err := rows.Scan(&machine.PrincipalID, &machine.Label, &machine.State); err != nil {
			return nil, errors.New("legacy inventory is malformed")
		}
		machines = append(machines, machine)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("legacy inventory is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("legacy inventory cannot commit")
	}
	return machines, nil
}

// RetireLegacyMachine explicitly resolves an intended machine without migration.
func (a *Administration) RetireLegacyMachine(ctx context.Context, actorPrincipalID, legacyPrincipalID string) error {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(legacyPrincipalID) {
		return errors.New("invalid legacy retirement")
	}
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return mutationStartError(err, "legacy retirement cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return ErrForbidden
	}
	if err := lockLegacyMutations(ctx, tx); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth.legacy_machines SET state = 'retired', migrated_credential_lookup_id = NULL, changed_at = statement_timestamp() WHERE principal_id = $1 AND state <> 'retired'`, legacyPrincipalID)
	if err != nil {
		return errors.New("legacy machine could not be retired")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrNotFound
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditLegacyRetire, Outcome: AuditSucceeded, TargetKind: AuditTargetLegacyMachine, TargetID: legacyPrincipalID}); err != nil {
		return err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("legacy retirement could not commit")
	}
	return nil
}

// DisableLegacyAuthentication closes the staged legacy gate only after every
// intended machine is migrated or explicitly retired.
func (a *Administration) DisableLegacyAuthentication(ctx context.Context, actorPrincipalID string) error {
	if !validOpaqueID(actorPrincipalID) {
		return errors.New("invalid legacy disable request")
	}
	tx, err := beginMutation(ctx, a.db)
	if err != nil {
		return mutationStartError(err, "legacy disable cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return ErrForbidden
	}
	if err := lockLegacyMutations(ctx, tx); err != nil {
		return err
	}
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE state = 'pending')`).Scan(&pending); err != nil {
		return errors.New("legacy inventory is unavailable")
	}
	if pending {
		return errors.New("legacy authentication still has pending machines")
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth.legacy_auth_state SET enabled = false, changed_at = statement_timestamp() WHERE singleton AND enabled`)
	if err != nil {
		return errors.New("legacy authentication could not be disabled")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrNotFound
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditLegacyDisable, Outcome: AuditSucceeded, TargetKind: AuditTargetLegacyMachine}); err != nil {
		return err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("legacy disable could not commit")
	}
	return nil
}

func lockLegacyMutations(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, legacyMutationLockKey); err != nil {
		return errors.New("legacy mutation could not be serialized")
	}
	return nil
}
