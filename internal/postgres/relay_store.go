package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

var _ relay.Backend = (*Database)(nil)
var _ relay.RoleBindingBackend = (*Database)(nil)
var _ relay.RoleProfileBackend = (*Database)(nil)
var _ relay.DirectMessageBackend = (*Database)(nil)
var _ relay.ControlBackend = (*Database)(nil)
var _ relay.DisplayNameBackend = (*Database)(nil)
var _ relay.TelegramClaimBackend = (*Database)(nil)

const postgresRelayMaxMessageBytes = 32 << 10

// ConsumeRequestNonce atomically consumes one signed-request replay token
// through the schema-owner routine. The application role cannot delete nonce
// rows directly and therefore cannot reopen a replay window.
func (d *Database) ConsumeRequestNonce(machineID, nonce string, now, expiresAt time.Time) error {
	if !relay.ValidMachineID(machineID) || !relay.ValidRequestToken(nonce) || !expiresAt.After(now) {
		return relay.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var consumed bool
	if err := d.relayPool().QueryRowContext(ctx, `SELECT relay.consume_mail_request_nonce($1,$2,$3,$4)`, machineID, nonce, now.UTC(), expiresAt.UTC()).Scan(&consumed); err != nil {
		return relayDatabaseError(err, "consume request nonce")
	}
	if !consumed {
		return relay.ErrForbidden
	}
	return nil
}

// AdvertiseEndpoints atomically replaces one machine's active attachment set.
func (d *Database) AdvertiseEndpoints(machineID string, endpoints []string, now time.Time, ttl time.Duration) error {
	return d.advertiseEndpoints(machineID, relay.PrincipalAuthority{}, endpoints, now, ttl)
}

// AdvertiseEndpointsForPrincipal publishes endpoint leases and their stable
// recipient-snapshot principal in one transaction.
func (d *Database) AdvertiseEndpointsForPrincipal(machineID string, authority relay.PrincipalAuthority, endpoints []string, now time.Time, ttl time.Duration) error {
	if !validOpaqueID(authority.PrincipalID) || !validOpaqueID(authority.CredentialLookupID) || authority.CredentialGeneration < 1 {
		return errors.New("invalid endpoint principal")
	}
	return d.advertiseEndpoints(machineID, authority, endpoints, now, ttl)
}

func (d *Database) advertiseEndpoints(machineID string, authority relay.PrincipalAuthority, endpoints []string, now time.Time, ttl time.Duration) error {
	if !relay.ValidMachineID(machineID) || ttl <= 0 {
		return errors.New("invalid endpoint lease")
	}
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if !relay.ValidEndpoint(endpoint) {
			return errors.New("endpoint is required")
		}
		if _, duplicate := seen[endpoint]; duplicate {
			return errors.New("duplicate endpoint")
		}
		seen[endpoint] = struct{}{}
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return errors.New("endpoint advertisement cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	orderedEndpoints := postgresSortedEndpoints(seen)
	encodedEndpoints, err := json.Marshal(orderedEndpoints)
	if err != nil {
		return errors.New("endpoint advertisement is invalid")
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT endpoint FROM relay.mail_endpoints
		WHERE (machine_id=$1 AND lease_until>$2) OR endpoint IN (SELECT value FROM jsonb_array_elements_text($3::jsonb))
		ORDER BY endpoint COLLATE "C" FOR UPDATE`, machineID, now.UTC(), string(encodedEndpoints))
	if err != nil {
		return relayDatabaseError(err, "lock endpoint advertisement")
	}
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			_ = rows.Close()
			return errors.New("endpoint advertisement lock is malformed")
		}
	}
	if err := rows.Close(); err != nil {
		return errors.New("endpoint advertisement locks are unavailable")
	}
	if err := rows.Err(); err != nil {
		return errors.New("endpoint advertisement locks are unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_endpoints
		SET lease_until=$2,ownership_generation=ownership_generation+1,consumer_id=NULL,consumer_lease_until=NULL
		WHERE machine_id=$1 AND lease_until>$2 AND endpoint NOT IN (SELECT value FROM jsonb_array_elements_text($3::jsonb))`, machineID, now.UTC(), string(encodedEndpoints)); err != nil {
		return relayDatabaseError(err, "detach endpoints")
	}
	until := now.Add(ttl).UTC()
	for _, endpoint := range orderedEndpoints {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_endpoints(endpoint,machine_id,lease_until) VALUES($1,$2,$3)
			ON CONFLICT(endpoint) DO UPDATE SET
				ownership_generation=CASE WHEN mail_endpoints.machine_id<>excluded.machine_id OR mail_endpoints.lease_until<=$4 THEN mail_endpoints.ownership_generation+1 ELSE mail_endpoints.ownership_generation END,
				consumer_id=CASE WHEN mail_endpoints.machine_id<>excluded.machine_id OR mail_endpoints.lease_until<=$4 THEN NULL ELSE mail_endpoints.consumer_id END,
				consumer_lease_until=CASE WHEN mail_endpoints.machine_id<>excluded.machine_id OR mail_endpoints.lease_until<=$4 THEN NULL ELSE mail_endpoints.consumer_lease_until END,
				machine_id=excluded.machine_id,lease_until=excluded.lease_until`, endpoint, machineID, until, now.UTC()); err != nil {
			return relayDatabaseError(err, "advertise endpoint")
		}
	}
	var roleBindingsAvailable bool
	if err := tx.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_role_bindings') IS NOT NULL`).Scan(&roleBindingsAvailable); err != nil {
		return relayDatabaseError(err, "inspect durable role bindings")
	}
	if roleBindingsAvailable {
		// A normal advertisement renews only an already-live binding for this exact
		// endpoint generation. A restarted or reclaimed endpoint must be bound
		// explicitly, so stale role authority cannot be revived by advertisement.
		for _, endpoint := range orderedEndpoints {
			if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_role_bindings AS binding
				SET lease_until=$1
				FROM relay.mail_endpoints AS endpoint
				WHERE binding.machine_id=$2 AND binding.session_endpoint=$3
				  AND binding.lease_until>$4 AND endpoint.endpoint=$3
				  AND endpoint.machine_id=$2 AND endpoint.lease_until=$1
				  AND binding.ownership_generation=endpoint.ownership_generation`, until, machineID, endpoint, now.UTC()); err != nil {
				return relayDatabaseError(err, "renew durable role binding")
			}
		}
	}
	var principalID, credentialLookupID any
	var credentialGeneration any
	if authority.PrincipalID != "" {
		principalID = authority.PrincipalID
		credentialLookupID = authority.CredentialLookupID
		credentialGeneration = authority.CredentialGeneration
	}
	var bound int
	var recipientBindingAvailable bool
	if err := tx.QueryRowContext(context.Background(), `SELECT to_regprocedure('attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone)') IS NOT NULL`).Scan(&recipientBindingAvailable); err != nil {
		return relayDatabaseError(err, "inspect endpoint principal binding")
	}
	if recipientBindingAvailable {
		if err := tx.QueryRowContext(context.Background(), `SELECT attachment.bind_endpoint_principals($1,$2,$3,$4,$5::jsonb,$6)`, machineID, principalID, credentialLookupID, credentialGeneration, string(encodedEndpoints), now.UTC()).Scan(&bound); err != nil || bound != len(orderedEndpoints) {
			return relayDatabaseError(err, "bind endpoint principals")
		}
	}
	if err := tx.Commit(); err != nil {
		return relayDatabaseError(err, "commit endpoint advertisement")
	}
	return nil
}

// BindRoleToSession explicitly attaches one durable role to a live endpoint
// currently owned by its immutable owner machine. The endpoint generation
// fences the binding against expiry or takeover.
func (d *Database) BindRoleToSession(machineID, role, endpoint string, now time.Time, ttl time.Duration) error {
	if !relay.ValidMachineID(machineID) || !relay.ValidRole(role) || role == relay.TelegramUserParticipant || !relay.ValidEndpoint(endpoint) || ttl <= 0 {
		return relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return errors.New("durable role binding cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return errors.New("durable role bindings are unavailable")
	}
	if !rolesAvailable {
		return relay.ErrForbidden
	}
	var owner string
	if err := tx.QueryRowContext(context.Background(), `SELECT machine_id FROM relay.mail_roles WHERE role=$1`, role).Scan(&owner); errors.Is(err, sql.ErrNoRows) || owner != machineID {
		return relay.ErrForbidden
	} else if err != nil {
		return errors.New("durable role ownership is unavailable")
	}
	// Lock every room this role already occupies, including still-unnamed ones,
	// then the session. Rename uses the same conversation/endpoint order so an
	// initial name cannot race a bind that would occupy two named rooms.
	conversationIDs, err := postgresConversationIDsForRole(tx, role)
	if err != nil {
		return err
	}
	if err := postgresLockOccupancy(tx, conversationIDs, map[string]struct{}{endpoint: {}}); err != nil {
		return err
	}
	generation, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now)
	if err != nil {
		return err
	}
	var endpointUntil time.Time
	if err := tx.QueryRowContext(context.Background(), `SELECT lease_until FROM relay.mail_endpoints WHERE endpoint=$1`, endpoint).Scan(&endpointUntil); err != nil {
		return errors.New("durable role endpoint is unavailable")
	}
	until := now.Add(ttl).UTC()
	if endpointUntil.Before(until) {
		until = endpointUntil
	}
	var activeRoles int
	if err := tx.QueryRowContext(context.Background(), `SELECT count(*) FROM relay.mail_role_bindings
		WHERE machine_id=$1 AND session_endpoint=$2 AND ownership_generation=$3 AND lease_until>$4 AND role<>$5`, machineID, endpoint, generation, now.UTC(), role).Scan(&activeRoles); err != nil {
		return errors.New("durable role binding count is unavailable")
	}
	if activeRoles >= relay.MaxActiveRolesPerSession {
		return relay.ErrConflict
	}
	if err := postgresRejectExclusiveBindOccupancy(tx, endpoint, role, now); err != nil {
		return err
	}
	var previousSession string
	var previousGeneration int64
	var previousLeaseUntil time.Time
	err = tx.QueryRowContext(context.Background(), `SELECT session_endpoint,ownership_generation,lease_until FROM relay.mail_role_bindings WHERE role=$1 FOR UPDATE`, role).Scan(&previousSession, &previousGeneration, &previousLeaseUntil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("durable role binding is unavailable")
	}
	rebinding := err == nil && (previousSession != endpoint || previousGeneration != generation || !previousLeaseUntil.After(now.UTC()))
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_role_bindings(role,session_endpoint,machine_id,ownership_generation,lease_until)
		VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(role) DO UPDATE SET session_endpoint=excluded.session_endpoint,machine_id=excluded.machine_id,ownership_generation=excluded.ownership_generation,lease_until=excluded.lease_until`, role, endpoint, machineID, generation, until); err != nil {
		return relayDatabaseError(err, "bind durable role")
	}
	if rebinding {
		if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries
			SET lease_machine_id=NULL,lease_token=NULL,ownership_generation=NULL,consumer_generation=NULL,lease_until=NULL
			WHERE recipient_endpoint=chr(30)||'role:'||$1 AND acked_at IS NULL`, role); err != nil {
			return relayDatabaseError(err, "invalidate rebound role leases")
		}
	}
	if err := tx.Commit(); err != nil {
		return relayDatabaseError(err, "commit durable role binding")
	}
	return nil
}

// RegisterRoleProfile creates or updates one machine-owned canonical role
// profile. Exact retries return the first result; later calls may change only
// display name and addressability.
func (d *Database) RegisterRoleProfile(input relay.RegisterRoleInput) (relay.RoleProfile, bool, error) {
	displayName, ok := relay.NormalizeRoleDisplayName(input.DisplayName)
	if !ok || !relay.ValidMachineID(input.MachineID) || !relay.ValidRequestToken(input.IdempotencyKey) || !relay.CanonicalRoleForMachine(input.Role, input.MachineID) {
		return relay.RoleProfile{}, false, fmt.Errorf("invalid role registration")
	}
	requestHash := relay.RegisterRoleRequestHash(input.Role, displayName, input.DirectAddressable)
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.RoleProfile{}, false, errors.New("role registration cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	profilesAvailable, err := postgresRoleProfilesAvailable(tx)
	if err != nil {
		return relay.RoleProfile{}, false, errors.New("durable role profiles are unavailable")
	}
	if !profilesAvailable {
		return relay.RoleProfile{}, false, relay.ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('role-profile-retry',$1::text,$2::text)::text, 579001230612))`, input.MachineID, input.IdempotencyKey); err != nil {
		return relay.RoleProfile{}, false, errors.New("role registration retry lock is unavailable")
	}
	var existingHash string
	var existingRole string
	var existingDisplay sql.NullString
	var existingAddressable bool
	var existingUpdatedAt time.Time
	err = tx.QueryRowContext(context.Background(), `SELECT request_hash,role,display_name,direct_addressable,updated_at FROM relay.mail_role_profile_idempotency WHERE machine_id=$1 AND key=$2`, input.MachineID, input.IdempotencyKey).Scan(&existingHash, &existingRole, &existingDisplay, &existingAddressable, &existingUpdatedAt)
	if err == nil {
		if existingHash != requestHash {
			return relay.RoleProfile{}, false, relay.ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return relay.RoleProfile{}, false, errors.New("role registration retry cannot commit")
		}
		return relay.RoleProfile{Role: existingRole, DisplayName: existingDisplay.String, DirectAddressable: existingAddressable, UpdatedAt: existingUpdatedAt.UTC()}, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.RoleProfile{}, false, errors.New("role registration retry state is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('durable-role',$1::text)::text, 579001230609))`, input.Role); err != nil {
		return relay.RoleProfile{}, false, errors.New("durable role creation lock is unavailable")
	}
	var owner string
	err = tx.QueryRowContext(context.Background(), `SELECT machine_id FROM relay.mail_roles WHERE role=$1`, input.Role).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_roles(role,machine_id) VALUES($1,$2)`, input.Role, input.MachineID); err != nil {
			return relay.RoleProfile{}, false, relayDatabaseError(err, "create durable role")
		}
		owner = input.MachineID
	case err != nil:
		return relay.RoleProfile{}, false, errors.New("durable role ownership is unavailable")
	case owner != input.MachineID:
		return relay.RoleProfile{}, false, relay.ErrForbidden
	}
	var existingUpdated time.Time
	err = tx.QueryRowContext(context.Background(), `SELECT updated_at FROM relay.mail_role_profiles WHERE role=$1 FOR UPDATE`, input.Role).Scan(&existingUpdated)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return relay.RoleProfile{}, false, errors.New("role profile is unavailable")
	}
	var display any
	if displayName != "" {
		display = displayName
	}
	updatedAt := input.Now.UTC().Truncate(time.Millisecond)
	if created {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_role_profiles(role,display_name,direct_addressable,updated_at) VALUES($1,$2,$3,$4)`, input.Role, display, input.DirectAddressable, updatedAt); err != nil {
			return relay.RoleProfile{}, false, relayDatabaseError(err, "create role profile")
		}
	} else if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_role_profiles SET display_name=$1,direct_addressable=$2,updated_at=$3 WHERE role=$4`, display, input.DirectAddressable, updatedAt, input.Role); err != nil {
		return relay.RoleProfile{}, false, relayDatabaseError(err, "update role profile")
	}
	profile := relay.RoleProfile{Role: input.Role, DisplayName: displayName, DirectAddressable: input.DirectAddressable, UpdatedAt: updatedAt}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_role_profile_idempotency(machine_id,key,request_hash,role,display_name,direct_addressable,updated_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, input.MachineID, input.IdempotencyKey, requestHash, input.Role, display, input.DirectAddressable, profile.UpdatedAt, updatedAt); err != nil {
		return relay.RoleProfile{}, false, relayDatabaseError(err, "record role profile retry")
	}
	if err := tx.Commit(); err != nil {
		return relay.RoleProfile{}, false, relayDatabaseError(err, "commit role registration")
	}
	return profile, created, nil
}

// RoleProfile returns one registered profile. Unregistered and legacy roles are
// indistinguishable from missing.
func (d *Database) RoleProfile(role string) (relay.RoleProfile, error) {
	if !relay.ValidRole(role) {
		return relay.RoleProfile{}, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return relay.RoleProfile{}, errors.New("role profile cannot be inspected")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	profilesAvailable, err := postgresRoleProfilesAvailable(tx)
	if err != nil {
		return relay.RoleProfile{}, errors.New("durable role profiles are unavailable")
	}
	if !profilesAvailable {
		return relay.RoleProfile{}, relay.ErrForbidden
	}
	var display sql.NullString
	var addressable bool
	var updatedAt time.Time
	err = tx.QueryRowContext(context.Background(), `SELECT display_name,direct_addressable,updated_at FROM relay.mail_role_profiles WHERE role=$1`, role).Scan(&display, &addressable, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.RoleProfile{}, relay.ErrForbidden
	}
	if err != nil {
		return relay.RoleProfile{}, errors.New("role profile is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return relay.RoleProfile{}, errors.New("role profile cannot commit")
	}
	return relay.RoleProfile{Role: role, DisplayName: display.String, DirectAddressable: addressable, UpdatedAt: updatedAt.UTC()}, nil
}

const postgresRoleDirectoryOnlineSQL = `EXISTS (
		SELECT 1 FROM relay.mail_role_bindings AS binding
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
			AND endpoint.machine_id=binding.machine_id
			AND endpoint.ownership_generation=binding.ownership_generation
		WHERE binding.role=profiles.role
			AND binding.machine_id=roles.machine_id
			AND binding.lease_until>$1
			AND endpoint.lease_until>$1
	)`

const postgresListAddressableRolesSQL = `SELECT profiles.role,profiles.display_name,roles.machine_id,` + postgresRoleDirectoryOnlineSQL + `
		FROM relay.mail_role_profiles AS profiles
		JOIN relay.mail_roles AS roles ON roles.role=profiles.role
		WHERE profiles.direct_addressable AND ($2='' OR profiles.role COLLATE "C" > $2)
		ORDER BY profiles.role COLLATE "C"
		LIMIT $3`

const postgresLookupAddressableContactSQL = `SELECT profiles.role,profiles.display_name,roles.machine_id,` + postgresRoleDirectoryOnlineSQL + `
		FROM relay.mail_role_profiles AS profiles
		JOIN relay.mail_roles AS roles ON roles.role=profiles.role
		WHERE profiles.direct_addressable AND profiles.role=$2`

const postgresResolveAddressableRoleSQL = `SELECT profiles.role,profiles.display_name,roles.machine_id,` + postgresRoleDirectoryOnlineSQL + `
		FROM relay.mail_role_profiles AS profiles
		JOIN relay.mail_roles AS roles ON roles.role=profiles.role
		WHERE profiles.direct_addressable AND profiles.role LIKE $2 ESCAPE '\'
		ORDER BY profiles.role COLLATE "C"
		LIMIT $3`

func scanPostgresRoleContact(scanner interface{ Scan(dest ...any) error }) (relay.RoleContact, error) {
	var contact relay.RoleContact
	var display sql.NullString
	if err := scanner.Scan(&contact.Role, &display, &contact.MachineID, &contact.Online); err != nil {
		return relay.RoleContact{}, err
	}
	contact.DisplayName = display.String
	return contact, nil
}

// ListAddressableRoles returns one bounded page of opted-in public roles.
func (d *Database) ListAddressableRoles(input relay.RoleListInput) (relay.RoleListPage, error) {
	after, ok := relay.DecodeRoleListCursor(input.Cursor)
	if !ok || input.Limit < 1 || input.Limit > relay.MaxRoleListLimit {
		return relay.RoleListPage{}, fmt.Errorf("invalid role directory request")
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return relay.RoleListPage{}, errors.New("role directory cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	profilesAvailable, err := postgresRoleProfilesAvailable(tx)
	if err != nil || !profilesAvailable {
		return relay.RoleListPage{}, errors.New("durable role profiles are unavailable")
	}
	now := input.Now.UTC()
	rows, err := tx.QueryContext(context.Background(), postgresListAddressableRolesSQL, now, after, input.Limit+1)
	if err != nil {
		return relay.RoleListPage{}, errors.New("role directory is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var contacts []relay.RoleContact
	for rows.Next() {
		contact, err := scanPostgresRoleContact(rows)
		if err != nil {
			return relay.RoleListPage{}, errors.New("role directory is unavailable")
		}
		contacts = append(contacts, contact)
	}
	if err := rows.Err(); err != nil {
		return relay.RoleListPage{}, errors.New("role directory is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return relay.RoleListPage{}, errors.New("role directory cannot commit")
	}
	page := relay.RoleListPage{Roles: contacts}
	if len(page.Roles) > input.Limit {
		last := page.Roles[input.Limit-1]
		page.Roles = page.Roles[:input.Limit]
		page.NextCursor = relay.EncodeRoleListCursor(last.Role)
	}
	if page.Roles == nil {
		page.Roles = []relay.RoleContact{}
	}
	return page, nil
}

func (d *Database) lookupAddressableContact(q queryer, role string, now time.Time) (relay.RoleContact, error) {
	row := q.QueryRowContext(context.Background(), postgresLookupAddressableContactSQL, now.UTC(), role)
	contact, err := scanPostgresRoleContact(row)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.RoleContact{}, relay.ErrForbidden
	}
	return contact, err
}

// ResolveAddressableRole answers one public name without guessing.
func (d *Database) ResolveAddressableRole(input relay.RoleResolveInput) (relay.RoleResolveResult, error) {
	name := strings.TrimSpace(input.Name)
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return relay.RoleResolveResult{}, errors.New("role resolution cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	profilesAvailable, err := postgresRoleProfilesAvailable(tx)
	if err != nil || !profilesAvailable {
		return relay.RoleResolveResult{}, errors.New("durable role profiles are unavailable")
	}
	now := input.Now.UTC()
	if relay.CanonicalRoleHandle(name) {
		contact, err := d.lookupAddressableContact(tx, name, now)
		if errors.Is(err, relay.ErrForbidden) {
			if err := tx.Commit(); err != nil {
				return relay.RoleResolveResult{}, errors.New("role resolution cannot commit")
			}
			return relay.RoleResolveResult{Status: relay.RoleResolveNotFound}, nil
		}
		if err != nil {
			return relay.RoleResolveResult{}, errors.New("role resolution is unavailable")
		}
		if err := tx.Commit(); err != nil {
			return relay.RoleResolveResult{}, errors.New("role resolution cannot commit")
		}
		return relay.RoleResolveResult{Status: relay.RoleResolveResolved, Role: contact.Role, DisplayName: contact.DisplayName, MachineID: contact.MachineID, Online: contact.Online}, nil
	}
	if !relay.ValidRoleSlug(name) {
		if err := tx.Commit(); err != nil {
			return relay.RoleResolveResult{}, errors.New("role resolution cannot commit")
		}
		return relay.RoleResolveResult{Status: relay.RoleResolveNotFound}, nil
	}
	like := "%/" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(name)
	rows, err := tx.QueryContext(context.Background(), postgresResolveAddressableRoleSQL, now, like, relay.MaxRoleResolveMatches+1)
	if err != nil {
		return relay.RoleResolveResult{}, errors.New("role resolution is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var matches []relay.RoleResolveMatch
	for rows.Next() {
		contact, err := scanPostgresRoleContact(rows)
		if err != nil {
			return relay.RoleResolveResult{}, errors.New("role resolution is unavailable")
		}
		if slug, ok := relay.CanonicalRoleSlug(contact.Role); !ok || slug != name {
			continue
		}
		matches = append(matches, relay.RoleResolveMatch{Role: contact.Role, DisplayName: contact.DisplayName})
	}
	if err := rows.Err(); err != nil {
		return relay.RoleResolveResult{}, errors.New("role resolution is unavailable")
	}
	result := relay.RoleResolveResult{Status: relay.RoleResolveNotFound}
	switch {
	case len(matches) == 1:
		contact, err := d.lookupAddressableContact(tx, matches[0].Role, now)
		if errors.Is(err, relay.ErrForbidden) {
			result = relay.RoleResolveResult{Status: relay.RoleResolveNotFound}
			break
		}
		if err != nil {
			return relay.RoleResolveResult{}, errors.New("role resolution is unavailable")
		}
		result = relay.RoleResolveResult{Status: relay.RoleResolveResolved, Role: contact.Role, DisplayName: contact.DisplayName, MachineID: contact.MachineID, Online: contact.Online}
	case len(matches) > 1:
		if len(matches) > relay.MaxRoleResolveMatches {
			matches = matches[:relay.MaxRoleResolveMatches]
		}
		result = relay.RoleResolveResult{Status: relay.RoleResolveAmbiguous, Matches: matches}
	}
	if err := tx.Commit(); err != nil {
		return relay.RoleResolveResult{}, errors.New("role resolution cannot commit")
	}
	return result, nil
}

// SendDirectMessage creates or reuses the unique unordered-role conversation
// and appends one targeted PostgreSQL message. Exact retries return the original result.
func (d *Database) SendDirectMessage(input relay.DirectMessageInput) (relay.Message, bool, error) {
	if !relay.ValidMachineID(input.SenderMachineID) || !relay.ValidRequestToken(input.IdempotencyKey) || !relay.CanonicalRoleForMachine(input.FromRole, input.SenderMachineID) || !relay.CanonicalRoleHandle(input.ToRole) || input.FromRole == input.ToRole {
		return relay.Message{}, false, fmt.Errorf("invalid direct message request")
	}
	if len(input.Body) > postgresRelayMaxMessageBytes {
		return relay.Message{}, false, errors.New("message body exceeds limit")
	}
	if !relay.ValidMessageBody(input.Body) {
		return relay.Message{}, false, errors.New("message body is not portable UTF-8 text")
	}
	roleLow, roleHigh, ok := relay.OrderedDirectRolePair(input.FromRole, input.ToRole)
	if !ok {
		return relay.Message{}, false, fmt.Errorf("invalid direct message request")
	}
	requestHash := relay.DirectMessageRequestHash(input.FromRole, input.ToRole, input.Body)
	now := input.Now.UTC().Truncate(time.Millisecond)
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Message{}, false, errors.New("direct message cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	available, err := postgresDirectMessagesAvailable(tx)
	if err != nil {
		return relay.Message{}, false, errors.New("direct messages are unavailable")
	}
	if !available {
		return relay.Message{}, false, relay.ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('direct-message-retry',$1::text,$2::text)::text, 579001230613))`, input.SenderMachineID, input.IdempotencyKey); err != nil {
		return relay.Message{}, false, errors.New("direct message retry lock is unavailable")
	}
	var existingHash, existingMessageID string
	err = tx.QueryRowContext(context.Background(), `SELECT request_hash,message_id::text FROM relay.mail_direct_message_idempotency WHERE machine_id=$1 AND key=$2`, input.SenderMachineID, input.IdempotencyKey).Scan(&existingHash, &existingMessageID)
	if err == nil {
		if existingHash != requestHash {
			return relay.Message{}, false, relay.ErrConflict
		}
		message, err := postgresMessageByID(tx, existingMessageID)
		if err != nil {
			return relay.Message{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return relay.Message{}, false, errors.New("direct message retry cannot commit")
		}
		return message, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.Message{}, false, errors.New("direct message retry state is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('direct-conversation',$1::text,$2::text)::text, 579001230614))`, roleLow, roleHigh); err != nil {
		return relay.Message{}, false, errors.New("direct conversation lock is unavailable")
	}
	session, err := postgresLiveBoundRoleSession(tx, input.SenderMachineID, input.FromRole, now)
	if err != nil {
		return relay.Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('durable-role',$1::text)::text, 579001230609))`, input.ToRole); err != nil {
		return relay.Message{}, false, errors.New("target role profile lock is unavailable")
	}
	var addressable bool
	err = tx.QueryRowContext(context.Background(), `SELECT direct_addressable FROM relay.mail_role_profiles WHERE role=$1 FOR UPDATE`, input.ToRole).Scan(&addressable)
	if errors.Is(err, sql.ErrNoRows) || !addressable {
		return relay.Message{}, false, relay.ErrForbidden
	}
	if err != nil {
		return relay.Message{}, false, errors.New("target role profile is unavailable")
	}
	conversationID, err := postgresGetOrCreateDirectConversation(tx, roleLow, roleHigh, input.FromRole, input.ToRole, now)
	if err != nil {
		return relay.Message{}, false, err
	}
	if err := d.consumeRateLimits(tx, input.SenderMachineID, conversationID, now); err != nil {
		return relay.Message{}, false, err
	}
	if err := d.consumeQuota(tx, []string{"\x1erole:" + input.ToRole}, int64(len(input.Body))); err != nil {
		return relay.Message{}, false, err
	}
	message := relay.Message{ID: uuid.NewString(), ConversationID: conversationID, FromRole: input.FromRole, Body: input.Body, CreatedAt: now}
	if err := tx.QueryRowContext(context.Background(), `UPDATE relay.mail_conversations SET next_sequence=next_sequence+1 WHERE id=$1::uuid RETURNING next_sequence`, conversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return relay.Message{}, false, relay.ErrForbidden
	} else if err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "allocate direct message sequence")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,body,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)`, message.ID, message.ConversationID, message.Sequence, session, message.Body, message.CreatedAt); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "append direct message")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_message_from_roles(message_id,from_role) VALUES($1::uuid,$2)`, message.ID, input.FromRole); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "record direct message sender role")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint) VALUES($1::uuid,chr(30)||'role:'||$2)`, message.ID, input.ToRole); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "create direct role delivery")
	}
	if err := postgresAdvanceRecipientCursor(tx, "\x1erole:"+input.FromRole, conversationID); err != nil {
		return relay.Message{}, false, err
	}
	if err := postgresAdvanceSessionCursors(tx, input.SenderMachineID, session, conversationID, now); err != nil {
		return relay.Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_direct_message_idempotency(machine_id,key,request_hash,from_role,to_role,conversation_id,message_id,sequence,created_at) VALUES($1,$2,$3,$4,$5,$6::uuid,$7::uuid,$8,$9)`, input.SenderMachineID, input.IdempotencyKey, requestHash, input.FromRole, input.ToRole, conversationID, message.ID, message.Sequence, now); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "record direct message retry")
	}
	if err := tx.Commit(); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "commit direct message")
	}
	d.refreshPendingMetrics(context.Background(), now)
	return message, false, nil
}

func postgresRejectDirectConversationAppend(tx *sql.Tx, conversationID string) error {
	available, err := postgresDirectMessagesAvailable(tx)
	if err != nil {
		return errors.New("direct conversations are unavailable")
	}
	if !available {
		return nil
	}
	var exists bool
	if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM relay.mail_direct_conversations WHERE conversation_id=$1::uuid)`, conversationID).Scan(&exists); err != nil {
		return errors.New("direct conversation lookup is unavailable")
	}
	if exists {
		return relay.ErrForbidden
	}
	return nil
}

func postgresDirectMessagesAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_direct_conversations') IS NOT NULL AND to_regclass('relay.mail_message_from_roles') IS NOT NULL AND to_regclass('relay.mail_direct_message_idempotency') IS NOT NULL`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresLiveBoundRoleSession(tx *sql.Tx, machineID, role string, now time.Time) (string, error) {
	var session string
	err := tx.QueryRowContext(context.Background(), `SELECT binding.session_endpoint FROM relay.mail_role_bindings AS binding
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
		WHERE binding.role=$1 AND binding.machine_id=$2 AND endpoint.machine_id=$2
		  AND binding.ownership_generation=endpoint.ownership_generation
		  AND binding.lease_until>$3 AND endpoint.lease_until>$3`, role, machineID, now.UTC()).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		return "", relay.ErrForbidden
	}
	if err != nil {
		return "", errors.New("live role binding is unavailable")
	}
	return session, nil
}

func postgresGetOrCreateDirectConversation(tx *sql.Tx, roleLow, roleHigh, fromRole, toRole string, now time.Time) (string, error) {
	if _, err := tx.ExecContext(context.Background(), `SAVEPOINT create_direct_conversation`); err != nil {
		return "", errors.New("direct conversation create cannot start")
	}
	conversationID := uuid.NewString()
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversations(id,created_at) VALUES($1::uuid,$2)`, conversationID, now.UTC()); err != nil {
		return "", relayDatabaseError(err, "create direct conversation")
	}
	for _, role := range []string{fromRole, toRole} {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_role_memberships(conversation_id,role,capabilities) VALUES($1::uuid,$2,$3)`, conversationID, role, relay.CapSend|relay.CapReceive); err != nil {
			return "", relayDatabaseError(err, "add direct conversation role member")
		}
	}
	_, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_direct_conversations(role_low,role_high,conversation_id,created_at) VALUES($1,$2,$3::uuid,$4)`, roleLow, roleHigh, conversationID, now.UTC())
	if err == nil {
		if _, err := tx.ExecContext(context.Background(), `RELEASE SAVEPOINT create_direct_conversation`); err != nil {
			return "", errors.New("direct conversation create cannot commit")
		}
		return conversationID, nil
	}
	if !isSQLState(err, "23505") {
		return "", relayDatabaseError(err, "record direct conversation pair")
	}
	if _, err := tx.ExecContext(context.Background(), `ROLLBACK TO SAVEPOINT create_direct_conversation`); err != nil {
		return "", errors.New("duplicate direct conversation cannot be discarded")
	}
	if _, err := tx.ExecContext(context.Background(), `RELEASE SAVEPOINT create_direct_conversation`); err != nil {
		return "", errors.New("direct conversation savepoint cannot release")
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT conversation_id::text FROM relay.mail_direct_conversations WHERE role_low=$1 AND role_high=$2`, roleLow, roleHigh).Scan(&conversationID); err != nil {
		return "", errors.New("converged direct conversation is unavailable")
	}
	return conversationID, nil
}

func postgresRoleProfilesAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_role_profiles') IS NOT NULL AND to_regclass('relay.mail_role_profile_idempotency') IS NOT NULL`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

// AssertEndpointOwnership verifies one live PostgreSQL endpoint lease.
func (d *Database) AssertEndpointOwnership(machineID, endpoint string, now time.Time) error {
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("endpoint ownership cannot be inspected")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyControl mutates membership through the same explicit, server-authorized
// control plane as SQLite. Controls never enter mail_messages or deliveries.
func (d *Database) ApplyControl(input relay.ControlInput) (relay.ControlEvent, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.ActorMachineID) || !relay.ValidEndpoint(input.ActorEndpoint) || !relay.ValidRequestToken(input.IdempotencyKey) || !relay.ValidEndpoint(input.Member.Endpoint) || relay.ReservedRelayMember(input.Member.Endpoint) || (input.Operation != relay.ControlUpsertMember && input.Operation != relay.ControlRemoveMember) || (input.Operation == relay.ControlUpsertMember && (input.Member.Capabilities == 0 || input.Member.Capabilities&^(relay.CapSend|relay.CapReceive|relay.CapAdmin|relay.CapInvoke) != 0)) || (input.Operation == relay.ControlRemoveMember && input.Member.Capabilities != 0) {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	if _, err := uuid.Parse(input.ConversationID); err != nil {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.ControlEvent{}, false, errors.New("control transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text, 579001230610))`, input.ActorMachineID, input.IdempotencyKey); err != nil {
		return relay.ControlEvent{}, false, errors.New("control retry lock is unavailable")
	}
	// Shared with rename so occupancy mutations on one room serialize.
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 579001230611))`, input.ConversationID); err != nil {
		return relay.ControlEvent{}, false, errors.New("control conversation lock is unavailable")
	}
	if _, err := postgresEndpointOwnershipLocked(tx, input.ActorEndpoint, input.ActorMachineID, input.Now); err != nil {
		return relay.ControlEvent{}, false, err
	}
	if err := postgresLockSessionRoleBindings(tx, input.ActorMachineID, input.ActorEndpoint, input.Now); err != nil {
		return relay.ControlEvent{}, false, err
	}
	actorCapabilities, err := postgresSessionCapabilities(tx, input.ConversationID, input.ActorMachineID, input.ActorEndpoint, input.Now)
	if err != nil {
		return relay.ControlEvent{}, false, errors.New("control actor authorization is unavailable")
	}
	if actorCapabilities&relay.CapAdmin == 0 {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	revoked := 0
	requestHash := relay.ControlRequestHash(input)
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), `SELECT control_id::text,request_hash FROM relay.mail_conversation_control_idempotency WHERE machine_id=$1 AND key=$2`, input.ActorMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return relay.ControlEvent{}, false, relay.ErrConflict
		}
		event, err := postgresControlEventByID(tx, existingID)
		if err != nil {
			return relay.ControlEvent{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return relay.ControlEvent{}, false, errors.New("control retry cannot commit")
		}
		return event, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.ControlEvent{}, false, errors.New("control retry state is unavailable")
	}
	var previous relay.Capability
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2 FOR UPDATE`, input.ConversationID, input.Member.Endpoint).Scan(&previous)
	if input.Operation == relay.ControlRemoveMember && errors.Is(err, sql.ErrNoRows) {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return relay.ControlEvent{}, false, errors.New("control target state is unavailable")
	}
	if input.Operation == relay.ControlUpsertMember && errors.Is(err, sql.ErrNoRows) {
		// Occupancy (conversation then endpoint) before the live-lease read so
		// this cannot deadlock with BindRoleToSession.
		if err := postgresLockOccupancy(tx, []string{input.ConversationID}, map[string]struct{}{input.Member.Endpoint: {}}); err != nil {
			return relay.ControlEvent{}, false, err
		}
		var until time.Time
		if err := tx.QueryRowContext(context.Background(), postgresControlMemberLeaseSQL(), input.Member.Endpoint).Scan(&until); err != nil || !until.After(input.Now) {
			return relay.ControlEvent{}, false, relay.ErrForbidden
		}
		var members int
		if err := tx.QueryRowContext(context.Background(), `SELECT (SELECT count(*) FROM relay.mail_memberships WHERE conversation_id=$1::uuid) + (SELECT count(*) FROM relay.mail_role_memberships WHERE conversation_id=$1::uuid)`, input.ConversationID).Scan(&members); err != nil {
			return relay.ControlEvent{}, false, errors.New("conversation member count is unavailable")
		}
		if members >= 256 {
			return relay.ControlEvent{}, false, relay.ErrConflict
		}
	}
	if (input.Operation == relay.ControlRemoveMember || (err == nil && previous&relay.CapAdmin != 0 && input.Member.Capabilities&relay.CapAdmin == 0)) && previous&relay.CapAdmin != 0 {
		var remaining int
		if err := tx.QueryRowContext(context.Background(), `SELECT (SELECT count(*) FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND (capabilities & $2)<>0 AND endpoint<>$3) + (SELECT count(*) FROM relay.mail_role_memberships WHERE conversation_id=$1::uuid AND (capabilities & $2)<>0)`, input.ConversationID, relay.CapAdmin, input.Member.Endpoint).Scan(&remaining); err != nil {
			return relay.ControlEvent{}, false, errors.New("remaining admin state is unavailable")
		}
		if remaining == 0 {
			return relay.ControlEvent{}, false, relay.ErrConflict
		}
	}
	if input.Operation == relay.ControlUpsertMember && err == nil && previous&relay.CapReceive != 0 && input.Member.Capabilities&relay.CapReceive == 0 {
		n, err := postgresRetireConversationDeliveries(tx, input.Member.Endpoint, input.ConversationID, input.Now.UTC())
		if err != nil {
			return relay.ControlEvent{}, false, err
		}
		revoked += n
		if err := postgresAdvanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
			return relay.ControlEvent{}, false, err
		}
	}
	if input.Operation == relay.ControlUpsertMember {
		if errors.Is(err, sql.ErrNoRows) {
			exclusive, exclusiveErr := postgresConversationIsExclusive(tx, input.ConversationID)
			if exclusiveErr != nil {
				return relay.ControlEvent{}, false, exclusiveErr
			}
			if exclusive {
				if occErr := postgresSessionOccupiesOtherExclusiveConversation(tx, input.Member.Endpoint, input.ConversationID, input.Now); occErr != nil {
					return relay.ControlEvent{}, false, occErr
				}
			}
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities) VALUES($1::uuid,$2,$3) ON CONFLICT(conversation_id,endpoint) DO UPDATE SET capabilities=excluded.capabilities`, input.ConversationID, input.Member.Endpoint, input.Member.Capabilities); err != nil {
			return relay.ControlEvent{}, false, relayDatabaseError(err, "upsert conversation member")
		}
		if input.Member.Capabilities&relay.CapReceive != 0 {
			if err := postgresAdvanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
				return relay.ControlEvent{}, false, err
			}
		}
	} else {
		n, err := postgresRetireConversationDeliveries(tx, input.Member.Endpoint, input.ConversationID, input.Now.UTC())
		if err != nil {
			return relay.ControlEvent{}, false, err
		}
		revoked += n
		if err := postgresAdvanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
			return relay.ControlEvent{}, false, err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, input.ConversationID, input.Member.Endpoint); err != nil {
			return relay.ControlEvent{}, false, relayDatabaseError(err, "remove conversation member")
		}
	}
	createdAt := input.Now.UTC().Truncate(time.Microsecond)
	var latestCreatedAt sql.NullTime
	if err := tx.QueryRowContext(context.Background(), `SELECT MAX(created_at) FROM relay.mail_conversation_controls WHERE conversation_id=$1::uuid`, input.ConversationID).Scan(&latestCreatedAt); err != nil {
		return relay.ControlEvent{}, false, errors.New("control audit order is unavailable")
	}
	if latestCreatedAt.Valid && !createdAt.After(latestCreatedAt.Time) {
		createdAt = latestCreatedAt.Time.Add(time.Microsecond)
	}
	event := relay.ControlEvent{ID: uuid.NewString(), ConversationID: input.ConversationID, ActorEndpoint: input.ActorEndpoint, Operation: input.Operation, Member: input.Member, CreatedAt: createdAt}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_controls(id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7)`, event.ID, event.ConversationID, event.ActorEndpoint, event.Operation, event.Member.Endpoint, event.Member.Capabilities, event.CreatedAt); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "record control audit")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_control_idempotency(machine_id,key,request_hash,control_id,created_at) VALUES($1,$2,$3,$4::uuid,$5)`, input.ActorMachineID, input.IdempotencyKey, requestHash, event.ID, input.Now.UTC()); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "record control idempotency")
	}
	if err := tx.Commit(); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "commit control")
	}
	d.metrics.ObserveTerminals(relay.ClosedRevoked, revoked)
	d.refreshPendingMetrics(context.Background(), input.Now)
	return event, false, nil
}

// ControlAudit returns at most 100 newest content-free control records to a
// live admin endpoint on the requesting machine.
func (d *Database) ControlAudit(conversationID, machineID, actorEndpoint string, now time.Time) ([]relay.ControlEvent, error) {
	if _, err := uuid.Parse(conversationID); err != nil {
		return nil, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errors.New("control audit cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, actorEndpoint, machineID, now); err != nil {
		return nil, err
	}
	capabilities, err := postgresSessionCapabilities(tx, conversationID, machineID, actorEndpoint, now)
	if err != nil {
		return nil, errors.New("control audit authorization is unavailable")
	}
	if capabilities&relay.CapAdmin == 0 {
		return nil, relay.ErrForbidden
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT id::text,conversation_id::text,actor_endpoint,operation,member_endpoint,member_capabilities,created_at FROM relay.mail_conversation_controls WHERE conversation_id=$1::uuid ORDER BY created_at DESC,id DESC LIMIT 100`, conversationID)
	if err != nil {
		return nil, relayDatabaseError(err, "read control audit")
	}
	defer func() { _ = rows.Close() }()
	var events []relay.ControlEvent
	for rows.Next() {
		var event relay.ControlEvent
		if err := rows.Scan(&event.ID, &event.ConversationID, &event.ActorEndpoint, &event.Operation, &event.Member.Endpoint, &event.Member.Capabilities, &event.CreatedAt); err != nil {
			return nil, errors.New("control audit row is malformed")
		}
		event.CreatedAt = event.CreatedAt.UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("control audit is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("control audit cannot commit")
	}
	return events, nil
}

// SetConversationDisplayName updates a room label after rechecking a live
// admin session. A stored (machine, key) replay returns the original completed
// operation without mutating a later label; a different label on the same key
// conflicts.
func (d *Database) SetConversationDisplayName(input relay.SetDisplayNameInput) (relay.Conversation, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.ActorMachineID) || !relay.ValidEndpoint(input.ActorEndpoint) || !relay.ValidRequestToken(input.IdempotencyKey) {
		return relay.Conversation{}, false, relay.ErrForbidden
	}
	if _, err := uuid.Parse(input.ConversationID); err != nil {
		return relay.Conversation{}, false, relay.ErrForbidden
	}
	displayName, err := relay.SanitizeConversationDisplayName(input.DisplayName)
	if err != nil || displayName == "" {
		return relay.Conversation{}, false, errors.New("invalid conversation display name")
	}
	requestHash := relay.DisplayNameRequestHash(input.ConversationID, input.ActorEndpoint, displayName)
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Conversation{}, false, errors.New("display name transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return relay.Conversation{}, false, errors.New("conversation display name schema is unavailable")
	}
	if !namesAvailable {
		return relay.Conversation{}, false, errors.New("conversation display names are unavailable")
	}
	retriesAvailable, err := postgresConversationDisplayNameIdempotencyAvailable(tx)
	if err != nil {
		return relay.Conversation{}, false, errors.New("conversation display name retry schema is unavailable")
	}
	if !retriesAvailable {
		return relay.Conversation{}, false, errors.New("conversation display name retries are unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text, 579001230612))`, input.ActorMachineID, input.IdempotencyKey); err != nil {
		return relay.Conversation{}, false, errors.New("display name retry lock is unavailable")
	}
	// Shared with control upsert. Bind/rename occupancy uses row locks below.
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 579001230611))`, input.ConversationID); err != nil {
		return relay.Conversation{}, false, errors.New("display name conversation lock is unavailable")
	}
	if _, err := postgresEndpointOwnershipLocked(tx, input.ActorEndpoint, input.ActorMachineID, input.Now); err != nil {
		return relay.Conversation{}, false, err
	}
	if err := postgresLockSessionRoleBindings(tx, input.ActorMachineID, input.ActorEndpoint, input.Now); err != nil {
		return relay.Conversation{}, false, err
	}
	actorCapabilities, err := postgresSessionCapabilities(tx, input.ConversationID, input.ActorMachineID, input.ActorEndpoint, input.Now)
	if err != nil {
		return relay.Conversation{}, false, errors.New("display name actor authorization is unavailable")
	}
	if actorCapabilities&relay.CapAdmin == 0 {
		return relay.Conversation{}, false, relay.ErrForbidden
	}
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), `SELECT conversation_id::text,request_hash FROM relay.mail_conversation_display_name_idempotency WHERE machine_id=$1 AND key=$2`, input.ActorMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return relay.Conversation{}, false, relay.ErrConflict
		}
		conversation, err := postgresConversationByID(tx, existingID)
		if err != nil {
			return relay.Conversation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return relay.Conversation{}, false, errors.New("display name retry cannot commit")
		}
		return conversation, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.Conversation{}, false, errors.New("display name retry state is unavailable")
	}
	conversation, err := postgresConversationByID(tx, input.ConversationID)
	if err != nil {
		return relay.Conversation{}, false, relay.ErrForbidden
	}
	duplicate := conversation.DisplayName == displayName
	if !duplicate {
		if conversation.DisplayName == "" {
			if err := postgresRejectExclusiveRenameOccupancy(tx, input.ConversationID, input.Now); err != nil {
				return relay.Conversation{}, false, err
			}
		}
		if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_conversations SET display_name=$2 WHERE id=$1::uuid`, input.ConversationID, displayName); err != nil {
			return relay.Conversation{}, false, relayDatabaseError(err, "update conversation display name")
		}
		conversation.DisplayName = displayName
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_display_name_idempotency(machine_id,key,request_hash,conversation_id,created_at) VALUES($1,$2,$3,$4::uuid,$5)`, input.ActorMachineID, input.IdempotencyKey, requestHash, input.ConversationID, input.Now); err != nil {
		return relay.Conversation{}, false, relayDatabaseError(err, "record display name retry")
	}
	if err := tx.Commit(); err != nil {
		return relay.Conversation{}, false, relayDatabaseError(err, "commit display name")
	}
	return conversation, duplicate, nil
}

func postgresConversationDisplayNameIdempotencyAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_conversation_display_name_idempotency') IS NOT NULL`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresConversationDisplayNameAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM pg_attribute
		WHERE attrelid = to_regclass('relay.mail_conversations')
		  AND attname = 'display_name' AND attnum > 0 AND NOT attisdropped
	)`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresConversationInsertSQL(namesAvailable bool) string {
	if namesAvailable {
		return `INSERT INTO relay.mail_conversations(id,created_at,display_name) VALUES($1::uuid,$2,$3)`
	}
	return `INSERT INTO relay.mail_conversations(id,created_at) VALUES($1::uuid,$2)`
}

func postgresConversationByIDSQL(namesAvailable bool) string {
	if namesAvailable {
		return `SELECT id::text, display_name FROM relay.mail_conversations WHERE id=$1::uuid`
	}
	return `SELECT id::text FROM relay.mail_conversations WHERE id=$1::uuid`
}

func postgresConversationListSQL(rolesAvailable, namesAvailable bool) string {
	inner := `conversation.id::text AS id`
	outer := `SELECT id`
	if namesAvailable {
		inner += `, conversation.display_name`
		outer = `SELECT id, display_name`
	}
	query := outer + ` FROM (
		SELECT ` + inner + ` FROM relay.mail_conversations AS conversation
		JOIN relay.mail_memberships AS membership ON membership.conversation_id=conversation.id
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=membership.endpoint
		WHERE endpoint.machine_id=$1 AND endpoint.lease_until>$2
	`
	if rolesAvailable {
		query += `UNION
		SELECT ` + inner + ` FROM relay.mail_conversations AS conversation
		JOIN relay.mail_role_memberships AS membership ON membership.conversation_id=conversation.id
		JOIN relay.mail_role_bindings AS binding ON binding.role=membership.role
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
		WHERE binding.machine_id=$1 AND binding.lease_until>$2 AND endpoint.machine_id=$1
		  AND endpoint.lease_until>$2 AND endpoint.ownership_generation=binding.ownership_generation
	`
	}
	query += `) AS visible ORDER BY id`
	return query
}

func postgresConversationByID(tx *sql.Tx, id string) (relay.Conversation, error) {
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return relay.Conversation{}, errors.New("conversation display name schema is unavailable")
	}
	var conversation relay.Conversation
	if !namesAvailable {
		if err := tx.QueryRowContext(context.Background(), postgresConversationByIDSQL(false), id).Scan(&conversation.ID); err != nil {
			return relay.Conversation{}, errors.New("conversation is unavailable")
		}
		return conversation, nil
	}
	var displayName sql.NullString
	if err := tx.QueryRowContext(context.Background(), postgresConversationByIDSQL(true), id).Scan(&conversation.ID, &displayName); err != nil {
		return relay.Conversation{}, errors.New("conversation is unavailable")
	}
	conversation.DisplayName = displayName.String
	return conversation, nil
}

func postgresNullableDisplayName(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func postgresTelegramClaimsAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_telegram_claims') IS NOT NULL`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresExclusiveConversationPredicate(alias string, namesAvailable, claimsAvailable bool) string {
	var parts []string
	if namesAvailable {
		parts = append(parts, "("+alias+".display_name IS NOT NULL AND "+alias+".display_name <> '')")
	}
	if claimsAvailable {
		parts = append(parts, "EXISTS (SELECT 1 FROM relay.mail_telegram_claims WHERE conversation_id = "+alias+".id)")
	}
	if len(parts) == 0 {
		return "FALSE"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func postgresNullableUUID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func postgresPendingTelegramClaimsSQL() string {
	return `SELECT claim.conversation_id::text, claim.status, COALESCE(conversation.display_name, ''), claim.created_at, claim.completed_at
		FROM relay.mail_telegram_claims AS claim
		JOIN relay.mail_conversations AS conversation ON conversation.id = claim.conversation_id
		WHERE claim.status='pending'
		  AND ($2::uuid IS NULL OR (claim.created_at, claim.conversation_id) > (
			SELECT cursor.created_at, cursor.conversation_id FROM relay.mail_telegram_claims AS cursor WHERE cursor.conversation_id = $2::uuid
		  ))
		ORDER BY claim.created_at ASC, claim.conversation_id ASC
		LIMIT $1`
}

func postgresSessionOccupiesOtherExclusiveConversationSQL(namesAvailable, rolesAvailable, claimsAvailable bool) string {
	query := `SELECT EXISTS (
		SELECT 1 FROM relay.mail_memberships AS membership
		JOIN relay.mail_conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.endpoint = $1
		  AND ($2::uuid IS NULL OR membership.conversation_id <> $2::uuid)
		  AND ` + postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)
	if rolesAvailable {
		query += `
		UNION ALL
		SELECT 1 FROM relay.mail_role_bindings AS binding
		JOIN relay.mail_role_memberships AS membership ON membership.role = binding.role
		JOIN relay.mail_conversations AS conversation ON conversation.id = membership.conversation_id
		JOIN relay.mail_endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE binding.session_endpoint = $1
		  AND binding.lease_until > $3
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > $3
		  AND ($2::uuid IS NULL OR membership.conversation_id <> $2::uuid)
		  AND ` + postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)
	}
	return query + `)`
}

func postgresConversationOccupancyLockSQL() string {
	return `SELECT id FROM relay.mail_conversations WHERE id=$1::uuid FOR UPDATE`
}

func postgresEndpointOccupancyLockSQL() string {
	return `SELECT endpoint FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE`
}

func postgresControlMemberLeaseSQL() string {
	return `SELECT lease_until FROM relay.mail_endpoints WHERE endpoint=$1`
}

func postgresOccupancyLockOrder(conversationIDs []string, endpoints map[string]struct{}) ([]string, []string) {
	seen := make(map[string]struct{}, len(conversationIDs))
	orderedConversations := make([]string, 0, len(conversationIDs))
	for _, id := range conversationIDs {
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		orderedConversations = append(orderedConversations, id)
	}
	sort.Strings(orderedConversations)
	return orderedConversations, postgresSortedEndpoints(endpoints)
}

func postgresLockOccupancy(tx *sql.Tx, conversationIDs []string, endpoints map[string]struct{}) error {
	orderedConversations, orderedEndpoints := postgresOccupancyLockOrder(conversationIDs, endpoints)
	for _, conversationID := range orderedConversations {
		var id string
		err := tx.QueryRowContext(context.Background(), postgresConversationOccupancyLockSQL(), conversationID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return relay.ErrForbidden
		}
		if err != nil {
			return errors.New("conversation occupancy lock is unavailable")
		}
	}
	for _, endpoint := range orderedEndpoints {
		var locked string
		err := tx.QueryRowContext(context.Background(), postgresEndpointOccupancyLockSQL(), endpoint).Scan(&locked)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return errors.New("endpoint occupancy lock is unavailable")
		}
	}
	return nil
}

func postgresConversationIsExclusive(tx *sql.Tx, conversationID string) (bool, error) {
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return false, errors.New("conversation display name schema is unavailable")
	}
	claimsAvailable, err := postgresTelegramClaimsAvailable(tx)
	if err != nil {
		return false, errors.New("telegram claim schema is unavailable")
	}
	var exists bool
	err = tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM relay.mail_conversations WHERE id=$1::uuid)`, conversationID).Scan(&exists)
	if err != nil {
		return false, errors.New("conversation occupancy is unavailable")
	}
	if !exists {
		return false, relay.ErrForbidden
	}
	var exclusive bool
	err = tx.QueryRowContext(context.Background(), `SELECT `+postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)+`
		FROM relay.mail_conversations AS conversation WHERE conversation.id=$1::uuid`, conversationID).Scan(&exclusive)
	if err != nil {
		return false, errors.New("conversation occupancy is unavailable")
	}
	return exclusive, nil
}

func postgresSessionOccupiesOtherExclusiveConversation(tx *sql.Tx, endpoint, excludeConversationID string, now time.Time) error {
	if endpoint == relay.TelegramPrimaryEndpoint {
		return nil
	}
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return errors.New("conversation display name schema is unavailable")
	}
	claimsAvailable, err := postgresTelegramClaimsAvailable(tx)
	if err != nil {
		return errors.New("telegram claim schema is unavailable")
	}
	if !namesAvailable && !claimsAvailable {
		return nil
	}
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return errors.New("durable role bindings are unavailable")
	}
	query := postgresSessionOccupiesOtherExclusiveConversationSQL(namesAvailable, rolesAvailable, claimsAvailable)
	exclude := postgresNullableUUID(excludeConversationID)
	var occupied bool
	if rolesAvailable {
		err = tx.QueryRowContext(context.Background(), query, endpoint, exclude, now.UTC()).Scan(&occupied)
	} else {
		err = tx.QueryRowContext(context.Background(), query, endpoint, exclude).Scan(&occupied)
	}
	if err != nil {
		return errors.New("exclusive conversation occupancy is unavailable")
	}
	if occupied {
		return relay.ErrConflict
	}
	return nil
}

func postgresRejectExclusiveCreateOccupancy(tx *sql.Tx, endpoints map[string]struct{}, roles map[string]string, now time.Time) error {
	sessions := make(map[string]struct{}, len(endpoints)+len(roles))
	for endpoint := range endpoints {
		sessions[endpoint] = struct{}{}
	}
	if len(roles) != 0 {
		rolesAvailable, err := postgresRoleBindingsAvailable(tx)
		if err != nil {
			return errors.New("durable role bindings are unavailable")
		}
		if rolesAvailable {
			for role := range roles {
				var session string
				err := tx.QueryRowContext(context.Background(), `SELECT binding.session_endpoint FROM relay.mail_role_bindings AS binding
					JOIN relay.mail_endpoints AS live ON live.endpoint = binding.session_endpoint
					WHERE binding.role = $1 AND binding.lease_until > $2
					  AND live.machine_id = binding.machine_id
					  AND live.ownership_generation = binding.ownership_generation
					  AND live.lease_until > $2`, role, now.UTC()).Scan(&session)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return errors.New("live role occupancy is unavailable")
				}
				sessions[session] = struct{}{}
			}
		}
	}
	if err := postgresLockOccupancy(tx, nil, sessions); err != nil {
		return err
	}
	for _, session := range postgresSortedEndpoints(sessions) {
		if err := postgresSessionOccupiesOtherExclusiveConversation(tx, session, "", now); err != nil {
			return err
		}
	}
	return nil
}

func postgresRejectExclusiveRenameOccupancy(tx *sql.Tx, conversationID string, now time.Time) error {
	// Conversation row first so BindRoleToSession waits on the same unnamed
	// room before inserting a binding this occupant walk cannot yet see.
	if err := postgresLockOccupancy(tx, []string{conversationID}, nil); err != nil {
		return err
	}
	occupants, err := postgresConversationOccupants(tx, conversationID, now)
	if err != nil {
		return err
	}
	if err := postgresLockOccupancy(tx, nil, occupants); err != nil {
		return err
	}
	exclusive, exclusiveErr := postgresConversationIsExclusive(tx, conversationID)
	if exclusiveErr != nil {
		return exclusiveErr
	}
	if exclusive {
		return nil
	}
	return postgresRejectOccupantsInOtherExclusiveConversations(tx, conversationID, occupants, now)
}

func postgresRejectExclusiveClaimOccupancy(tx *sql.Tx, conversationID string, now time.Time) error {
	// Named rooms are already exclusive. Rename can skip the occupant walk;
	// reserve cannot — every non-gateway occupant must be fenced.
	occupants, err := postgresConversationOccupants(tx, conversationID, now)
	if err != nil {
		return err
	}
	if err := postgresLockOccupancy(tx, []string{conversationID}, occupants); err != nil {
		return err
	}
	return postgresRejectOccupantsInOtherExclusiveConversations(tx, conversationID, occupants, now)
}

func postgresConversationOccupants(tx *sql.Tx, conversationID string, now time.Time) (map[string]struct{}, error) {
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return nil, errors.New("durable role bindings are unavailable")
	}
	query := `SELECT endpoint FROM relay.mail_memberships WHERE conversation_id = $1::uuid`
	if rolesAvailable {
		query += `
		UNION
		SELECT binding.session_endpoint FROM relay.mail_role_memberships AS membership
		JOIN relay.mail_role_bindings AS binding ON binding.role = membership.role
		JOIN relay.mail_endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE membership.conversation_id = $1::uuid
		  AND binding.lease_until > $2
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > $2`
	}
	var rows *sql.Rows
	if rolesAvailable {
		rows, err = tx.QueryContext(context.Background(), query, conversationID, now.UTC())
	} else {
		rows, err = tx.QueryContext(context.Background(), query, conversationID)
	}
	if err != nil {
		return nil, errors.New("conversation occupants are unavailable")
	}
	defer func() { _ = rows.Close() }()
	occupants := make(map[string]struct{})
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			return nil, errors.New("conversation occupant is malformed")
		}
		occupants[endpoint] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("conversation occupants are unavailable")
	}
	return occupants, nil
}

func postgresRejectOccupantsInOtherExclusiveConversations(tx *sql.Tx, conversationID string, occupants map[string]struct{}, now time.Time) error {
	for _, endpoint := range postgresSortedEndpoints(occupants) {
		if err := postgresSessionOccupiesOtherExclusiveConversation(tx, endpoint, conversationID, now); err != nil {
			return err
		}
	}
	return nil
}

func postgresConversationIDsForRoleSQL() string {
	return `SELECT conversation_id::text FROM relay.mail_role_memberships WHERE role=$1`
}

func postgresConversationIDsForRole(tx *sql.Tx, role string) ([]string, error) {
	rows, err := tx.QueryContext(context.Background(), postgresConversationIDsForRoleSQL(), role)
	if err != nil {
		return nil, errors.New("role occupancy conversations are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New("role occupancy conversation is malformed")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("role occupancy conversations are unavailable")
	}
	return ids, nil
}

func postgresRejectExclusiveBindOccupancy(tx *sql.Tx, sessionEndpoint, role string, now time.Time) error {
	if sessionEndpoint == relay.TelegramPrimaryEndpoint {
		return nil
	}
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return errors.New("conversation display name schema is unavailable")
	}
	claimsAvailable, err := postgresTelegramClaimsAvailable(tx)
	if err != nil {
		return errors.New("telegram claim schema is unavailable")
	}
	if !namesAvailable && !claimsAvailable {
		return nil
	}
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return errors.New("durable role bindings are unavailable")
	}
	if !rolesAvailable {
		return nil
	}
	var count int
	err = tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM (
		SELECT membership.conversation_id AS id FROM relay.mail_memberships AS membership
		JOIN relay.mail_conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.endpoint = $1
		  AND `+postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)+`
		UNION
		SELECT membership.conversation_id FROM relay.mail_role_memberships AS membership
		JOIN relay.mail_conversations AS conversation ON conversation.id = membership.conversation_id
		JOIN relay.mail_role_bindings AS binding ON binding.role = membership.role
		JOIN relay.mail_endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE binding.session_endpoint = $1
		  AND binding.role <> $2
		  AND binding.lease_until > $3
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > $3
		  AND `+postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)+`
		UNION
		SELECT membership.conversation_id FROM relay.mail_role_memberships AS membership
		JOIN relay.mail_conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.role = $2
		  AND `+postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)+`
	) AS occupied`, sessionEndpoint, role, now.UTC()).Scan(&count)
	if err != nil {
		return errors.New("role-binding occupancy is unavailable")
	}
	if count > 1 {
		return relay.ErrConflict
	}
	return nil
}

func postgresControlEventByID(tx *sql.Tx, id string) (relay.ControlEvent, error) {
	var event relay.ControlEvent
	if err := tx.QueryRowContext(context.Background(), `SELECT id::text,conversation_id::text,actor_endpoint,operation,member_endpoint,member_capabilities,created_at FROM relay.mail_conversation_controls WHERE id=$1::uuid`, id).Scan(&event.ID, &event.ConversationID, &event.ActorEndpoint, &event.Operation, &event.Member.Endpoint, &event.Member.Capabilities, &event.CreatedAt); err != nil {
		return relay.ControlEvent{}, errors.New("control retry event is unavailable")
	}
	event.CreatedAt = event.CreatedAt.UTC()
	return event, nil
}

// CreateConversationIdempotent creates one PostgreSQL relay conversation per retry key.
func (d *Database) CreateConversationIdempotent(input relay.CreateConversationInput) (relay.Conversation, error) {
	if !relay.ValidMachineID(input.MachineID) || !relay.ValidRequestToken(input.IdempotencyKey) || !relay.ValidEndpoint(input.CreatorEndpoint) || len(input.Members) == 0 || len(input.Members) > 256 {
		return relay.Conversation{}, errors.New("invalid conversation request")
	}
	if input.ProjectID != "" && (!validOpaqueID(input.ProjectID) || !validOpaqueID(input.PrincipalID) || !validOpaqueID(input.CredentialLookupID) || input.CredentialGeneration < 1) {
		return relay.Conversation{}, errors.New("invalid conversation project authority")
	}
	seen := make(map[string]struct{}, len(input.Members))
	roles := make(map[string]string, len(input.Members))
	creatorAdmin := false
	for _, member := range input.Members {
		if member.Capabilities == 0 || member.Capabilities & ^(relay.CapSend|relay.CapReceive|relay.CapAdmin|relay.CapInvoke) != 0 {
			return relay.Conversation{}, errors.New("invalid conversation member")
		}
		switch {
		case member.Endpoint != "" && member.Role == "" && member.RoleMachineID == "":
			if !relay.ValidEndpoint(member.Endpoint) || relay.ReservedRelayMember(member.Endpoint) {
				return relay.Conversation{}, errors.New("invalid conversation member")
			}
			if _, duplicate := seen[member.Endpoint]; duplicate {
				return relay.Conversation{}, errors.New("duplicate conversation member")
			}
			seen[member.Endpoint] = struct{}{}
			if member.Endpoint == input.CreatorEndpoint && member.Capabilities&(relay.CapSend|relay.CapReceive|relay.CapAdmin) == relay.CapSend|relay.CapReceive|relay.CapAdmin {
				creatorAdmin = true
			}
		case member.Endpoint == "" && relay.ValidRole(member.Role) && member.Role != relay.TelegramUserParticipant && relay.ValidMachineID(member.RoleMachineID):
			if member.Capabilities&relay.CapInvoke != 0 {
				return relay.Conversation{}, errors.New("invalid conversation member")
			}
			if _, duplicate := roles[member.Role]; duplicate {
				return relay.Conversation{}, errors.New("duplicate conversation member")
			}
			roles[member.Role] = member.RoleMachineID
		default:
			return relay.Conversation{}, errors.New("invalid conversation member")
		}
	}
	if !creatorAdmin {
		return relay.Conversation{}, relay.ErrForbidden
	}
	displayName, err := relay.SanitizeConversationDisplayName(input.DisplayName)
	if err != nil {
		return relay.Conversation{}, err
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Conversation{}, errors.New("conversation transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return relay.Conversation{}, errors.New("conversation display name schema is unavailable")
	}
	if displayName != "" && !namesAvailable {
		return relay.Conversation{}, errors.New("conversation display names are unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text, 579001230608))`, input.MachineID, input.IdempotencyKey); err != nil {
		return relay.Conversation{}, errors.New("conversation retry lock is unavailable")
	}
	hash := relay.CreateConversationRequestHash(input.CreatorEndpoint, input.Members, displayName, input.ProjectID)
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), `SELECT conversation_id::text,request_hash FROM relay.mail_conversation_idempotency WHERE machine_id=$1 AND key=$2`, input.MachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if _, err := postgresEndpointOwnershipLocked(tx, input.CreatorEndpoint, input.MachineID, input.Now); err != nil {
			return relay.Conversation{}, err
		}
		if existingHash != hash {
			return relay.Conversation{}, relay.ErrConflict
		}
		if input.ProjectID != "" {
			var canonicalProject string
			if err := tx.QueryRowContext(context.Background(), `SELECT attachment.bind_conversation_project($1,$2,$3,$4::uuid,$5,$6::uuid)::text`, input.PrincipalID, input.CredentialLookupID, input.CredentialGeneration, existingID, input.CreatorEndpoint, input.ProjectID).Scan(&canonicalProject); err != nil || !validOpaqueID(canonicalProject) {
				return relay.Conversation{}, relayDatabaseError(err, "reauthorize conversation project")
			}
		}
		conversation, err := postgresConversationByID(tx, existingID)
		if err != nil {
			return relay.Conversation{}, err
		}
		if err := tx.Commit(); err != nil {
			return relay.Conversation{}, errors.New("conversation retry cannot commit")
		}
		return conversation, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.Conversation{}, errors.New("conversation retry state is unavailable")
	}
	for _, endpoint := range postgresSortedEndpoints(seen) {
		var owner string
		var until time.Time
		err := tx.QueryRowContext(context.Background(), `SELECT machine_id,lease_until FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE`, endpoint).Scan(&owner, &until)
		if errors.Is(err, sql.ErrNoRows) {
			return relay.Conversation{}, relay.ErrForbidden
		}
		if err != nil {
			return relay.Conversation{}, errors.New("endpoint lease is unavailable")
		}
		if !until.After(input.Now) || endpoint == input.CreatorEndpoint && owner != input.MachineID {
			return relay.Conversation{}, relay.ErrForbidden
		}
	}
	orderedRoles := make([]string, 0, len(roles))
	for role := range roles {
		orderedRoles = append(orderedRoles, role)
	}
	sort.Strings(orderedRoles)
	if len(orderedRoles) != 0 {
		rolesAvailable, err := postgresRoleBindingsAvailable(tx)
		if err != nil {
			return relay.Conversation{}, errors.New("durable role bindings are unavailable")
		}
		if !rolesAvailable {
			return relay.Conversation{}, relay.ErrForbidden
		}
	}
	for _, role := range orderedRoles {
		owner := roles[role]
		if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('durable-role',$1::text)::text, 579001230609))`, role); err != nil {
			return relay.Conversation{}, errors.New("durable role creation lock is unavailable")
		}
		var existingOwner string
		err := tx.QueryRowContext(context.Background(), `SELECT machine_id FROM relay.mail_roles WHERE role=$1`, role).Scan(&existingOwner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_roles(role,machine_id) VALUES($1,$2)`, role, owner); err != nil {
				return relay.Conversation{}, relayDatabaseError(err, "create durable role")
			}
		case err != nil:
			return relay.Conversation{}, errors.New("durable role ownership is unavailable")
		case existingOwner != owner:
			return relay.Conversation{}, relay.ErrForbidden
		}
	}
	if displayName != "" {
		if err := postgresRejectExclusiveCreateOccupancy(tx, seen, roles, input.Now); err != nil {
			return relay.Conversation{}, err
		}
	}
	conversation := relay.Conversation{ID: uuid.NewString(), DisplayName: displayName}
	if namesAvailable {
		if _, err := tx.ExecContext(context.Background(), postgresConversationInsertSQL(true), conversation.ID, input.Now.UTC(), postgresNullableDisplayName(displayName)); err != nil {
			return relay.Conversation{}, relayDatabaseError(err, "create conversation")
		}
	} else if _, err := tx.ExecContext(context.Background(), postgresConversationInsertSQL(false), conversation.ID, input.Now.UTC()); err != nil {
		return relay.Conversation{}, relayDatabaseError(err, "create conversation")
	}
	for _, member := range input.Members {
		if member.Endpoint != "" {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities) VALUES($1::uuid,$2,$3)`, conversation.ID, member.Endpoint, member.Capabilities); err != nil {
				return relay.Conversation{}, relayDatabaseError(err, "add conversation member")
			}
		} else if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_role_memberships(conversation_id,role,capabilities) VALUES($1::uuid,$2,$3)`, conversation.ID, member.Role, member.Capabilities); err != nil {
			return relay.Conversation{}, relayDatabaseError(err, "add durable role member")
		}
	}
	if input.ProjectID != "" {
		var canonicalProject string
		if err := tx.QueryRowContext(context.Background(), `SELECT attachment.bind_conversation_project($1,$2,$3,$4::uuid,$5,$6::uuid)::text`, input.PrincipalID, input.CredentialLookupID, input.CredentialGeneration, conversation.ID, input.CreatorEndpoint, input.ProjectID).Scan(&canonicalProject); err != nil || !validOpaqueID(canonicalProject) {
			return relay.Conversation{}, relayDatabaseError(err, "bind conversation project")
		}
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_idempotency(machine_id,key,request_hash,conversation_id,created_at) VALUES($1,$2,$3,$4::uuid,$5)`, input.MachineID, input.IdempotencyKey, hash, conversation.ID, input.Now.UTC()); err != nil {
		return relay.Conversation{}, relayDatabaseError(err, "record conversation retry")
	}
	if err := tx.Commit(); err != nil {
		return relay.Conversation{}, relayDatabaseError(err, "commit conversation")
	}
	return conversation, nil
}

// AuthorizeSender verifies current PostgreSQL sender authority without mutation.
func (d *Database) AuthorizeSender(conversationID, machineID, endpoint string, now time.Time) error {
	if _, err := uuid.Parse(conversationID); err != nil {
		return relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("sender authorization cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return err
	}
	capabilities, err := postgresSessionCapabilities(tx, conversationID, machineID, endpoint, now)
	if err != nil {
		return err
	}
	if capabilities&relay.CapSend == 0 {
		return relay.ErrForbidden
	}
	if err := postgresRejectDirectConversationAppend(tx, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendMessage transactionally appends one immutable PostgreSQL relay message.
// Direct-role conversations are writable only through SendDirectMessage.
func (d *Database) AppendMessage(input relay.AppendInput) (relay.Message, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.SenderMachineID) || !relay.ValidEndpoint(input.FromEndpoint) || !relay.ValidRequestToken(input.IdempotencyKey) {
		return relay.Message{}, false, errors.New("invalid message request")
	}
	if len(input.Body) > postgresRelayMaxMessageBytes {
		return relay.Message{}, false, errors.New("message body exceeds limit")
	}
	if !relay.ValidMessageBody(input.Body) {
		return relay.Message{}, false, errors.New("message body is not portable UTF-8 text")
	}
	if len(input.ArtifactIDs) > 16 {
		return relay.Message{}, false, errors.New("message attachment list exceeds limit")
	}
	seenArtifacts := make(map[string]struct{}, len(input.ArtifactIDs))
	for _, artifactID := range input.ArtifactIDs {
		if !validOpaqueID(artifactID) {
			return relay.Message{}, false, errors.New("invalid message attachment")
		}
		if _, duplicate := seenArtifacts[artifactID]; duplicate {
			return relay.Message{}, false, errors.New("duplicate message attachment")
		}
		seenArtifacts[artifactID] = struct{}{}
	}
	if len(input.ArtifactIDs) != 0 && (!validOpaqueID(input.PrincipalID) || !validOpaqueID(input.CredentialLookupID) || input.CredentialGeneration < 1) {
		return relay.Message{}, false, relay.ErrForbidden
	}
	if _, err := uuid.Parse(input.ConversationID); err != nil {
		return relay.Message{}, false, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Message{}, false, errors.New("message transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text, 579001230609))`, input.SenderMachineID, input.IdempotencyKey); err != nil {
		return relay.Message{}, false, errors.New("message retry lock is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 579001230611))`, input.ConversationID); err != nil {
		return relay.Message{}, false, errors.New("message conversation lock is unavailable")
	}
	if _, err := postgresEndpointOwnershipLocked(tx, input.FromEndpoint, input.SenderMachineID, input.Now); err != nil {
		return relay.Message{}, false, err
	}
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return relay.Message{}, false, errors.New("durable role bindings are unavailable")
	}
	if rolesAvailable {
		if err := postgresLockSessionRoleBindings(tx, input.SenderMachineID, input.FromEndpoint, input.Now); err != nil {
			return relay.Message{}, false, err
		}
	}
	capabilities, err := postgresSessionCapabilities(tx, input.ConversationID, input.SenderMachineID, input.FromEndpoint, input.Now)
	if err != nil {
		return relay.Message{}, false, err
	}
	if capabilities&relay.CapSend == 0 {
		return relay.Message{}, false, relay.ErrForbidden
	}
	if err := postgresRejectDirectConversationAppend(tx, input.ConversationID); err != nil {
		return relay.Message{}, false, err
	}
	if input.FromParticipant == relay.TelegramUserParticipant {
		if err := postgresRequireCompleteTelegramClaim(tx, input.ConversationID); err != nil {
			return relay.Message{}, false, err
		}
	}
	if input.TargetRole == relay.TelegramUserParticipant {
		if err := postgresRequireCompleteTelegramClaim(tx, input.ConversationID); err != nil {
			return relay.Message{}, false, err
		}
		var allowed bool
		if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2 AND (capabilities & $3) <> 0)`, input.ConversationID, relay.TelegramGatewayEndpoint, relay.CapReceive).Scan(&allowed); err != nil {
			return relay.Message{}, false, errors.New("telegram participant authorization is unavailable")
		}
		if !allowed {
			return relay.Message{}, false, relay.ErrForbidden
		}
	} else if input.TargetRole != "" {
		if !relay.ValidRole(input.TargetRole) || !rolesAvailable {
			return relay.Message{}, false, relay.ErrForbidden
		}
		var allowed bool
		if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM relay.mail_role_memberships WHERE conversation_id=$1::uuid AND role=$2 AND (capabilities & $3) <> 0)`, input.ConversationID, input.TargetRole, relay.CapReceive).Scan(&allowed); err != nil {
			return relay.Message{}, false, errors.New("target role authorization is unavailable")
		}
		if !allowed {
			return relay.Message{}, false, relay.ErrForbidden
		}
	}
	hash := relay.AppendRequestHash(input)
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), `SELECT message_id::text,request_hash FROM relay.mail_message_idempotency WHERE machine_id=$1 AND key=$2`, input.SenderMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != hash {
			return relay.Message{}, false, relay.ErrConflict
		}
		if len(input.ArtifactIDs) != 0 {
			encodedArtifacts, err := json.Marshal(input.ArtifactIDs)
			if err != nil {
				return relay.Message{}, false, errors.New("message attachment list is invalid")
			}
			var bound int
			if err := tx.QueryRowContext(context.Background(), `SELECT attachment.bind_message_artifacts($1,$2,$3,$4::uuid,$5::jsonb)`, input.PrincipalID, input.CredentialLookupID, input.CredentialGeneration, existingID, string(encodedArtifacts)).Scan(&bound); err != nil || bound != len(input.ArtifactIDs) {
				return relay.Message{}, false, relayDatabaseError(err, "reauthorize message attachments")
			}
		}
		message, err := postgresMessageByID(tx, existingID)
		if err != nil {
			return relay.Message{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return relay.Message{}, false, errors.New("message retry cannot commit")
		}
		return message, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.Message{}, false, errors.New("message retry state is unavailable")
	}
	if err := d.consumeRateLimits(tx, input.SenderMachineID, input.ConversationID, input.Now); err != nil {
		return relay.Message{}, false, err
	}
	deliveryRecipients, err := postgresAppendDeliveryRecipients(tx, input.ConversationID, input.FromEndpoint, input.TargetRole, rolesAvailable)
	if err != nil {
		return relay.Message{}, false, err
	}
	if err := d.consumeQuota(tx, deliveryRecipients, int64(len(input.Body))); err != nil {
		return relay.Message{}, false, err
	}
	message := relay.Message{ID: uuid.NewString(), ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body, CreatedAt: input.Now.UTC().Truncate(time.Millisecond)}
	if err := tx.QueryRowContext(context.Background(), `UPDATE relay.mail_conversations SET next_sequence=next_sequence+1 WHERE id=$1::uuid RETURNING next_sequence`, input.ConversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return relay.Message{}, false, relay.ErrForbidden
	} else if err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "allocate message sequence")
	}
	message.FromParticipant = input.FromParticipant
	message.InReplyToPunaroMessageID = input.InReplyToPunaroMessageID
	message.InReplyToEndpoint = input.InReplyToEndpoint
	message.TelegramThreadID = input.TelegramThreadID
	if metadataAvailable, metaErr := postgresMessageMetadataAvailable(tx); metaErr != nil {
		return relay.Message{}, false, errors.New("message metadata schema is unavailable")
	} else if metadataAvailable {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,from_participant,in_reply_to_message_id,in_reply_to_endpoint,telegram_thread_id,body,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, postgresNullableText(message.FromParticipant), postgresNullableText(message.InReplyToPunaroMessageID), postgresNullableText(message.InReplyToEndpoint), postgresNullableThreadID(message.TelegramThreadID), message.Body, message.CreatedAt); err != nil {
			return relay.Message{}, false, relayDatabaseError(err, "append message")
		}
	} else if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,body,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, message.Body, message.CreatedAt); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "append message")
	}
	if input.TargetRole == relay.TelegramUserParticipant {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint)
			SELECT $1::uuid,endpoint FROM relay.mail_memberships WHERE conversation_id=$2::uuid AND endpoint=$3 AND (capabilities & $4) <> 0 AND endpoint<>$5`, message.ID, message.ConversationID, relay.TelegramGatewayEndpoint, relay.CapReceive, message.FromEndpoint); err != nil {
			return relay.Message{}, false, relayDatabaseError(err, "create telegram participant delivery")
		}
		if err := postgresAdvanceSkippedTelegramCursors(tx, input.ConversationID, input.FromEndpoint); err != nil {
			return relay.Message{}, false, err
		}
	} else {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint)
		SELECT $1::uuid,endpoint FROM relay.mail_memberships WHERE $5='' AND conversation_id=$2::uuid AND (capabilities & $3) <> 0 AND endpoint<>$4`, message.ID, message.ConversationID, relay.CapReceive, message.FromEndpoint, input.TargetRole); err != nil {
			return relay.Message{}, false, relayDatabaseError(err, "create recipient deliveries")
		}
		if rolesAvailable {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint)
		SELECT $1::uuid,chr(30)||'role:'||membership.role
		FROM relay.mail_role_memberships AS membership
		WHERE membership.conversation_id=$2::uuid AND (membership.capabilities & $3) <> 0 AND ($4='' OR membership.role=$4)`, message.ID, message.ConversationID, relay.CapReceive, input.TargetRole); err != nil {
				return relay.Message{}, false, relayDatabaseError(err, "create durable role deliveries")
			}
		}
		if input.TargetRole != "" {
			if err := postgresAdvanceSkippedTargetCursors(tx, input.ConversationID, input.FromEndpoint, input.TargetRole); err != nil {
				return relay.Message{}, false, err
			}
		}
	}
	if len(input.ArtifactIDs) != 0 {
		encodedArtifacts, err := json.Marshal(input.ArtifactIDs)
		if err != nil {
			return relay.Message{}, false, errors.New("message attachment list is invalid")
		}
		var bound int
		if err := tx.QueryRowContext(context.Background(), `SELECT attachment.bind_message_artifacts($1,$2,$3,$4::uuid,$5::jsonb)`, input.PrincipalID, input.CredentialLookupID, input.CredentialGeneration, message.ID, string(encodedArtifacts)).Scan(&bound); err != nil || bound != len(input.ArtifactIDs) {
			return relay.Message{}, false, relayDatabaseError(err, "bind message attachments")
		}
	}
	if err := postgresAdvanceSessionCursors(tx, input.SenderMachineID, input.FromEndpoint, input.ConversationID, input.Now); err != nil {
		return relay.Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_message_idempotency(machine_id,key,request_hash,message_id,created_at) VALUES($1,$2,$3,$4::uuid,$5)`, input.SenderMachineID, input.IdempotencyKey, hash, message.ID, input.Now.UTC()); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "record message retry")
	}
	if err := tx.Commit(); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "commit message")
	}
	d.refreshPendingMetrics(context.Background(), input.Now)
	return message, false, nil
}

// SetRateLimits replaces the in-process bucket policy without resetting durable depletion.
func (d *Database) SetRateLimits(cfg relay.RateLimitConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.rateMu.Lock()
	d.rateLimits = cfg
	d.rateMu.Unlock()
	return nil
}

// SetMetrics attaches the shared content-free counter sink.
func (d *Database) SetMetrics(metrics *relay.Metrics) {
	d.metrics = metrics
	d.refreshPendingMetrics(context.Background(), time.Time{})
}

func (d *Database) rateLimitConfig() relay.RateLimitConfig {
	d.rateMu.Lock()
	defer d.rateMu.Unlock()
	if d.rateLimits == (relay.RateLimitConfig{}) {
		return relay.DefaultRateLimitConfig()
	}
	return d.rateLimits
}

func (d *Database) consumeRateLimits(tx *sql.Tx, senderMachineID, conversationID string, now time.Time) error {
	cfg := d.rateLimitConfig()
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('rate-sender',$1::text)::text, 579001230613))`, senderMachineID); err != nil {
		return errors.New("sender rate lock is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('rate-conversation',$1::text)::text, 579001230614))`, conversationID); err != nil {
		return errors.New("conversation rate lock is unavailable")
	}
	sender, err := postgresLoadRateBucket(tx, "sender", senderMachineID, now, int64(cfg.SenderBurst))
	if err != nil {
		return err
	}
	conversation, err := postgresLoadRateBucket(tx, "conversation", conversationID, now, int64(cfg.ConversationBurst))
	if err != nil {
		return err
	}
	decision := relay.DecideRateLimit(cfg, sender, conversation, now)
	if !decision.Allowed {
		d.metrics.ObserveRateLimited()
		return &relay.RateLimitedError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	if err := postgresSaveRateBucket(tx, "sender", senderMachineID, decision.Sender); err != nil {
		return err
	}
	return postgresSaveRateBucket(tx, "conversation", conversationID, decision.Conversation)
}

func postgresLoadRateBucket(tx *sql.Tx, kind, key string, now time.Time, burst int64) (relay.RateBucket, error) {
	now = now.UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_rate_buckets(kind,bucket_key,tokens,updated_at) VALUES ($1,$2,$3,$4) ON CONFLICT (kind, bucket_key) DO NOTHING`, kind, key, burst, now); err != nil {
		return relay.RateBucket{}, errors.New("rate bucket initialize is unavailable")
	}
	var tokens int64
	var updatedAt time.Time
	if err := tx.QueryRowContext(context.Background(), `SELECT tokens,updated_at FROM relay.mail_rate_buckets WHERE kind=$1 AND bucket_key=$2 FOR UPDATE`, kind, key).Scan(&tokens, &updatedAt); err != nil {
		return relay.RateBucket{}, errors.New("rate bucket read is unavailable")
	}
	return relay.RateBucket{Tokens: tokens, UpdatedAt: updatedAt.UTC()}, nil
}

func postgresSaveRateBucket(tx *sql.Tx, kind, key string, bucket relay.RateBucket) error {
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_rate_buckets SET tokens=$1,updated_at=$2 WHERE kind=$3 AND bucket_key=$4`, bucket.Tokens, bucket.UpdatedAt.UTC().Truncate(time.Millisecond), kind, key); err != nil {
		return errors.New("rate bucket update is unavailable")
	}
	return nil
}

// LeaseDeliveries claims a bounded fenced PostgreSQL delivery page.
func (d *Database) LeaseDeliveries(machineID, consumerID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) (relay.DeliveryLeasePage, error) {
	if !relay.ValidMachineID(machineID) || !relay.ValidRequestToken(consumerID) || !relay.ValidEndpoint(endpoint) || ttl <= 0 || limit < 1 || limit > 100 {
		return relay.DeliveryLeasePage{}, errors.New("invalid delivery lease request")
	}
	if conversationID != "" {
		if _, err := uuid.Parse(conversationID); err != nil {
			return relay.DeliveryLeasePage{}, relay.ErrForbidden
		}
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.DeliveryLeasePage{}, errors.New("delivery lease transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	ownershipGeneration, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now)
	if err != nil {
		return relay.DeliveryLeasePage{}, err
	}
	if err := postgresLockSessionRoleBindings(tx, machineID, endpoint, now); err != nil {
		return relay.DeliveryLeasePage{}, err
	}
	recipientIDs, err := postgresSessionRecipientIDs(tx, machineID, endpoint, ownershipGeneration, now)
	if err != nil {
		return relay.DeliveryLeasePage{}, err
	}
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return relay.DeliveryLeasePage{}, errors.New("durable role bindings are unavailable")
	}
	encodedRecipientIDs, err := json.Marshal(recipientIDs)
	if err != nil {
		return relay.DeliveryLeasePage{}, errors.New("delivery recipients are invalid")
	}
	var activeConsumer sql.NullString
	var consumerGeneration int64
	var consumerUntil sql.NullTime
	if err := tx.QueryRowContext(context.Background(), `SELECT consumer_id,consumer_generation,consumer_lease_until FROM relay.mail_endpoints WHERE endpoint=$1`, endpoint).Scan(&activeConsumer, &consumerGeneration, &consumerUntil); err != nil {
		return relay.DeliveryLeasePage{}, errors.New("endpoint consumer lease is unavailable")
	}
	if activeConsumer.Valid && activeConsumer.String != consumerID && consumerUntil.Valid && consumerUntil.Time.After(now) {
		return relay.DeliveryLeasePage{}, relay.ErrConflict
	}
	if !activeConsumer.Valid || activeConsumer.String != consumerID || !consumerUntil.Valid || !consumerUntil.Time.After(now) {
		consumerGeneration++
	}
	consumerLeaseUntil := now.Add(ttl).UTC()
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_endpoints SET consumer_id=$1,consumer_generation=$2,consumer_lease_until=$3 WHERE endpoint=$4 AND ownership_generation=$5`, consumerID, consumerGeneration, consumerLeaseUntil, endpoint, ownershipGeneration); err != nil {
		return relay.DeliveryLeasePage{}, relayDatabaseError(err, "claim endpoint consumer lease")
	}
	metadataAvailable, err := postgresMessageMetadataAvailable(tx)
	if err != nil {
		return relay.DeliveryLeasePage{}, errors.New("message metadata schema is unavailable")
	}
	messageColumns := postgresLeaseMessageColumns(metadataAvailable)
	query := `SELECT delivery.id::text,delivery.recipient_endpoint,delivery.lease_machine_id,delivery.lease_token::text,delivery.lease_generation,delivery.ownership_generation,delivery.consumer_generation,delivery.lease_until,
		` + messageColumns + `
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		LEFT JOIN relay.mail_message_from_roles AS sender ON sender.message_id=message.id
		WHERE delivery.recipient_endpoint IN (SELECT value FROM jsonb_array_elements_text($1::jsonb)) AND delivery.acked_at IS NULL
		  AND (delivery.lease_until IS NULL OR delivery.lease_until<=$2 OR delivery.ownership_generation IS NULL OR delivery.ownership_generation<>$3 OR delivery.consumer_generation IS NULL OR delivery.consumer_generation<>$4 OR delivery.lease_machine_id=$5)` // #nosec G202 -- message columns are a static allowlist selected from schema presence, not caller input.
	args := []any{string(encodedRecipientIDs), now.UTC(), ownershipGeneration, consumerGeneration, machineID}
	if conversationID != "" {
		query += ` AND message.conversation_id=$6::uuid ORDER BY message.sequence,message.id LIMIT $7 FOR UPDATE OF delivery SKIP LOCKED`
		args = append(args, conversationID, limit)
	} else {
		query += ` ORDER BY message.created_at,message.conversation_id,message.sequence,message.id LIMIT $6 FOR UPDATE OF delivery SKIP LOCKED`
		args = append(args, limit)
	}
	rows, err := tx.QueryContext(context.Background(), query, args...)
	if err != nil {
		return relay.DeliveryLeasePage{}, errors.New("pending deliveries are unavailable")
	}
	type leasedRow struct {
		delivery       relay.Delivery
		leaseMachine   sql.NullString
		leaseToken     sql.NullString
		leaseOwnership sql.NullInt64
		leaseConsumer  sql.NullInt64
		leaseUntil     sql.NullTime
	}
	var pending []leasedRow
	for rows.Next() {
		var row leasedRow
		var recipientID string
		row.delivery.RecipientEndpoint = endpoint
		var fromRole, fromParticipant, replyMessage, replyEndpoint sql.NullString
		var threadID sql.NullInt64
		var err error
		if metadataAvailable {
			err = rows.Scan(&row.delivery.ID, &recipientID, &row.leaseMachine, &row.leaseToken, &row.delivery.LeaseGeneration, &row.leaseOwnership, &row.leaseConsumer, &row.leaseUntil, &row.delivery.Message.ID, &row.delivery.Message.ConversationID, &row.delivery.Message.Sequence, &row.delivery.Message.FromEndpoint, &fromParticipant, &replyMessage, &replyEndpoint, &threadID, &row.delivery.Message.Body, &row.delivery.Message.CreatedAt, &fromRole)
		} else {
			err = rows.Scan(&row.delivery.ID, &recipientID, &row.leaseMachine, &row.leaseToken, &row.delivery.LeaseGeneration, &row.leaseOwnership, &row.leaseConsumer, &row.leaseUntil, &row.delivery.Message.ID, &row.delivery.Message.ConversationID, &row.delivery.Message.Sequence, &row.delivery.Message.FromEndpoint, &row.delivery.Message.Body, &row.delivery.Message.CreatedAt, &fromRole)
		}
		if err != nil {
			_ = rows.Close()
			return relay.DeliveryLeasePage{}, errors.New("pending delivery is malformed")
		}
		applyPostgresMessageMetadata(&row.delivery.Message, fromParticipant, replyMessage, replyEndpoint, threadID)
		postgresApplyDirectSender(&row.delivery.Message, fromRole)
		if role, isRole := postgresParseRoleRecipient(recipientID); isRole {
			row.delivery.RecipientRole = role
		}
		row.delivery.Message.CreatedAt = row.delivery.Message.CreatedAt.UTC()
		pending = append(pending, row)
	}
	if err := rows.Close(); err != nil {
		return relay.DeliveryLeasePage{}, errors.New("pending deliveries are unavailable")
	}
	if err := rows.Err(); err != nil {
		return relay.DeliveryLeasePage{}, errors.New("pending deliveries are unavailable")
	}
	deliveries := make([]relay.Delivery, 0, len(pending))
	redeliveries := 0
	for _, row := range pending {
		delivery := row.delivery
		if row.leaseMachine.Valid && row.leaseMachine.String == machineID && row.leaseToken.Valid && row.leaseOwnership.Valid && row.leaseOwnership.Int64 == ownershipGeneration && row.leaseConsumer.Valid && row.leaseConsumer.Int64 == consumerGeneration && row.leaseUntil.Valid && row.leaseUntil.Time.After(now) {
			delivery.LeaseToken = row.leaseToken.String
			delivery.LeaseUntil = row.leaseUntil.Time.UTC()
		} else {
			if row.leaseUntil.Valid && !row.leaseUntil.Time.After(now) {
				redeliveries++
			}
			delivery.LeaseGeneration++
			delivery.LeaseToken = uuid.NewString()
			delivery.LeaseUntil = now.Add(ttl).UTC()
			if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries SET lease_machine_id=$1,lease_token=$2::uuid,lease_generation=$3,ownership_generation=$4,consumer_generation=$5,lease_until=$6 WHERE id=$7::uuid`, machineID, delivery.LeaseToken, delivery.LeaseGeneration, ownershipGeneration, consumerGeneration, delivery.LeaseUntil, delivery.ID); err != nil {
				return relay.DeliveryLeasePage{}, relayDatabaseError(err, "lease delivery")
			}
		}
		deliveries = append(deliveries, delivery)
	}
	conversationIDs := make(map[string]struct{})
	if conversationID != "" {
		conversationIDs[conversationID] = struct{}{}
	}
	for _, delivery := range deliveries {
		conversationIDs[delivery.Message.ConversationID] = struct{}{}
	}
	cursorIDs := make([]string, 0, len(conversationIDs))
	for id := range conversationIDs {
		cursorIDs = append(cursorIDs, id)
	}
	cursors, err := postgresRecipientCursorsForLease(tx, encodedRecipientIDs, cursorIDs, rolesAvailable)
	if err != nil {
		return relay.DeliveryLeasePage{}, err
	}
	if err := tx.Commit(); err != nil {
		return relay.DeliveryLeasePage{}, relayDatabaseError(err, "commit delivery lease")
	}
	d.metrics.ObserveLeaseRedeliveries(redeliveries)
	return relay.DeliveryLeasePage{Deliveries: deliveries, Cursors: cursors}, nil
}

func postgresRecipientCursorsForLease(tx *sql.Tx, encodedRecipientIDs []byte, conversationIDs []string, rolesAvailable bool) (map[string]int64, error) {
	encodedConversationIDs, err := json.Marshal(conversationIDs)
	if err != nil {
		return nil, errors.New("recipient conversations are invalid")
	}
	query := `WITH recipients AS (
		SELECT value AS recipient FROM jsonb_array_elements_text($1::jsonb)
	), conversations AS (
		SELECT value::uuid AS id FROM jsonb_array_elements_text($2::jsonb)
	), authorized AS (
		SELECT membership.conversation_id,membership.endpoint AS recipient
		FROM relay.mail_memberships AS membership
		JOIN conversations ON conversations.id=membership.conversation_id
		JOIN recipients ON recipients.recipient=membership.endpoint
		WHERE membership.capabilities&$3<>0`
	if rolesAvailable {
		query += ` UNION ALL
		SELECT membership.conversation_id,chr(30)||'role:'||membership.role
		FROM relay.mail_role_memberships AS membership
		JOIN conversations ON conversations.id=membership.conversation_id
		JOIN recipients ON recipients.recipient=chr(30)||'role:'||membership.role
		WHERE membership.capabilities&$3<>0`
	}
	query += `
	)
	SELECT authorized.conversation_id::text,MIN(COALESCE(cursor.sequence,0))
	FROM authorized LEFT JOIN relay.mail_recipient_cursors AS cursor
	ON cursor.conversation_id=authorized.conversation_id AND cursor.recipient_endpoint=authorized.recipient
	GROUP BY authorized.conversation_id`
	rows, err := tx.QueryContext(context.Background(), query, string(encodedRecipientIDs), string(encodedConversationIDs), relay.CapReceive)
	if err != nil {
		return nil, errors.New("recipient cursor authorization is unavailable")
	}
	cursors := make(map[string]int64, len(conversationIDs))
	for rows.Next() {
		var conversationID string
		var cursor int64
		if err := rows.Scan(&conversationID, &cursor); err != nil {
			_ = rows.Close()
			return nil, errors.New("recipient cursor is malformed")
		}
		cursors[conversationID] = cursor
	}
	if err := rows.Close(); err != nil {
		return nil, errors.New("recipient cursor authorization is unavailable")
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("recipient cursor authorization is unavailable")
	}
	if len(cursors) != len(conversationIDs) {
		return nil, relay.ErrForbidden
	}
	return cursors, nil
}

func postgresRecipientCursorForLease(tx *sql.Tx, recipientIDs []string, conversationID string) (int64, error) {
	var minimum int64
	found := false
	for _, recipientID := range recipientIDs {
		var capabilities relay.Capability
		var err error
		if role, ok := postgresParseRoleRecipient(recipientID); ok {
			err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_role_memberships WHERE conversation_id=$1::uuid AND role=$2`, conversationID, role).Scan(&capabilities)
		} else {
			err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, conversationID, recipientID).Scan(&capabilities)
		}
		if errors.Is(err, sql.ErrNoRows) || capabilities&relay.CapReceive == 0 {
			continue
		}
		if err != nil {
			return 0, errors.New("recipient cursor authorization is unavailable")
		}
		var cursor int64
		err = tx.QueryRowContext(context.Background(), `SELECT sequence FROM relay.mail_recipient_cursors WHERE recipient_endpoint=$1 AND conversation_id=$2::uuid`, recipientID, conversationID).Scan(&cursor)
		if errors.Is(err, sql.ErrNoRows) {
			cursor = 0
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, errors.New("recipient cursor is unavailable")
		}
		if !found || cursor < minimum {
			minimum, found = cursor, true
		}
	}
	if !found {
		return 0, relay.ErrForbidden
	}
	return minimum, nil
}

// AckDelivery conditionally acknowledges one fenced PostgreSQL delivery.
func (d *Database) AckDelivery(machineID, endpoint, deliveryID, token string, generation int64, now time.Time) error {
	if _, err := uuid.Parse(deliveryID); err != nil {
		return relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return errors.New("delivery acknowledgement cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	ownershipGeneration, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now)
	if err != nil {
		return err
	}
	if err := postgresLockSessionRoleBindings(tx, machineID, endpoint, now); err != nil {
		return err
	}
	recipientIDs, err := postgresSessionRecipientIDs(tx, machineID, endpoint, ownershipGeneration, now)
	if err != nil {
		return err
	}
	var recipient string
	var leaseMachine, leaseToken sql.NullString
	var leaseGeneration int64
	var leaseOwnership, leaseConsumer sql.NullInt64
	var leaseUntil, acknowledged sql.NullTime
	var conversationID string
	err = tx.QueryRowContext(context.Background(), `SELECT delivery.recipient_endpoint,delivery.lease_machine_id,delivery.lease_token::text,
		delivery.lease_generation,delivery.ownership_generation,delivery.consumer_generation,delivery.lease_until,delivery.acked_at,message.conversation_id::text
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.id=$1::uuid FOR UPDATE OF delivery`, deliveryID).Scan(&recipient, &leaseMachine, &leaseToken, &leaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil, &acknowledged, &conversationID)
	if errors.Is(err, sql.ErrNoRows) || !postgresContainsString(recipientIDs, recipient) {
		return relay.ErrForbidden
	}
	if err != nil {
		return relay.ErrForbidden
	}
	if acknowledged.Valid && leaseToken.Valid && leaseToken.String == token && leaseGeneration == generation {
		return tx.Commit()
	}
	var currentConsumerGeneration int64
	if err := tx.QueryRowContext(context.Background(), `SELECT consumer_generation FROM relay.mail_endpoints WHERE endpoint=$1`, endpoint).Scan(&currentConsumerGeneration); err != nil {
		return relay.ErrForbidden
	}
	if !leaseMachine.Valid || leaseMachine.String != machineID || !leaseToken.Valid || leaseToken.String != token || leaseGeneration != generation || !leaseOwnership.Valid || leaseOwnership.Int64 != ownershipGeneration || !leaseConsumer.Valid || leaseConsumer.Int64 != currentConsumerGeneration || !leaseUntil.Valid || !leaseUntil.Time.After(now) {
		return relay.ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries SET acked_at=$1 WHERE id=$2::uuid AND acked_at IS NULL`, now.UTC(), deliveryID); err != nil {
		return relayDatabaseError(err, "acknowledge delivery")
	}
	acked := 0
	if !acknowledged.Valid {
		var bodyBytes int64
		if err := tx.QueryRowContext(context.Background(), `SELECT octet_length(message.body) FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id WHERE delivery.id=$1::uuid`, deliveryID).Scan(&bodyBytes); err != nil {
			return errors.New("delivery body length is unavailable")
		}
		if err := postgresReleaseQuota(tx, recipient, bodyBytes); err != nil {
			return err
		}
		if err := postgresRecordAckedTerminal(tx, deliveryID, now); err != nil {
			return err
		}
		acked = 1
	}
	if err := postgresAdvanceRecipientCursor(tx, recipient, conversationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return relayDatabaseError(err, "commit delivery acknowledgement")
	}
	d.metrics.ObserveTerminals(relay.ClosedAcked, acked)
	d.refreshPendingMetrics(context.Background(), now)
	return nil
}

// RecipientCursor reads one recipient's durable contiguous sequence.
func (d *Database) RecipientCursor(machineID, endpoint, conversationID string, now time.Time) (int64, error) {
	if _, err := uuid.Parse(conversationID); err != nil {
		return 0, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return 0, errors.New("recipient cursor cannot be inspected")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	generation, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now)
	if err != nil {
		return 0, err
	}
	if err := postgresLockSessionRoleBindings(tx, machineID, endpoint, now); err != nil {
		return 0, err
	}
	recipientIDs, err := postgresSessionRecipientIDs(tx, machineID, endpoint, generation, now)
	if err != nil {
		return 0, err
	}
	cursor, err := postgresRecipientCursorForLease(tx, recipientIDs, conversationID)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.New("recipient cursor snapshot cannot commit")
	}
	return cursor, nil
}

// RecipientMachines returns active machine owners for payload-free wake hints.
func (d *Database) RecipientMachines(messageID string, now time.Time) ([]string, error) {
	if _, err := uuid.Parse(messageID); err != nil {
		return nil, relay.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	rolesAvailable, err := postgresRoleBindingsAvailable(d.relayPool())
	if err != nil {
		return nil, errors.New("durable role bindings are unavailable")
	}
	query := `SELECT DISTINCT machine_id FROM (
		SELECT endpoint.machine_id FROM relay.mail_deliveries AS delivery
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=delivery.recipient_endpoint
		WHERE delivery.message_id=$1::uuid AND endpoint.lease_until>$2
	`
	if rolesAvailable {
		query += `UNION
		SELECT binding.machine_id FROM relay.mail_deliveries AS delivery
		JOIN relay.mail_role_bindings AS binding ON delivery.recipient_endpoint=chr(30)||'role:'||binding.role
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
		WHERE delivery.message_id=$1::uuid AND binding.lease_until>$2
		  AND endpoint.lease_until>$2 AND endpoint.machine_id=binding.machine_id
		  AND endpoint.ownership_generation=binding.ownership_generation
	`
	}
	query += `) AS recipients ORDER BY machine_id`
	rows, err := d.relayPool().QueryContext(ctx, query, messageID, now.UTC())
	if err != nil {
		return nil, errors.New("message recipients are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var machines []string
	for rows.Next() {
		var machineID string
		if err := rows.Scan(&machineID); err != nil {
			return nil, errors.New("message recipient is malformed")
		}
		machines = append(machines, machineID)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("message recipients are unavailable")
	}
	return machines, nil
}

// ConversationsForMachine lists rooms visible through live machine endpoints.
func (d *Database) ConversationsForMachine(machineID string, now time.Time) ([]relay.Conversation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	rolesAvailable, err := postgresRoleBindingsAvailable(d.relayPool())
	if err != nil {
		return nil, errors.New("durable role bindings are unavailable")
	}
	namesAvailable, err := postgresConversationDisplayNameAvailable(d.relayPool())
	if err != nil {
		return nil, errors.New("conversation display name schema is unavailable")
	}
	rows, err := d.relayPool().QueryContext(ctx, postgresConversationListSQL(rolesAvailable, namesAvailable), machineID, now.UTC())
	if err != nil {
		return nil, errors.New("machine conversations are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var conversations []relay.Conversation
	for rows.Next() {
		var conversation relay.Conversation
		if namesAvailable {
			var displayName sql.NullString
			if err := rows.Scan(&conversation.ID, &displayName); err != nil {
				return nil, errors.New("machine conversation is malformed")
			}
			conversation.DisplayName = displayName.String
		} else if err := rows.Scan(&conversation.ID); err != nil {
			return nil, errors.New("machine conversation is malformed")
		}
		conversations = append(conversations, conversation)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("machine conversations are unavailable")
	}
	return conversations, nil
}

func postgresSortedEndpoints(endpoints map[string]struct{}) []string {
	ordered := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		ordered = append(ordered, endpoint)
	}
	sort.Strings(ordered)
	return ordered
}

func postgresEndpointOwnedBy(tx *sql.Tx, endpoint, machineID string, now time.Time) error {
	var owner string
	var until time.Time
	if err := tx.QueryRowContext(context.Background(), `SELECT machine_id,lease_until FROM relay.mail_endpoints WHERE endpoint=$1`, endpoint).Scan(&owner, &until); errors.Is(err, sql.ErrNoRows) || owner != machineID || !until.After(now) {
		return relay.ErrForbidden
	} else if err != nil {
		return errors.New("endpoint ownership is unavailable")
	}
	return nil
}

func postgresEndpointOwnershipLocked(tx *sql.Tx, endpoint, machineID string, now time.Time) (int64, error) {
	var owner string
	var until time.Time
	var generation int64
	if err := tx.QueryRowContext(context.Background(), `SELECT machine_id,lease_until,ownership_generation FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE`, endpoint).Scan(&owner, &until, &generation); errors.Is(err, sql.ErrNoRows) || owner != machineID || !until.After(now) {
		return 0, relay.ErrForbidden
	} else if err != nil {
		return 0, errors.New("endpoint ownership is unavailable")
	}
	return generation, nil
}

func postgresMessageByID(tx *sql.Tx, messageID string) (relay.Message, error) {
	var message relay.Message
	metadataAvailable, err := postgresMessageMetadataAvailable(tx)
	if err != nil {
		return relay.Message{}, errors.New("message metadata schema is unavailable")
	}
	var fromRole, fromParticipant, replyMessage, replyEndpoint sql.NullString
	var threadID sql.NullInt64
	if !metadataAvailable {
		if err := tx.QueryRowContext(context.Background(), `SELECT message.id::text,message.conversation_id::text,message.sequence,message.from_endpoint,message.body,message.created_at,sender.from_role
			FROM relay.mail_messages AS message
			LEFT JOIN relay.mail_message_from_roles AS sender ON sender.message_id=message.id
			WHERE message.id=$1::uuid`, messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &message.Body, &message.CreatedAt, &fromRole); err != nil {
			return relay.Message{}, errors.New("idempotent message is unavailable")
		}
		message.CreatedAt = message.CreatedAt.UTC()
		postgresApplyDirectSender(&message, fromRole)
		return message, nil
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT message.id::text,message.conversation_id::text,message.sequence,message.from_endpoint,message.from_participant,message.in_reply_to_message_id,message.in_reply_to_endpoint,message.telegram_thread_id,message.body,message.created_at,sender.from_role
		FROM relay.mail_messages AS message
		LEFT JOIN relay.mail_message_from_roles AS sender ON sender.message_id=message.id
		WHERE message.id=$1::uuid`, messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &fromParticipant, &replyMessage, &replyEndpoint, &threadID, &message.Body, &message.CreatedAt, &fromRole); err != nil {
		return relay.Message{}, errors.New("idempotent message is unavailable")
	}
	applyPostgresMessageMetadata(&message, fromParticipant, replyMessage, replyEndpoint, threadID)
	message.CreatedAt = message.CreatedAt.UTC()
	return message, nil
}

func applyPostgresMessageMetadata(message *relay.Message, fromParticipant, replyMessage, replyEndpoint sql.NullString, threadID sql.NullInt64) {
	if fromParticipant.Valid {
		message.FromParticipant = fromParticipant.String
	}
	if replyMessage.Valid {
		message.InReplyToPunaroMessageID = replyMessage.String
	}
	if replyEndpoint.Valid {
		message.InReplyToEndpoint = replyEndpoint.String
	}
	if threadID.Valid {
		message.TelegramThreadID = threadID.Int64
	}
}

func postgresApplyDirectSender(message *relay.Message, fromRole sql.NullString) {
	if fromRole.Valid && fromRole.String != "" {
		message.FromRole = fromRole.String
		message.FromEndpoint = ""
	}
}

func postgresLeaseMessageColumns(metadataAvailable bool) string {
	if metadataAvailable {
		return `message.id::text,message.conversation_id::text,message.sequence,message.from_endpoint,message.from_participant,message.in_reply_to_message_id,message.in_reply_to_endpoint,message.telegram_thread_id,message.body,message.created_at,sender.from_role`
	}
	return `message.id::text,message.conversation_id::text,message.sequence,message.from_endpoint,message.body,message.created_at,sender.from_role`
}

func postgresMessageMetadataAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT (
		SELECT COUNT(*) FROM pg_attribute
		WHERE attrelid = to_regclass('relay.mail_messages')
		  AND attname IN ('from_participant','in_reply_to_message_id','in_reply_to_endpoint','telegram_thread_id')
		  AND attnum > 0 AND NOT attisdropped
	) = 4`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresAdvanceRecipientCursor(tx *sql.Tx, endpoint, conversationID string) error {
	var maximum int64
	if err := tx.QueryRowContext(context.Background(), `SELECT next_sequence FROM relay.mail_conversations WHERE id=$1::uuid`, conversationID).Scan(&maximum); err != nil {
		return errors.New("recipient cursor maximum is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_recipient_cursors(recipient_endpoint,conversation_id,sequence) VALUES($1,$2::uuid,0) ON CONFLICT DO NOTHING`, endpoint, conversationID); err != nil {
		return relayDatabaseError(err, "initialize recipient cursor")
	}
	var cursor int64
	if err := tx.QueryRowContext(context.Background(), `SELECT sequence FROM relay.mail_recipient_cursors WHERE recipient_endpoint=$1 AND conversation_id=$2::uuid FOR UPDATE`, endpoint, conversationID).Scan(&cursor); err != nil {
		return errors.New("recipient cursor is unavailable")
	}
	var nextPending sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), `SELECT MIN(message.sequence) FROM relay.mail_deliveries AS delivery
		JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.recipient_endpoint=$1 AND message.conversation_id=$2::uuid AND delivery.acked_at IS NULL AND message.sequence>$3`, endpoint, conversationID, cursor).Scan(&nextPending); err != nil {
		return errors.New("recipient cursor gap is unavailable")
	}
	var target int64
	if nextPending.Valid {
		target = nextPending.Int64 - 1
	} else {
		target = maximum
	}
	if target > cursor {
		if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_recipient_cursors SET sequence=$1 WHERE recipient_endpoint=$2 AND conversation_id=$3::uuid AND sequence=$4`, target, endpoint, conversationID, cursor); err != nil {
			return relayDatabaseError(err, "advance recipient cursor")
		}
	}
	return nil
}

func postgresAdvanceSkippedTargetCursors(tx *sql.Tx, conversationID, senderEndpoint, targetRole string) error {
	rows, err := tx.QueryContext(context.Background(), `
		SELECT endpoint FROM relay.mail_memberships
		WHERE conversation_id=$1::uuid AND (capabilities & $2) <> 0 AND endpoint<>$3
		UNION ALL
		SELECT chr(30)||'role:'||role FROM relay.mail_role_memberships
		WHERE conversation_id=$1::uuid AND (capabilities & $2) <> 0 AND role<>$4`, conversationID, relay.CapReceive, senderEndpoint, targetRole)
	if err != nil {
		return errors.New("skipped target recipients are unavailable")
	}
	var recipients []string
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			_ = rows.Close()
			return errors.New("skipped target recipient is malformed")
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Close(); err != nil {
		return errors.New("skipped target recipients are unavailable")
	}
	if err := rows.Err(); err != nil {
		return errors.New("skipped target recipients are unavailable")
	}
	for _, recipient := range recipients {
		if err := postgresAdvanceRecipientCursor(tx, recipient, conversationID); err != nil {
			return err
		}
	}
	return nil
}

func postgresAdvanceSkippedTelegramCursors(tx *sql.Tx, conversationID, senderEndpoint string) error {
	rows, err := tx.QueryContext(context.Background(), `
		SELECT endpoint FROM relay.mail_memberships
		WHERE conversation_id=$1::uuid AND (capabilities & $2) <> 0 AND endpoint<>$3 AND endpoint<>$4
		UNION ALL
		SELECT chr(30)||'role:'||role FROM relay.mail_role_memberships
		WHERE conversation_id=$1::uuid AND (capabilities & $2) <> 0`, conversationID, relay.CapReceive, senderEndpoint, relay.TelegramGatewayEndpoint)
	if err != nil {
		return errors.New("skipped telegram recipients are unavailable")
	}
	var recipients []string
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			_ = rows.Close()
			return errors.New("skipped telegram recipient is malformed")
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return errors.New("skipped telegram recipients are unavailable")
	}
	for _, recipient := range recipients {
		if err := postgresAdvanceRecipientCursor(tx, recipient, conversationID); err != nil {
			return err
		}
	}
	return nil
}

func postgresRequireCompleteTelegramClaim(tx *sql.Tx, conversationID string) error {
	available, err := postgresTelegramClaimsAvailable(tx)
	if err != nil || !available {
		return relay.ErrForbidden
	}
	var status string
	err = tx.QueryRowContext(context.Background(), `SELECT status FROM relay.mail_telegram_claims WHERE conversation_id=$1::uuid`, conversationID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || status != "complete" {
		return relay.ErrForbidden
	}
	if err != nil {
		return errors.New("telegram claim is unavailable")
	}
	return nil
}

func postgresTelegramClaimByConversation(tx *sql.Tx, conversationID string) (relay.TelegramClaim, error) {
	return postgresTelegramClaimByConversationLocked(tx, conversationID, false)
}

func postgresTelegramClaimByConversationLocked(tx *sql.Tx, conversationID string, lock bool) (relay.TelegramClaim, error) {
	var claim relay.TelegramClaim
	var completedAt sql.NullTime
	query := `SELECT claim.conversation_id::text, claim.status, COALESCE(conversation.display_name, ''), claim.created_at, claim.completed_at
		FROM relay.mail_telegram_claims AS claim
		JOIN relay.mail_conversations AS conversation ON conversation.id = claim.conversation_id
		WHERE claim.conversation_id=$1::uuid`
	if lock {
		query += ` FOR UPDATE OF claim`
	}
	if err := tx.QueryRowContext(context.Background(), query, conversationID).Scan(&claim.ConversationID, &claim.Status, &claim.DisplayName, &claim.CreatedAt, &completedAt); err != nil {
		return relay.TelegramClaim{}, err
	}
	claim.CreatedAt = claim.CreatedAt.UTC()
	if completedAt.Valid {
		completed := completedAt.Time.UTC()
		claim.CompletedAt = &completed
	}
	return claim, nil
}

// ReserveTelegramClaim is a singleton ensure: the first successful reserve
// wins, and any later key returns that row without rewriting it.
func (d *Database) ReserveTelegramClaim(input relay.TelegramClaimInput) (relay.TelegramClaim, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.MachineID) || !relay.ValidEndpoint(input.Endpoint) || !relay.ValidRequestToken(input.IdempotencyKey) {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if _, err := uuid.Parse(input.ConversationID); err != nil {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.TelegramClaim{}, false, errors.New("telegram claim transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	available, err := postgresTelegramClaimsAvailable(tx)
	if err != nil || !available {
		return relay.TelegramClaim{}, false, errors.New("telegram claims are unavailable")
	}
	if _, err := postgresEndpointOwnershipLocked(tx, input.Endpoint, input.MachineID, input.Now); err != nil {
		return relay.TelegramClaim{}, false, err
	}
	conversation, err := postgresConversationByID(tx, input.ConversationID)
	if err != nil || conversation.DisplayName == "" {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if input.Endpoint != relay.TelegramGatewayEndpoint {
		if err := postgresLockSessionRoleBindings(tx, input.MachineID, input.Endpoint, input.Now); err != nil {
			return relay.TelegramClaim{}, false, err
		}
		capabilities, err := postgresSessionCapabilities(tx, input.ConversationID, input.MachineID, input.Endpoint, input.Now)
		if err != nil {
			return relay.TelegramClaim{}, false, errors.New("telegram claim actor authorization is unavailable")
		}
		if capabilities == 0 {
			return relay.TelegramClaim{}, false, relay.ErrForbidden
		}
	}
	claim, err := postgresTelegramClaimByConversation(tx, input.ConversationID)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return relay.TelegramClaim{}, false, errors.New("telegram claim retry cannot commit")
		}
		return claim, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return relay.TelegramClaim{}, false, errors.New("telegram claim is unavailable")
	}
	if err := postgresRejectExclusiveClaimOccupancy(tx, input.ConversationID, input.Now); err != nil {
		return relay.TelegramClaim{}, false, err
	}
	createdAt := input.Now.UTC().Truncate(time.Microsecond)
	result, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_telegram_claims(conversation_id,status,requested_by_machine,requested_by_endpoint,idempotency_key,request_hash,created_at)
		VALUES($1::uuid,'pending',$2,$3,$4,$5,$6)
		ON CONFLICT (conversation_id) DO NOTHING`, input.ConversationID, input.MachineID, input.Endpoint, input.IdempotencyKey, postgresTelegramClaimHash(input.ConversationID), createdAt)
	if err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "reserve telegram claim")
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return relay.TelegramClaim{}, false, errors.New("telegram claim insert is unavailable")
	}
	if inserted == 0 {
		claim, err := postgresTelegramClaimByConversation(tx, input.ConversationID)
		if err != nil {
			return relay.TelegramClaim{}, false, errors.New("telegram claim is unavailable")
		}
		if err := tx.Commit(); err != nil {
			return relay.TelegramClaim{}, false, errors.New("telegram claim retry cannot commit")
		}
		return claim, true, nil
	}
	if err := tx.Commit(); err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "commit telegram claim")
	}
	return relay.TelegramClaim{ConversationID: input.ConversationID, Status: "pending", DisplayName: conversation.DisplayName, CreatedAt: createdAt}, false, nil
}

func postgresTelegramClaimHash(conversationID string) string {
	digest := sha256.Sum256([]byte(conversationID))
	return hex.EncodeToString(digest[:])
}

// CompleteTelegramClaim materializes telegram/primary and user-telegram after
// a pending reservation. A completed row is an idempotent no-op.
func (d *Database) CompleteTelegramClaim(input relay.TelegramClaimCompleteInput) (relay.TelegramClaim, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.MachineID) {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if _, err := uuid.Parse(input.ConversationID); err != nil {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.TelegramClaim{}, false, errors.New("telegram claim complete cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	available, err := postgresTelegramClaimsAvailable(tx)
	if err != nil || !available {
		return relay.TelegramClaim{}, false, errors.New("telegram claims are unavailable")
	}
	if _, err := postgresEndpointOwnershipLocked(tx, relay.TelegramGatewayEndpoint, input.MachineID, input.Now); err != nil {
		return relay.TelegramClaim{}, false, err
	}
	claim, err := postgresTelegramClaimByConversationLocked(tx, input.ConversationID, true)
	if err != nil {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if claim.Status == "complete" {
		if err := tx.Commit(); err != nil {
			return relay.TelegramClaim{}, false, errors.New("telegram claim complete retry cannot commit")
		}
		return claim, true, nil
	}
	if claim.Status != "pending" {
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if err := postgresEnsureTelegramGatewayMembership(tx, input.ConversationID); err != nil {
		return relay.TelegramClaim{}, false, err
	}
	completedAt := input.Now.UTC().Truncate(time.Microsecond)
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_telegram_participants(conversation_id,label,created_at) VALUES($1::uuid,$2,$3) ON CONFLICT (conversation_id) DO NOTHING`, input.ConversationID, relay.TelegramUserParticipant, completedAt); err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "insert telegram participant")
	}
	result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_telegram_claims SET status='complete', completed_at=$2 WHERE conversation_id=$1::uuid AND status='pending'`, input.ConversationID, completedAt)
	if err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "complete telegram claim")
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return relay.TelegramClaim{}, false, errors.New("telegram claim complete is unavailable")
	}
	if updated == 0 {
		claim, err := postgresTelegramClaimByConversation(tx, input.ConversationID)
		if err != nil {
			return relay.TelegramClaim{}, false, relay.ErrForbidden
		}
		if claim.Status == "complete" {
			if err := tx.Commit(); err != nil {
				return relay.TelegramClaim{}, false, errors.New("telegram claim complete retry cannot commit")
			}
			return claim, true, nil
		}
		return relay.TelegramClaim{}, false, relay.ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_telegram_claim_events(conversation_id,event,actor_machine,actor_endpoint,created_at) VALUES($1::uuid,'complete',$2,$3,$4)`, input.ConversationID, input.MachineID, relay.TelegramGatewayEndpoint, completedAt); err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "record telegram claim event")
	}
	if err := tx.Commit(); err != nil {
		return relay.TelegramClaim{}, false, relayDatabaseError(err, "commit telegram claim complete")
	}
	claim.Status = "complete"
	claim.CompletedAt = &completedAt
	return claim, false, nil
}

// PendingTelegramClaims is a gateway poll of pending reservations, not a lease.
func (d *Database) PendingTelegramClaims(machineID string, now time.Time, limit int, after string) ([]relay.TelegramClaim, error) {
	if !relay.ValidMachineID(machineID) || limit < 1 || limit > 100 || (after != "" && strings.TrimSpace(after) != after) {
		return nil, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errors.New("pending telegram claims cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, relay.TelegramGatewayEndpoint, machineID, now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(context.Background(), postgresPendingTelegramClaimsSQL(), limit, postgresNullableUUID(after)) // #nosec G202 -- query is the fixed postgresPendingTelegramClaimsSQL allowlist.
	if err != nil {
		return nil, errors.New("pending telegram claims are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var claims []relay.TelegramClaim
	for rows.Next() {
		var claim relay.TelegramClaim
		var completedAt sql.NullTime
		if err := rows.Scan(&claim.ConversationID, &claim.Status, &claim.DisplayName, &claim.CreatedAt, &completedAt); err != nil {
			return nil, errors.New("pending telegram claim is malformed")
		}
		claim.CreatedAt = claim.CreatedAt.UTC()
		if completedAt.Valid {
			completed := completedAt.Time.UTC()
			claim.CompletedAt = &completed
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("pending telegram claims are unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("pending telegram claims cannot commit")
	}
	return claims, nil
}

// UnclaimedNamedConversations returns the newest named rooms without a
// completed claim. Last-message time is computed from messages.created_at.
func (d *Database) UnclaimedNamedConversations(machineID string, now time.Time, limit int) ([]relay.UnclaimedTopic, error) {
	if !relay.ValidMachineID(machineID) || limit < 1 || limit > 100 {
		return nil, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, errors.New("unclaimed topics cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, relay.TelegramGatewayEndpoint, machineID, now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT conversation.id::text, conversation.display_name, MAX(message.created_at)
		FROM relay.mail_conversations AS conversation
		LEFT JOIN relay.mail_messages AS message ON message.conversation_id = conversation.id
		WHERE conversation.display_name IS NOT NULL AND conversation.display_name <> ''
		  AND NOT EXISTS (SELECT 1 FROM relay.mail_telegram_claims WHERE conversation_id = conversation.id AND status = 'complete')
		GROUP BY conversation.id
		ORDER BY MAX(message.created_at) DESC NULLS LAST, conversation.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, errors.New("unclaimed topics are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var topics []relay.UnclaimedTopic
	for rows.Next() {
		var topic relay.UnclaimedTopic
		var lastMessage sql.NullTime
		if err := rows.Scan(&topic.ID, &topic.DisplayName, &lastMessage); err != nil {
			return nil, errors.New("unclaimed topic is malformed")
		}
		if lastMessage.Valid {
			at := lastMessage.Time.UTC()
			topic.LastMessageAt = &at
		}
		topics = append(topics, topic)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("unclaimed topics are unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("unclaimed topics cannot commit")
	}
	return topics, nil
}

// SessionTopic returns the endpoint's sole named or claimed occupancy.
func (d *Database) SessionTopic(machineID, endpoint string, now time.Time) (relay.SessionTopic, error) {
	if !relay.ValidMachineID(machineID) || !relay.ValidEndpoint(endpoint) {
		return relay.SessionTopic{}, relay.ErrForbidden
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return relay.SessionTopic{}, errors.New("session topic cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresEndpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return relay.SessionTopic{}, err
	}
	namesAvailable, err := postgresConversationDisplayNameAvailable(tx)
	if err != nil {
		return relay.SessionTopic{}, errors.New("conversation display name schema is unavailable")
	}
	claimsAvailable, err := postgresTelegramClaimsAvailable(tx)
	if err != nil {
		return relay.SessionTopic{}, errors.New("telegram claim schema is unavailable")
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT conversation.id::text, COALESCE(conversation.display_name, ''), EXISTS(SELECT 1 FROM relay.mail_telegram_claims WHERE conversation_id = conversation.id AND status = 'complete')
		FROM relay.mail_conversations AS conversation
		WHERE `+postgresExclusiveConversationPredicate("conversation", namesAvailable, claimsAvailable)+`
		  AND (
			EXISTS (SELECT 1 FROM relay.mail_memberships WHERE conversation_id = conversation.id AND endpoint = $1)
			OR EXISTS (
				SELECT 1 FROM relay.mail_role_memberships AS membership
				JOIN relay.mail_role_bindings AS binding ON binding.role = membership.role
				JOIN relay.mail_endpoints AS live ON live.endpoint = binding.session_endpoint
				WHERE membership.conversation_id = conversation.id
				  AND binding.session_endpoint = $1
				  AND binding.lease_until > $2
				  AND live.machine_id = binding.machine_id
				  AND live.ownership_generation = binding.ownership_generation
				  AND live.lease_until > $2
			)
		  )`, endpoint, now.UTC()) // #nosec G202 -- exclusive predicate is a schema-presence allowlist; alias is a fixed identifier.
	if err != nil {
		return relay.SessionTopic{}, errors.New("session topic is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var topics []relay.SessionTopic
	for rows.Next() {
		var topic relay.SessionTopic
		if err := rows.Scan(&topic.ID, &topic.DisplayName, &topic.Claimed); err != nil {
			return relay.SessionTopic{}, errors.New("session topic is malformed")
		}
		topics = append(topics, topic)
	}
	if err := rows.Err(); err != nil {
		return relay.SessionTopic{}, errors.New("session topic is unavailable")
	}
	if len(topics) == 0 {
		return relay.SessionTopic{}, relay.ErrForbidden
	}
	if len(topics) > 1 {
		return relay.SessionTopic{}, relay.ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return relay.SessionTopic{}, errors.New("session topic cannot commit")
	}
	return topics[0], nil
}

func postgresEnsureTelegramGatewayMembership(tx *sql.Tx, conversationID string) error {
	var previous relay.Capability
	err := tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2 FOR UPDATE`, conversationID, relay.TelegramGatewayEndpoint).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities) VALUES($1::uuid,$2,$3)`, conversationID, relay.TelegramGatewayEndpoint, relay.TelegramGatewayCapabilities); err != nil {
			return relayDatabaseError(err, "insert telegram gateway member")
		}
		return postgresAdvanceRecipientCursor(tx, relay.TelegramGatewayEndpoint, conversationID)
	}
	if err != nil {
		return errors.New("telegram gateway member is unavailable")
	}
	if previous != relay.TelegramGatewayCapabilities {
		if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_memberships SET capabilities=$3 WHERE conversation_id=$1::uuid AND endpoint=$2`, conversationID, relay.TelegramGatewayEndpoint, relay.TelegramGatewayCapabilities); err != nil {
			return relayDatabaseError(err, "clamp telegram gateway member")
		}
	}
	if previous&relay.CapReceive == 0 {
		return postgresAdvanceRecipientCursor(tx, relay.TelegramGatewayEndpoint, conversationID)
	}
	return nil
}

// AppendTelegramInbound accepts gateway inbound mail. Metadata is stored but
// excluded from the append hash so a later reply-map fill cannot conflict.
func (d *Database) AppendTelegramInbound(input relay.TelegramInboundInput) (relay.Message, bool, error) {
	if err := relay.ValidateTelegramInbound(input); err != nil {
		return relay.Message{}, false, err
	}
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Message{}, false, errors.New("telegram inbound cannot start")
	}
	if err := postgresRequireCompleteTelegramClaim(tx, input.ConversationID); err != nil {
		cancel()
		_ = tx.Rollback()
		return relay.Message{}, false, err
	}
	_ = tx.Rollback()
	cancel()
	return d.AppendMessage(relay.AppendInput{
		ConversationID:           input.ConversationID,
		SenderMachineID:          input.SenderMachineID,
		FromEndpoint:             input.FromEndpoint,
		FromParticipant:          input.FromParticipant,
		InReplyToPunaroMessageID: input.InReplyToMessageID,
		InReplyToEndpoint:        input.InReplyToEndpoint,
		TelegramThreadID:         input.TelegramThreadID,
		Body:                     input.Body,
		IdempotencyKey:           input.IdempotencyKey,
		Now:                      input.Now,
	})
}

func postgresNullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func postgresNullableThreadID(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func postgresSessionCapabilities(tx *sql.Tx, conversationID, machineID, endpoint string, now time.Time) (relay.Capability, error) {
	if err := postgresEndpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return 0, err
	}
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return 0, errors.New("session authorization is unavailable")
	}
	var capabilities int64
	if !rolesAvailable {
		err = tx.QueryRowContext(context.Background(), `SELECT COALESCE(capabilities::int,0) FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, conversationID, endpoint).Scan(&capabilities)
	} else {
		err = tx.QueryRowContext(context.Background(), `SELECT COALESCE(bit_or(capabilities::int),0) FROM (
		SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2
		UNION ALL
		SELECT membership.capabilities FROM relay.mail_role_memberships AS membership
		JOIN relay.mail_role_bindings AS binding ON binding.role=membership.role
		JOIN relay.mail_endpoints AS live ON live.endpoint=binding.session_endpoint
		WHERE membership.conversation_id=$1::uuid AND binding.machine_id=$3 AND binding.session_endpoint=$2
		  AND binding.lease_until>$4 AND live.machine_id=$3 AND live.lease_until>$4
		  AND live.ownership_generation=binding.ownership_generation
	) AS grants`, conversationID, endpoint, machineID, now.UTC()).Scan(&capabilities)
	}
	if err != nil {
		return 0, errors.New("session authorization is unavailable")
	}
	if capabilities < 0 || capabilities > int64(relay.CapSend|relay.CapReceive|relay.CapAdmin|relay.CapInvoke) {
		return 0, errors.New("session authorization is malformed")
	}
	return relay.Capability(capabilities), nil
}

// postgresLockSessionRoleBindings serializes a live session's role-authorized
// work with a rebind. Role bindings are mutable fences, unlike immutable role
// ownership records, so operations that lease, acknowledge, or append through
// them must hold a shared lock until commit.
func postgresLockSessionRoleBindings(tx *sql.Tx, machineID, endpoint string, now time.Time) error {
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return errors.New("session role bindings are unavailable")
	}
	if !rolesAvailable {
		return nil
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT binding.role FROM relay.mail_role_bindings AS binding
		WHERE binding.machine_id=$1 AND binding.session_endpoint=$2 AND binding.lease_until>$3
		FOR SHARE OF binding`, machineID, endpoint, now.UTC())
	if err != nil {
		return errors.New("session role bindings are unavailable")
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return errors.New("session role binding is malformed")
		}
	}
	if err := rows.Err(); err != nil {
		return errors.New("session role bindings are unavailable")
	}
	return nil
}

func postgresSessionRecipientIDs(tx *sql.Tx, machineID, endpoint string, generation int64, now time.Time) ([]string, error) {
	rolesAvailable, err := postgresRoleBindingsAvailable(tx)
	if err != nil {
		return nil, errors.New("session recipients are unavailable")
	}
	if !rolesAvailable {
		return []string{endpoint}, nil
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT recipient FROM (
		SELECT $2::text AS recipient,0 AS ordinal
		UNION ALL
		SELECT chr(30)||'role:'||binding.role,1 AS ordinal FROM relay.mail_role_bindings AS binding
		JOIN relay.mail_endpoints AS live ON live.endpoint=binding.session_endpoint
		WHERE binding.machine_id=$1 AND binding.session_endpoint=$2 AND binding.ownership_generation=$3
		  AND binding.lease_until>$4 AND live.machine_id=$1 AND live.lease_until>$4
		  AND live.ownership_generation=$3
	) AS identities ORDER BY ordinal,recipient`, machineID, endpoint, generation, now.UTC())
	if err != nil {
		return nil, errors.New("session recipients are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var identities []string
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return nil, errors.New("session recipient is malformed")
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("session recipients are unavailable")
	}
	return identities, nil
}

func postgresRoleBindingsAvailable(q queryer) (bool, error) {
	var available bool
	if err := q.QueryRowContext(context.Background(), `SELECT to_regclass('relay.mail_role_bindings') IS NOT NULL`).Scan(&available); err != nil {
		return false, err
	}
	return available, nil
}

func postgresAdvanceSessionCursors(tx *sql.Tx, machineID, endpoint, conversationID string, now time.Time) error {
	if _, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now); err != nil {
		return err
	}
	var capabilities relay.Capability
	err := tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, conversationID, endpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&relay.CapReceive == 0 {
		return nil
	}
	if err != nil {
		return errors.New("sender cursor authorization is unavailable")
	}
	if err := postgresAdvanceRecipientCursor(tx, endpoint, conversationID); err != nil {
		return err
	}
	return nil
}

func postgresParseRoleRecipient(value string) (string, bool) {
	role, ok := strings.CutPrefix(value, "\x1erole:")
	return role, ok && relay.ValidRole(role)
}

func postgresContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func relayDatabaseError(err error, operation string) error {
	if isMaintenanceError(err) {
		return relay.ErrMaintenance
	}
	if isSQLState(err, "42501") {
		return relay.ErrForbidden
	}
	if isSQLState(err, "23505") {
		return relay.ErrConflict
	}
	return fmt.Errorf("PostgreSQL relay %s failed", operation)
}

func (d *Database) beginRelayTransaction(options *sql.TxOptions) (*sql.Tx, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	tx, err := d.relayPool().BeginTx(ctx, options)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	for _, statement := range []string{
		`SET LOCAL statement_timeout = '5s'`,
		`SET LOCAL lock_timeout = '5s'`,
	} {
		if _, err := tx.ExecContext(context.Background(), statement); err != nil {
			_ = tx.Rollback()
			cancel()
			return nil, nil, err
		}
	}
	return tx, cancel, nil
}

func (d *Database) relayPool() *sql.DB {
	if d.relayDB != nil {
		return d.relayDB
	}
	return d.db
}

func relayControlsAvailable(ctx context.Context, q queryer, schemaVersion int64) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_endpoints') AS endpoints_oid,
           to_regclass('relay.mail_conversations') AS conversations_oid,
           to_regclass('relay.mail_memberships') AS memberships_oid,
		   to_regclass('relay.mail_roles') AS roles_oid,
		   to_regclass('relay.mail_role_memberships') AS role_memberships_oid,
		   to_regclass('relay.mail_role_bindings') AS role_bindings_oid,
           to_regclass('relay.mail_messages') AS messages_oid,
           to_regclass('relay.mail_deliveries') AS deliveries_oid,
           to_regclass('relay.mail_recipient_cursors') AS cursors_oid,
           to_regclass('relay.mail_message_idempotency') AS message_idempotency_oid,
           to_regclass('relay.mail_conversation_idempotency') AS conversation_idempotency_oid,
           to_regclass('relay.mail_request_nonces') AS nonces_oid,
		   to_regclass('relay.mail_telegram_claims') AS telegram_claims_oid,
		   to_regclass('relay.mail_telegram_participants') AS telegram_participants_oid,
		   to_regclass('relay.mail_telegram_claim_events') AS telegram_claim_events_oid,
		   to_regclass('relay.mail_endpoints_machine') AS endpoints_index_oid,
		   to_regclass('relay.mail_role_bindings_session') AS role_bindings_index_oid,
		   to_regclass('relay.mail_deliveries_pending') AS deliveries_index_oid,
           to_regclass('relay.mail_request_nonces_expiry') AS nonces_index_oid,
           to_regprocedure('relay.consume_mail_request_nonce(text,text,timestamp with time zone,timestamp with time zone)') AS consume_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS legacy_guard_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS cutover_guard_oid
), table_ownership AS (
    SELECT count(*)=CASE WHEN $1 >= 51 THEN 15 WHEN $1 >= 40 THEN 12 ELSE 9 END AND bool_and(pg_get_userbyid(relation.relowner)='punaro_owner' AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS relation ON relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
), expected_columns(table_oid,column_name,type_oid,required) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'endpoint','text'::regtype,true),(endpoints_oid,'machine_id','text'::regtype,true),
        (endpoints_oid,'lease_until','timestamptz'::regtype,true),(endpoints_oid,'ownership_generation','bigint'::regtype,true),
        (endpoints_oid,'consumer_id','text'::regtype,false),(endpoints_oid,'consumer_generation','bigint'::regtype,true),
        (endpoints_oid,'consumer_lease_until','timestamptz'::regtype,false),
        (conversations_oid,'id','uuid'::regtype,true),(conversations_oid,'next_sequence','bigint'::regtype,true),(conversations_oid,'created_at','timestamptz'::regtype,true),
        (conversations_oid,'display_name','text'::regtype,false),
        (memberships_oid,'conversation_id','uuid'::regtype,true),(memberships_oid,'endpoint','text'::regtype,true),(memberships_oid,'capabilities','smallint'::regtype,true),
		(roles_oid,'role','text'::regtype,true),(roles_oid,'machine_id','text'::regtype,true),
		(role_memberships_oid,'conversation_id','uuid'::regtype,true),(role_memberships_oid,'role','text'::regtype,true),(role_memberships_oid,'capabilities','smallint'::regtype,true),
		(role_bindings_oid,'role','text'::regtype,true),(role_bindings_oid,'session_endpoint','text'::regtype,true),(role_bindings_oid,'machine_id','text'::regtype,true),(role_bindings_oid,'ownership_generation','bigint'::regtype,true),(role_bindings_oid,'lease_until','timestamptz'::regtype,true),
        (messages_oid,'id','uuid'::regtype,true),(messages_oid,'conversation_id','uuid'::regtype,true),(messages_oid,'sequence','bigint'::regtype,true),
        (messages_oid,'from_endpoint','text'::regtype,true),(messages_oid,'body','text'::regtype,true),(messages_oid,'created_at','timestamptz'::regtype,true),
        (messages_oid,'from_participant','text'::regtype,false),(messages_oid,'in_reply_to_message_id','text'::regtype,false),(messages_oid,'in_reply_to_endpoint','text'::regtype,false),(messages_oid,'telegram_thread_id','bigint'::regtype,false),
        (telegram_claims_oid,'conversation_id','uuid'::regtype,true),(telegram_claims_oid,'status','text'::regtype,true),(telegram_claims_oid,'requested_by_machine','text'::regtype,true),(telegram_claims_oid,'requested_by_endpoint','text'::regtype,true),
        (telegram_claims_oid,'idempotency_key','text'::regtype,true),(telegram_claims_oid,'request_hash','bpchar'::regtype,true),(telegram_claims_oid,'created_at','timestamptz'::regtype,true),(telegram_claims_oid,'completed_at','timestamptz'::regtype,false),
        (telegram_participants_oid,'conversation_id','uuid'::regtype,true),(telegram_participants_oid,'label','text'::regtype,true),(telegram_participants_oid,'created_at','timestamptz'::regtype,true),
        (telegram_claim_events_oid,'id','uuid'::regtype,true),(telegram_claim_events_oid,'conversation_id','uuid'::regtype,true),(telegram_claim_events_oid,'event','text'::regtype,true),
        (telegram_claim_events_oid,'actor_machine','text'::regtype,true),(telegram_claim_events_oid,'actor_endpoint','text'::regtype,true),(telegram_claim_events_oid,'created_at','timestamptz'::regtype,true),
        (deliveries_oid,'id','uuid'::regtype,true),(deliveries_oid,'message_id','uuid'::regtype,true),(deliveries_oid,'recipient_endpoint','text'::regtype,true),
        (deliveries_oid,'lease_machine_id','text'::regtype,false),(deliveries_oid,'lease_token','uuid'::regtype,false),(deliveries_oid,'lease_generation','bigint'::regtype,true),
        (deliveries_oid,'ownership_generation','bigint'::regtype,false),(deliveries_oid,'consumer_generation','bigint'::regtype,false),
        (deliveries_oid,'lease_until','timestamptz'::regtype,false),(deliveries_oid,'acked_at','timestamptz'::regtype,false),
        (cursors_oid,'recipient_endpoint','text'::regtype,true),(cursors_oid,'conversation_id','uuid'::regtype,true),(cursors_oid,'sequence','bigint'::regtype,true),
        (message_idempotency_oid,'machine_id','text'::regtype,true),(message_idempotency_oid,'key','text'::regtype,true),(message_idempotency_oid,'request_hash','bpchar'::regtype,true),
        (message_idempotency_oid,'message_id','uuid'::regtype,true),(message_idempotency_oid,'created_at','timestamptz'::regtype,true),
        (conversation_idempotency_oid,'machine_id','text'::regtype,true),(conversation_idempotency_oid,'key','text'::regtype,true),(conversation_idempotency_oid,'request_hash','bpchar'::regtype,true),
        (conversation_idempotency_oid,'conversation_id','uuid'::regtype,true),(conversation_idempotency_oid,'created_at','timestamptz'::regtype,true),
        (nonces_oid,'machine_id','text'::regtype,true),(nonces_oid,'nonce','text'::regtype,true),(nonces_oid,'expires_at','timestamptz'::regtype,true)
    ) AS expected(table_oid,column_name,type_oid,required)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 50 OR NOT (expected.table_oid=conversations_oid AND expected.column_name='display_name'))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid AND NOT (expected.table_oid=messages_oid AND expected.column_name IN ('from_participant','in_reply_to_message_id','in_reply_to_endpoint','telegram_thread_id'))))
), actual_columns AS (
    SELECT attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull
    FROM objects JOIN pg_attribute AS attribute
      ON attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND attribute.attnum>0 AND NOT attribute.attisdropped
), columns AS (
    SELECT NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
       AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
       AND (SELECT count(*)=CASE WHEN $1 >= 51 THEN 3 ELSE 2 END FROM pg_attribute WHERE attrelid=ANY(ARRAY[message_idempotency_oid,conversation_idempotency_oid,telegram_claims_oid]) AND attname='request_hash' AND atttypid='bpchar'::regtype AND atttypmod=68)
       AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid]) AND attnum>0 AND NOT attisdropped AND atttypid<>'bpchar'::regtype AND atttypmod<>-1) AS exact
    FROM objects
), expected_defaults(table_oid,column_name,expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'ownership_generation','1'),(endpoints_oid,'consumer_generation','0'),
        (conversations_oid,'id','gen_random_uuid()'),(conversations_oid,'next_sequence','0'),(conversations_oid,'created_at','statement_timestamp()'),
        (messages_oid,'id','gen_random_uuid()'),(deliveries_oid,'id','gen_random_uuid()'),(deliveries_oid,'lease_generation','0'),
        (cursors_oid,'sequence','0'),(telegram_claim_events_oid,'id','gen_random_uuid()')
    ) AS expected(table_oid,column_name,expression)
    WHERE $1 >= 51 OR expected.table_oid IS DISTINCT FROM telegram_claim_events_oid
), actual_defaults AS (
    SELECT default_value.adrelid,attribute.attname,pg_get_expr(default_value.adbin,default_value.adrelid)
    FROM objects JOIN pg_attrdef AS default_value
      ON default_value.adrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
    JOIN pg_attribute AS attribute ON attribute.attrelid=default_value.adrelid AND attribute.attnum=default_value.adnum
), defaults AS (
    SELECT NOT EXISTS (SELECT * FROM expected_defaults EXCEPT SELECT * FROM actual_defaults)
       AND NOT EXISTS (SELECT * FROM actual_defaults EXCEPT SELECT * FROM expected_defaults) AS exact
), expected_keys(table_oid,constraint_type,column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'p'::"char",ARRAY[1]::smallint[]),(conversations_oid,'p'::"char",ARRAY[1]::smallint[]),
        (memberships_oid,'p'::"char",ARRAY[1,2]::smallint[]),(messages_oid,'p'::"char",ARRAY[1]::smallint[]),
		(roles_oid,'p'::"char",ARRAY[1]::smallint[]),(role_memberships_oid,'p'::"char",ARRAY[1,2]::smallint[]),(role_bindings_oid,'p'::"char",ARRAY[1]::smallint[]),
        (deliveries_oid,'p'::"char",ARRAY[1]::smallint[]),(cursors_oid,'p'::"char",ARRAY[1,2]::smallint[]),
        (message_idempotency_oid,'p'::"char",ARRAY[1,2]::smallint[]),(conversation_idempotency_oid,'p'::"char",ARRAY[1,2]::smallint[]),
        (nonces_oid,'p'::"char",ARRAY[1,2]::smallint[]),
        (telegram_claims_oid,'p'::"char",ARRAY[1]::smallint[]),(telegram_participants_oid,'p'::"char",ARRAY[1]::smallint[]),(telegram_claim_events_oid,'p'::"char",ARRAY[1]::smallint[]),
        (messages_oid,'u'::"char",ARRAY[2,3]::smallint[]),(deliveries_oid,'u'::"char",ARRAY[2,3]::smallint[]),
        (message_idempotency_oid,'u'::"char",ARRAY[4]::smallint[]),(conversation_idempotency_oid,'u'::"char",ARRAY[4]::smallint[])
    ) AS expected(table_oid,constraint_type,column_keys)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid))
), actual_keys AS (
    SELECT con.conrelid,con.contype,con.conkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND con.contype IN ('p','u') AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
), expected_foreign_keys(table_oid,column_keys,foreign_table_oid,foreign_column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (memberships_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(memberships_oid,ARRAY[2]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
        (messages_oid,ARRAY[2]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(messages_oid,ARRAY[4]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(role_memberships_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(role_memberships_oid,ARRAY[2]::smallint[],roles_oid,ARRAY[1]::smallint[]),
		(role_bindings_oid,ARRAY[1]::smallint[],roles_oid,ARRAY[1]::smallint[]),(role_bindings_oid,ARRAY[2]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(deliveries_oid,ARRAY[2]::smallint[],messages_oid,ARRAY[1]::smallint[]),(deliveries_oid,ARRAY[3]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(cursors_oid,ARRAY[1]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),(cursors_oid,ARRAY[2]::smallint[],conversations_oid,ARRAY[1]::smallint[]),
        (message_idempotency_oid,ARRAY[4]::smallint[],messages_oid,ARRAY[1]::smallint[]),(conversation_idempotency_oid,ARRAY[4]::smallint[],conversations_oid,ARRAY[1]::smallint[]),
        (telegram_claims_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(telegram_participants_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(telegram_claim_events_oid,ARRAY[2]::smallint[],conversations_oid,ARRAY[1]::smallint[])
    ) AS expected(table_oid,column_keys,foreign_table_oid,foreign_column_keys)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 < 40 OR (NOT (expected.table_oid=deliveries_oid AND expected.column_keys=ARRAY[3]::smallint[])
                         AND NOT (expected.table_oid=cursors_oid AND expected.column_keys=ARRAY[1]::smallint[])))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid))
), actual_foreign_keys AS (
    SELECT con.conrelid,con.conkey,con.confrelid,con.confkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[memberships_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND con.contype='f' AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
     AND con.confupdtype='a' AND con.confdeltype='a' AND con.confmatchtype='s'
), expected_check_keys(table_oid,column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,ARRAY[1]::smallint[]),(endpoints_oid,ARRAY[2]::smallint[]),(endpoints_oid,ARRAY[4]::smallint[]),
        (endpoints_oid,ARRAY[5]::smallint[]),(endpoints_oid,ARRAY[6]::smallint[]),(endpoints_oid,ARRAY[5,7]::smallint[]),
        (conversations_oid,ARRAY[2]::smallint[]),(conversations_oid,ARRAY[4]::smallint[]),(memberships_oid,ARRAY[3]::smallint[]),
		(roles_oid,ARRAY[1]::smallint[]),(roles_oid,ARRAY[2]::smallint[]),(role_memberships_oid,ARRAY[3]::smallint[]),(role_bindings_oid,ARRAY[4]::smallint[]),
        (messages_oid,ARRAY[3]::smallint[]),(messages_oid,ARRAY[5]::smallint[]),
        (messages_oid,ARRAY[7]::smallint[]),(messages_oid,ARRAY[8]::smallint[]),(messages_oid,ARRAY[9]::smallint[]),(messages_oid,ARRAY[10]::smallint[]),
        (deliveries_oid,ARRAY[6]::smallint[]),(deliveries_oid,ARRAY[4,5,7,8,9]::smallint[]),
        (cursors_oid,ARRAY[3]::smallint[]),(message_idempotency_oid,ARRAY[2]::smallint[]),(message_idempotency_oid,ARRAY[3]::smallint[]),
        (conversation_idempotency_oid,ARRAY[2]::smallint[]),(conversation_idempotency_oid,ARRAY[3]::smallint[]),(nonces_oid,ARRAY[2]::smallint[]),
        (telegram_claims_oid,ARRAY[2]::smallint[]),(telegram_claims_oid,ARRAY[3]::smallint[]),(telegram_claims_oid,ARRAY[4]::smallint[]),(telegram_claims_oid,ARRAY[5]::smallint[]),(telegram_claims_oid,ARRAY[6]::smallint[]),(telegram_claims_oid,ARRAY[2,8]::smallint[]),
        (telegram_participants_oid,ARRAY[2]::smallint[]),
        (telegram_claim_events_oid,ARRAY[3]::smallint[]),(telegram_claim_events_oid,ARRAY[4]::smallint[]),(telegram_claim_events_oid,ARRAY[5]::smallint[])
    ) AS expected(table_oid,column_keys)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 50 OR NOT (expected.table_oid=conversations_oid AND expected.column_keys=ARRAY[4]::smallint[]))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid AND NOT (expected.table_oid=messages_oid AND (expected.column_keys=ARRAY[7]::smallint[] OR expected.column_keys=ARRAY[8]::smallint[] OR expected.column_keys=ARRAY[9]::smallint[] OR expected.column_keys=ARRAY[10]::smallint[]))))
), actual_check_keys AS (
    SELECT con.conrelid,con.conkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND con.contype='c' AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
), check_expressions AS (
    SELECT NOT EXISTS (SELECT * FROM expected_check_keys EXCEPT ALL SELECT * FROM actual_check_keys)
       AND NOT EXISTS (SELECT * FROM actual_check_keys EXCEPT ALL SELECT * FROM expected_check_keys)
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid]) AND contype='c' AND (NOT convalidated OR condeferrable OR condeferred))
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[1]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(endpoint) >= 1) AND (char_length(endpoint) <= 512) AND (octet_length(endpoint) <= 2048) AND (endpoint !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(machine_id) >= 1) AND (char_length(machine_id) <= 128) AND (octet_length(machine_id) <= 512) AND (machine_id !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='(ownership_generation > 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[6]::smallint[] AND pg_get_expr(conbin,conrelid)='(consumer_generation >= 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='((consumer_id IS NULL) OR ((char_length(consumer_id) >= 1) AND (char_length(consumer_id) <= 128) AND (octet_length(consumer_id) <= 512) AND (consumer_id !~ ''[[:cntrl:]]''::text)))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey @> ARRAY[5,7]::smallint[] AND conkey <@ ARRAY[5,7]::smallint[] AND pg_get_expr(conbin,conrelid)='((consumer_id IS NULL) = (consumer_lease_until IS NULL))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=conversations_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='(next_sequence >= 0)')
	   AND ($1 < 50 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=conversations_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='((display_name IS NULL) OR ((char_length(display_name) >= 1) AND (char_length(display_name) <= 128) AND (octet_length(display_name) <= 512) AND (display_name !~ ''[[:cntrl:]]''::text)))'))
	   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=memberships_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)=CASE WHEN $1 >= 43 THEN '((capabilities >= 1) AND (capabilities <= 15))' ELSE '((capabilities >= 1) AND (capabilities <= 7))' END)
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=roles_oid AND contype='c' AND conkey=ARRAY[1]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(role) >= 1) AND (char_length(role) <= 512) AND (octet_length(role) <= 2048) AND (role !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=roles_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(machine_id) >= 1) AND (char_length(machine_id) <= 128) AND (octet_length(machine_id) <= 512) AND (machine_id !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=role_memberships_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='((capabilities >= 1) AND (capabilities <= 7))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=role_bindings_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='(ownership_generation > 0)'))
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(sequence > 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='(octet_length(body) <= 32768)')
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[7]::smallint[] AND pg_get_expr(conbin,conrelid)='((from_participant IS NULL) OR (from_participant = ''user-telegram''::text))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[8]::smallint[] AND pg_get_expr(conbin,conrelid)='((in_reply_to_message_id IS NULL) OR ((char_length(in_reply_to_message_id) >= 1) AND (char_length(in_reply_to_message_id) <= 128) AND (octet_length(in_reply_to_message_id) <= 512) AND (in_reply_to_message_id !~ ''[[:cntrl:]]''::text)))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[9]::smallint[] AND pg_get_expr(conbin,conrelid)='((in_reply_to_endpoint IS NULL) OR ((char_length(in_reply_to_endpoint) >= 1) AND (char_length(in_reply_to_endpoint) <= 512) AND (octet_length(in_reply_to_endpoint) <= 2048) AND (in_reply_to_endpoint !~ ''[[:cntrl:]]''::text)))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[10]::smallint[] AND pg_get_expr(conbin,conrelid)='((telegram_thread_id IS NULL) OR (telegram_thread_id > 0))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='(status = ANY (ARRAY[''pending''::text, ''complete''::text]))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(requested_by_machine) >= 1) AND (char_length(requested_by_machine) <= 128) AND (octet_length(requested_by_machine) <= 512) AND (requested_by_machine !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(requested_by_endpoint) >= 1) AND (char_length(requested_by_endpoint) <= 512) AND (octet_length(requested_by_endpoint) <= 2048) AND (requested_by_endpoint !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(idempotency_key) >= 1) AND (char_length(idempotency_key) <= 128) AND (octet_length(idempotency_key) <= 512) AND (idempotency_key !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey=ARRAY[6]::smallint[] AND pg_get_expr(conbin,conrelid)='(request_hash ~ ''^[0-9a-f]{64}$''::text)'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claims_oid AND contype='c' AND conkey @> ARRAY[2,8]::smallint[] AND conkey <@ ARRAY[2,8]::smallint[] AND pg_get_expr(conbin,conrelid)='((status = ''complete''::text) = (completed_at IS NOT NULL))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_participants_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='(label = ''user-telegram''::text)'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claim_events_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(event = ''complete''::text)'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claim_events_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(actor_machine) >= 1) AND (char_length(actor_machine) <= 128) AND (octet_length(actor_machine) <= 512) AND (actor_machine !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 51 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=telegram_claim_events_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(actor_endpoint) >= 1) AND (char_length(actor_endpoint) <= 512) AND (octet_length(actor_endpoint) <= 2048) AND (actor_endpoint !~ ''[[:cntrl:]]''::text))'))
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=deliveries_oid AND contype='c' AND conkey=ARRAY[6]::smallint[] AND pg_get_expr(conbin,conrelid)='(lease_generation >= 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=deliveries_oid AND contype='c' AND conkey @> ARRAY[4,5,7,8,9]::smallint[] AND conkey <@ ARRAY[4,5,7,8,9]::smallint[] AND pg_get_expr(conbin,conrelid)='(((lease_machine_id IS NULL) AND (lease_token IS NULL) AND (ownership_generation IS NULL) AND (consumer_generation IS NULL) AND (lease_until IS NULL)) OR ((lease_machine_id IS NOT NULL) AND (lease_token IS NOT NULL) AND (ownership_generation IS NOT NULL) AND (consumer_generation IS NOT NULL) AND (lease_until IS NOT NULL)))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=cursors_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(sequence >= 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=message_idempotency_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=message_idempotency_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(request_hash ~ ''^[0-9a-f]{64}$''::text)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=conversation_idempotency_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=conversation_idempotency_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(request_hash ~ ''^[0-9a-f]{64}$''::text)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=nonces_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(nonce) >= 1) AND (char_length(nonce) <= 128) AND (octet_length(nonce) <= 512) AND (nonce !~ ''[[:cntrl:]]''::text))') AS exact
    FROM objects
), constraints AS (
    SELECT count(*) FILTER (WHERE con.contype='p')=CASE WHEN $1 >= 51 THEN 15 WHEN $1 >= 40 THEN 12 ELSE 9 END
       AND count(*) FILTER (WHERE con.contype='u')=4
	       AND count(*) FILTER (WHERE con.contype='f')=CASE WHEN $1 >= 51 THEN 15 WHEN $1 >= 40 THEN 12 ELSE 10 END
	       AND count(*) FILTER (WHERE con.contype='c')=CASE WHEN $1 >= 51 THEN 37 WHEN $1 >= 50 THEN 23 WHEN $1 >= 40 THEN 22 ELSE 18 END
	       AND NOT EXISTS (SELECT * FROM expected_keys EXCEPT SELECT * FROM actual_keys)
	       AND NOT EXISTS (SELECT * FROM actual_keys EXCEPT SELECT * FROM expected_keys)
	       AND NOT EXISTS (SELECT * FROM expected_foreign_keys EXCEPT SELECT * FROM actual_foreign_keys)
	       AND NOT EXISTS (SELECT * FROM actual_foreign_keys EXCEPT SELECT * FROM expected_foreign_keys)
	       AND bool_and(check_expressions.exact) AS exact
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND con.convalidated CROSS JOIN check_expressions
), expected_guards(table_oid, trigger_name) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid, 'mail_endpoints_mutation_guard'),
        (conversations_oid, 'mail_conversations_mutation_guard'),
        (memberships_oid, 'mail_memberships_mutation_guard'),
		(roles_oid, 'mail_roles_mutation_guard'),
		(role_memberships_oid, 'mail_role_memberships_mutation_guard'),
		(role_bindings_oid, 'mail_role_bindings_mutation_guard'),
        (messages_oid, 'mail_messages_mutation_guard'),
        (deliveries_oid, 'mail_deliveries_mutation_guard'),
        (cursors_oid, 'mail_recipient_cursors_mutation_guard'),
        (message_idempotency_oid, 'mail_message_idempotency_mutation_guard'),
        (conversation_idempotency_oid, 'mail_conversation_idempotency_mutation_guard'),
        (nonces_oid, 'mail_request_nonces_mutation_guard'),
        (telegram_claims_oid, 'mail_telegram_claims_mutation_guard'),
        (telegram_participants_oid, 'mail_telegram_participants_mutation_guard'),
        (telegram_claim_events_oid, 'mail_telegram_claim_events_mutation_guard')
    ) AS expected(table_oid, trigger_name)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid))
), guards AS (
    SELECT count(*)=CASE WHEN $1 >= 51 THEN 15 WHEN $1 >= 40 THEN 12 ELSE 9 END
       AND bool_and(trg.tgfoid IN (objects.legacy_guard_oid, objects.cutover_guard_oid) AND trg.tgenabled='O' AND NOT trg.tgisinternal
                    AND trg.tgtype=30 AND trg.tgconstraint=0
                    AND NOT trg.tgdeferrable AND NOT trg.tginitdeferred AND trg.tgnargs=0
                    AND trg.tgqual IS NULL AND trg.tgnewtable IS NULL AND trg.tgoldtable IS NULL
                    AND trg.tgattr::text='') AS exact
    FROM objects JOIN expected_guards ON true
    JOIN pg_trigger AS trg
      ON trg.tgrelid=expected_guards.table_oid AND trg.tgname=expected_guards.trigger_name
), function_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prosecdef
       AND proc.prokind='f' AND proc.provolatile='v' AND NOT proc.proretset
       AND proc.prorettype='boolean'::regtype AND proc.pronargs=4
       AND COALESCE(proc.proconfig=ARRAY['search_path=pg_catalog']::text[],false)
       AND md5(regexp_replace(proc.prosrc,'^\s+|\s+$','','g'))='4c348d98b79375c10c6c53728b7368fb') AS exact
    FROM objects JOIN pg_proc AS proc ON proc.oid=consume_oid
), index_safety AS (
    SELECT count(*)=CASE WHEN $1 >= 40 THEN 4 ELSE 3 END AND bool_and(index.indisvalid AND index.indisready AND index.indislive AND NOT index.indisunique
       AND index.indnkeyatts=index.indnatts AND access_method.amname='btree'
       AND pg_get_userbyid(relation.relowner)='punaro_owner'
       AND CASE index.indexrelid
		   WHEN objects.endpoints_index_oid THEN index.indrelid=objects.endpoints_oid AND index.indkey::text='2 3 1'
		   WHEN objects.role_bindings_index_oid THEN index.indrelid=objects.role_bindings_oid AND index.indkey::text='3 2 5 1'
		   WHEN objects.deliveries_index_oid THEN index.indrelid=objects.deliveries_oid AND index.indkey::text='3 10 9 1'
           WHEN objects.nonces_index_oid THEN index.indrelid=objects.nonces_oid AND index.indkey::text='3 1 2'
           ELSE false END) AS exact
    FROM objects JOIN pg_index AS index ON index.indexrelid=ANY(ARRAY[endpoints_index_oid,role_bindings_index_oid,deliveries_index_oid,nonces_index_oid])
    JOIN pg_class AS relation ON relation.oid=index.indexrelid
    JOIN pg_am AS access_method ON access_method.oid=relation.relam
), expected_table_acl(table_oid,privilege_type) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'SELECT'),(endpoints_oid,'INSERT'),(conversations_oid,'SELECT'),(conversations_oid,'INSERT'),
        (memberships_oid,'SELECT'),(memberships_oid,'INSERT'),(memberships_oid,'DELETE'),(messages_oid,'SELECT'),(messages_oid,'INSERT'),
		(roles_oid,'SELECT'),(roles_oid,'INSERT'),(role_memberships_oid,'SELECT'),(role_memberships_oid,'INSERT'),(role_bindings_oid,'SELECT'),(role_bindings_oid,'INSERT'),
        (deliveries_oid,'SELECT'),(deliveries_oid,'INSERT'),(cursors_oid,'SELECT'),(cursors_oid,'INSERT'),
        (message_idempotency_oid,'SELECT'),(message_idempotency_oid,'INSERT'),
        (conversation_idempotency_oid,'SELECT'),(conversation_idempotency_oid,'INSERT'),
        (telegram_claims_oid,'SELECT'),(telegram_claims_oid,'INSERT'),(telegram_participants_oid,'SELECT'),(telegram_participants_oid,'INSERT'),(telegram_claim_events_oid,'SELECT'),(telegram_claim_events_oid,'INSERT')
    ) AS expected(table_oid,privilege_type)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 41 OR NOT (expected.table_oid=memberships_oid AND expected.privilege_type='DELETE'))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid AND expected.table_oid IS DISTINCT FROM telegram_participants_oid AND expected.table_oid IS DISTINCT FROM telegram_claim_events_oid))
), actual_table_acl AS (
    SELECT relation.oid,acl.privilege_type
    FROM objects JOIN pg_class AS relation
      ON relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
    JOIN pg_roles AS grantee ON grantee.oid=acl.grantee AND grantee.rolname='punaro_app'
    WHERE NOT acl.is_grantable
), table_acl AS (
    SELECT NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
       AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl) AS exact
), expected_column_acl(table_oid,column_name,privilege_type) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'machine_id','UPDATE'),(endpoints_oid,'lease_until','UPDATE'),(endpoints_oid,'ownership_generation','UPDATE'),
        (endpoints_oid,'consumer_id','UPDATE'),(endpoints_oid,'consumer_generation','UPDATE'),(endpoints_oid,'consumer_lease_until','UPDATE'),
        (conversations_oid,'next_sequence','UPDATE'),(conversations_oid,'display_name','UPDATE'),(memberships_oid,'capabilities','UPDATE'),
		(role_bindings_oid,'session_endpoint','UPDATE'),(role_bindings_oid,'machine_id','UPDATE'),(role_bindings_oid,'ownership_generation','UPDATE'),(role_bindings_oid,'lease_until','UPDATE'),
        (deliveries_oid,'lease_machine_id','UPDATE'),(deliveries_oid,'lease_token','UPDATE'),(deliveries_oid,'lease_generation','UPDATE'),
        (deliveries_oid,'ownership_generation','UPDATE'),(deliveries_oid,'consumer_generation','UPDATE'),(deliveries_oid,'lease_until','UPDATE'),(deliveries_oid,'acked_at','UPDATE'),
        (cursors_oid,'sequence','UPDATE'),
        (telegram_claims_oid,'status','UPDATE'),(telegram_claims_oid,'completed_at','UPDATE')
    ) AS expected(table_oid,column_name,privilege_type)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 >= 41 OR NOT (expected.table_oid=memberships_oid AND expected.column_name='capabilities'))
      AND ($1 >= 50 OR NOT (expected.table_oid=conversations_oid AND expected.column_name='display_name'))
      AND ($1 >= 51 OR (expected.table_oid IS DISTINCT FROM telegram_claims_oid))
), actual_column_acl AS (
    SELECT attribute.attrelid,attribute.attname,acl.privilege_type
    FROM objects JOIN pg_attribute AS attribute
      ON attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
     AND attribute.attnum>0 AND attribute.attacl IS NOT NULL
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
    JOIN pg_roles AS grantee ON grantee.oid=acl.grantee AND grantee.rolname='punaro_app'
    WHERE NOT acl.is_grantable
), column_acl AS (
    SELECT NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
       AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl) AS exact
)
SELECT endpoints_oid IS NOT NULL AND conversations_oid IS NOT NULL AND memberships_oid IS NOT NULL
	AND ($1 < 40 OR (roles_oid IS NOT NULL AND role_memberships_oid IS NOT NULL AND role_bindings_oid IS NOT NULL))
	AND ($1 < 51 OR (telegram_claims_oid IS NOT NULL AND telegram_participants_oid IS NOT NULL AND telegram_claim_events_oid IS NOT NULL))
   AND messages_oid IS NOT NULL AND deliveries_oid IS NOT NULL AND cursors_oid IS NOT NULL
   AND message_idempotency_oid IS NOT NULL AND conversation_idempotency_oid IS NOT NULL AND nonces_oid IS NOT NULL
	   AND endpoints_index_oid IS NOT NULL AND ($1 < 40 OR role_bindings_index_oid IS NOT NULL) AND deliveries_index_oid IS NOT NULL AND nonces_index_oid IS NOT NULL
   AND consume_oid IS NOT NULL AND (legacy_guard_oid IS NOT NULL OR cutover_guard_oid IS NOT NULL)
	   AND table_ownership.exact AND columns.exact AND defaults.exact AND constraints.exact AND guards.exact AND function_safety.exact AND index_safety.exact
	   AND table_acl.exact AND column_acl.exact
	   AND has_function_privilege('punaro_app',consume_oid,'EXECUTE')
	   AND (SELECT count(*)=2 AND bool_and(NOT acl.is_grantable AND (grantee.rolname='punaro_owner' OR grantee.rolname='punaro_app'))
	        FROM pg_proc AS routine
	        CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS acl
	        LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	        WHERE routine.oid=consume_oid)
	   AND NOT EXISTS (
	       SELECT 1 FROM pg_class AS relation
	       CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
	       LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	       WHERE relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
	         AND (acl.grantee=0 OR grantee.rolname IS NULL OR grantee.rolname NOT IN ('punaro_owner','punaro_app') OR (grantee.rolname='punaro_app' AND acl.is_grantable))
	   )
	   AND NOT EXISTS (
	       SELECT 1 FROM pg_attribute AS attribute
	       CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
	       LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	       WHERE attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid,telegram_claims_oid,telegram_participants_oid,telegram_claim_events_oid])
	         AND attribute.attnum>0 AND attribute.attacl IS NOT NULL
	         AND (acl.grantee=0 OR grantee.rolname IS NULL OR grantee.rolname NOT IN ('punaro_owner','punaro_app') OR (grantee.rolname='punaro_app' AND acl.is_grantable))
	   )
	   AND NOT EXISTS (
	       SELECT 1 FROM pg_proc AS routine
	       CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS acl
	       WHERE routine.oid=consume_oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE'
	   )
	   AND has_table_privilege('punaro_app',endpoints_oid,'SELECT') AND has_table_privilege('punaro_app',endpoints_oid,'INSERT')
	   AND NOT has_table_privilege('punaro_app',endpoints_oid,'UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'machine_id','UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'lease_until','UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'ownership_generation','UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'consumer_id','UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'consumer_generation','UPDATE')
	   AND has_column_privilege('punaro_app',endpoints_oid,'consumer_lease_until','UPDATE')
	   AND NOT has_column_privilege('punaro_app',endpoints_oid,'endpoint','UPDATE')
	   AND has_table_privilege('punaro_app',conversations_oid,'SELECT') AND has_table_privilege('punaro_app',conversations_oid,'INSERT')
	   AND NOT has_table_privilege('punaro_app',conversations_oid,'UPDATE')
	   AND has_column_privilege('punaro_app',conversations_oid,'next_sequence','UPDATE')
	   AND ($1 < 50 OR has_column_privilege('punaro_app',conversations_oid,'display_name','UPDATE'))
	   AND NOT has_column_privilege('punaro_app',conversations_oid,'id','UPDATE')
	   AND NOT has_column_privilege('punaro_app',conversations_oid,'created_at','UPDATE')
   AND has_table_privilege('punaro_app',memberships_oid,'SELECT') AND has_table_privilege('punaro_app',memberships_oid,'INSERT')
   AND has_table_privilege('punaro_app',messages_oid,'SELECT') AND has_table_privilege('punaro_app',messages_oid,'INSERT')
	   AND has_table_privilege('punaro_app',deliveries_oid,'SELECT') AND has_table_privilege('punaro_app',deliveries_oid,'INSERT')
	   AND NOT has_table_privilege('punaro_app',deliveries_oid,'UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'lease_machine_id','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'lease_token','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'lease_generation','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'ownership_generation','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'consumer_generation','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'lease_until','UPDATE')
	   AND has_column_privilege('punaro_app',deliveries_oid,'acked_at','UPDATE')
	   AND NOT has_column_privilege('punaro_app',deliveries_oid,'id','UPDATE')
	   AND NOT has_column_privilege('punaro_app',deliveries_oid,'message_id','UPDATE')
	   AND NOT has_column_privilege('punaro_app',deliveries_oid,'recipient_endpoint','UPDATE')
	   AND has_table_privilege('punaro_app',cursors_oid,'SELECT') AND has_table_privilege('punaro_app',cursors_oid,'INSERT')
	   AND NOT has_table_privilege('punaro_app',cursors_oid,'UPDATE')
	   AND has_column_privilege('punaro_app',cursors_oid,'sequence','UPDATE')
	   AND NOT has_column_privilege('punaro_app',cursors_oid,'recipient_endpoint','UPDATE')
	   AND NOT has_column_privilege('punaro_app',cursors_oid,'conversation_id','UPDATE')
   AND has_table_privilege('punaro_app',message_idempotency_oid,'SELECT') AND has_table_privilege('punaro_app',message_idempotency_oid,'INSERT')
   AND has_table_privilege('punaro_app',conversation_idempotency_oid,'SELECT') AND has_table_privilege('punaro_app',conversation_idempotency_oid,'INSERT')
   AND NOT has_table_privilege('punaro_app',nonces_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',endpoints_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',conversations_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND CASE WHEN $1 >= 41 THEN NOT has_table_privilege('punaro_app',memberships_oid,'UPDATE,TRUNCATE,REFERENCES,TRIGGER') ELSE NOT has_table_privilege('punaro_app',memberships_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') END
   AND NOT has_table_privilege('punaro_app',messages_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',deliveries_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',cursors_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',message_idempotency_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',conversation_idempotency_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND ($1 < 51 OR (
       has_table_privilege('punaro_app',telegram_claims_oid,'SELECT') AND has_table_privilege('punaro_app',telegram_claims_oid,'INSERT')
       AND NOT has_table_privilege('punaro_app',telegram_claims_oid,'UPDATE')
       AND has_column_privilege('punaro_app',telegram_claims_oid,'status','UPDATE')
       AND has_column_privilege('punaro_app',telegram_claims_oid,'completed_at','UPDATE')
       AND NOT has_column_privilege('punaro_app',telegram_claims_oid,'conversation_id','UPDATE')
       AND has_table_privilege('punaro_app',telegram_participants_oid,'SELECT') AND has_table_privilege('punaro_app',telegram_participants_oid,'INSERT')
       AND NOT has_table_privilege('punaro_app',telegram_participants_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND has_table_privilege('punaro_app',telegram_claim_events_oid,'SELECT') AND has_table_privilege('punaro_app',telegram_claim_events_oid,'INSERT')
       AND NOT has_table_privilege('punaro_app',telegram_claim_events_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   ))
FROM objects,table_ownership,columns,defaults,constraints,guards,function_safety,index_safety,table_acl,column_acl`, schemaVersion).Scan(&available)
	return available, err
}
