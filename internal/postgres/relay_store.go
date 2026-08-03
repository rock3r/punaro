package postgres

import (
	"context"
	"database/sql"
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
var _ relay.ControlBackend = (*Database)(nil)

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
	if !relay.ValidMachineID(machineID) || !relay.ValidRole(role) || !relay.ValidEndpoint(endpoint) || ttl <= 0 {
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
	generation, err := postgresEndpointOwnershipLocked(tx, endpoint, machineID, now)
	if err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRowContext(context.Background(), `SELECT machine_id FROM relay.mail_roles WHERE role=$1`, role).Scan(&owner); errors.Is(err, sql.ErrNoRows) || owner != machineID {
		return relay.ErrForbidden
	} else if err != nil {
		return errors.New("durable role ownership is unavailable")
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
	if strings.TrimSpace(input.ConversationID) == "" || !relay.ValidMachineID(input.ActorMachineID) || !relay.ValidEndpoint(input.ActorEndpoint) || !relay.ValidRequestToken(input.IdempotencyKey) || !relay.ValidEndpoint(input.Member.Endpoint) || (input.Operation != relay.ControlUpsertMember && input.Operation != relay.ControlRemoveMember) || (input.Operation == relay.ControlUpsertMember && (input.Member.Capabilities == 0 || input.Member.Capabilities&^(relay.CapSend|relay.CapReceive|relay.CapAdmin) != 0)) || (input.Operation == relay.ControlRemoveMember && input.Member.Capabilities != 0) {
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
	if _, err := postgresEndpointOwnershipLocked(tx, input.ActorEndpoint, input.ActorMachineID, input.Now); err != nil {
		return relay.ControlEvent{}, false, err
	}
	var actorCapabilities relay.Capability
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2 FOR UPDATE`, input.ConversationID, input.ActorEndpoint).Scan(&actorCapabilities)
	if errors.Is(err, sql.ErrNoRows) || actorCapabilities&relay.CapAdmin == 0 {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	if err != nil {
		return relay.ControlEvent{}, false, errors.New("control actor authorization is unavailable")
	}
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
	if input.Operation == relay.ControlUpsertMember {
		// New members must be actively advertised. Ownership need not match the
		// actor, while remove deliberately permits pruning a detached endpoint.
		var until time.Time
		if err := tx.QueryRowContext(context.Background(), `SELECT lease_until FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE`, input.Member.Endpoint).Scan(&until); err != nil || !until.After(input.Now) {
			return relay.ControlEvent{}, false, relay.ErrForbidden
		}
	}
	var previous relay.Capability
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2 FOR UPDATE`, input.ConversationID, input.Member.Endpoint).Scan(&previous)
	if input.Operation == relay.ControlRemoveMember && errors.Is(err, sql.ErrNoRows) {
		return relay.ControlEvent{}, false, relay.ErrForbidden
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return relay.ControlEvent{}, false, errors.New("control target state is unavailable")
	}
	if (input.Operation == relay.ControlRemoveMember || (err == nil && previous&relay.CapAdmin != 0 && input.Member.Capabilities&relay.CapAdmin == 0)) && previous&relay.CapAdmin != 0 {
		var remaining int
		if err := tx.QueryRowContext(context.Background(), `SELECT count(*) FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND (capabilities & $2)<>0 AND endpoint<>$3`, input.ConversationID, relay.CapAdmin, input.Member.Endpoint).Scan(&remaining); err != nil {
			return relay.ControlEvent{}, false, errors.New("remaining admin state is unavailable")
		}
		if remaining == 0 {
			return relay.ControlEvent{}, false, relay.ErrConflict
		}
	}
	if input.Operation == relay.ControlUpsertMember {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities) VALUES($1::uuid,$2,$3) ON CONFLICT(conversation_id,endpoint) DO UPDATE SET capabilities=excluded.capabilities`, input.ConversationID, input.Member.Endpoint, input.Member.Capabilities); err != nil {
			return relay.ControlEvent{}, false, relayDatabaseError(err, "upsert conversation member")
		}
	} else if _, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, input.ConversationID, input.Member.Endpoint); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "remove conversation member")
	}
	event := relay.ControlEvent{ID: uuid.NewString(), ConversationID: input.ConversationID, ActorEndpoint: input.ActorEndpoint, Operation: input.Operation, Member: input.Member, CreatedAt: input.Now.UTC().Truncate(time.Microsecond)}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_controls(id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7)`, event.ID, event.ConversationID, event.ActorEndpoint, event.Operation, event.Member.Endpoint, event.Member.Capabilities, event.CreatedAt); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "record control audit")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversation_control_idempotency(machine_id,key,request_hash,control_id,created_at) VALUES($1,$2,$3,$4::uuid,$5)`, input.ActorMachineID, input.IdempotencyKey, requestHash, event.ID, input.Now.UTC()); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "record control idempotency")
	}
	if err := tx.Commit(); err != nil {
		return relay.ControlEvent{}, false, relayDatabaseError(err, "commit control")
	}
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
	var capabilities relay.Capability
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND endpoint=$2`, conversationID, actorEndpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&relay.CapAdmin == 0 {
		return nil, relay.ErrForbidden
	}
	if err != nil {
		return nil, errors.New("control audit authorization is unavailable")
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

func postgresControlEventByID(tx *sql.Tx, id string) (relay.ControlEvent, error) {
	var event relay.ControlEvent
	if err := tx.QueryRowContext(context.Background(), `SELECT id::text,conversation_id::text,actor_endpoint,operation,member_endpoint,member_capabilities,created_at FROM relay.mail_conversation_controls WHERE id=$1::uuid`, id).Scan(&event.ID, &event.ConversationID, &event.ActorEndpoint, &event.Operation, &event.Member.Endpoint, &event.Member.Capabilities, &event.CreatedAt); err != nil {
		return relay.ControlEvent{}, errors.New("control retry event is unavailable")
	}
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
		if member.Capabilities == 0 || member.Capabilities & ^(relay.CapSend|relay.CapReceive|relay.CapAdmin) != 0 {
			return relay.Conversation{}, errors.New("invalid conversation member")
		}
		switch {
		case member.Endpoint != "" && member.Role == "" && member.RoleMachineID == "":
			if !relay.ValidEndpoint(member.Endpoint) {
				return relay.Conversation{}, errors.New("invalid conversation member")
			}
			if _, duplicate := seen[member.Endpoint]; duplicate {
				return relay.Conversation{}, errors.New("duplicate conversation member")
			}
			seen[member.Endpoint] = struct{}{}
			if member.Endpoint == input.CreatorEndpoint && member.Capabilities&(relay.CapSend|relay.CapReceive|relay.CapAdmin) == relay.CapSend|relay.CapReceive|relay.CapAdmin {
				creatorAdmin = true
			}
		case member.Endpoint == "" && relay.ValidRole(member.Role) && relay.ValidMachineID(member.RoleMachineID):
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
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.Conversation{}, errors.New("conversation transaction cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text, 579001230608))`, input.MachineID, input.IdempotencyKey); err != nil {
		return relay.Conversation{}, errors.New("conversation retry lock is unavailable")
	}
	hash := relay.CreateConversationRequestHash(input.CreatorEndpoint, input.Members, input.ProjectID)
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
		if err := tx.Commit(); err != nil {
			return relay.Conversation{}, errors.New("conversation retry cannot commit")
		}
		return relay.Conversation{ID: existingID}, nil
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
	conversation := relay.Conversation{ID: uuid.NewString()}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_conversations(id,created_at) VALUES($1::uuid,$2)`, conversation.ID, input.Now.UTC()); err != nil {
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
	return tx.Commit()
}

// AppendMessage transactionally appends one immutable PostgreSQL relay message.
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
	message := relay.Message{ID: uuid.NewString(), ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body, CreatedAt: input.Now.UTC().Truncate(time.Millisecond)}
	if err := tx.QueryRowContext(context.Background(), `UPDATE relay.mail_conversations SET next_sequence=next_sequence+1 WHERE id=$1::uuid RETURNING next_sequence`, input.ConversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return relay.Message{}, false, relay.ErrForbidden
	} else if err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "allocate message sequence")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,body,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, message.Body, message.CreatedAt); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "append message")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint)
		SELECT $1::uuid,endpoint FROM relay.mail_memberships WHERE conversation_id=$2::uuid AND (capabilities & $3) <> 0 AND endpoint<>$4`, message.ID, message.ConversationID, relay.CapReceive, message.FromEndpoint); err != nil {
		return relay.Message{}, false, relayDatabaseError(err, "create recipient deliveries")
	}
	if rolesAvailable {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint)
		SELECT $1::uuid,chr(30)||'role:'||membership.role
		FROM relay.mail_role_memberships AS membership
		WHERE membership.conversation_id=$2::uuid AND (membership.capabilities & $3) <> 0`, message.ID, message.ConversationID, relay.CapReceive); err != nil {
			return relay.Message{}, false, relayDatabaseError(err, "create durable role deliveries")
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
	return message, false, nil
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
	query := `SELECT delivery.id::text,delivery.lease_machine_id,delivery.lease_token::text,delivery.lease_generation,delivery.ownership_generation,delivery.consumer_generation,delivery.lease_until,
		message.id::text,message.conversation_id::text,message.sequence,message.from_endpoint,message.body,message.created_at
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.recipient_endpoint IN (SELECT value FROM jsonb_array_elements_text($1::jsonb)) AND delivery.acked_at IS NULL
		  AND (delivery.lease_until IS NULL OR delivery.lease_until<=$2 OR delivery.ownership_generation IS NULL OR delivery.ownership_generation<>$3 OR delivery.consumer_generation IS NULL OR delivery.consumer_generation<>$4 OR delivery.lease_machine_id=$5)`
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
		row.delivery.RecipientEndpoint = endpoint
		if err := rows.Scan(&row.delivery.ID, &row.leaseMachine, &row.leaseToken, &row.delivery.LeaseGeneration, &row.leaseOwnership, &row.leaseConsumer, &row.leaseUntil, &row.delivery.Message.ID, &row.delivery.Message.ConversationID, &row.delivery.Message.Sequence, &row.delivery.Message.FromEndpoint, &row.delivery.Message.Body, &row.delivery.Message.CreatedAt); err != nil {
			_ = rows.Close()
			return relay.DeliveryLeasePage{}, errors.New("pending delivery is malformed")
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
	for _, row := range pending {
		delivery := row.delivery
		if row.leaseMachine.Valid && row.leaseMachine.String == machineID && row.leaseToken.Valid && row.leaseOwnership.Valid && row.leaseOwnership.Int64 == ownershipGeneration && row.leaseConsumer.Valid && row.leaseConsumer.Int64 == consumerGeneration && row.leaseUntil.Valid && row.leaseUntil.Time.After(now) {
			delivery.LeaseToken = row.leaseToken.String
			delivery.LeaseUntil = row.leaseUntil.Time.UTC()
		} else {
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
	if err := postgresAdvanceRecipientCursor(tx, recipient, conversationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return relayDatabaseError(err, "commit delivery acknowledgement")
	}
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
	query := `SELECT DISTINCT id FROM (
		SELECT conversation.id::text AS id FROM relay.mail_conversations AS conversation
		JOIN relay.mail_memberships AS membership ON membership.conversation_id=conversation.id
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=membership.endpoint
		WHERE endpoint.machine_id=$1 AND endpoint.lease_until>$2
	`
	if rolesAvailable {
		query += `UNION
		SELECT conversation.id::text AS id FROM relay.mail_conversations AS conversation
		JOIN relay.mail_role_memberships AS membership ON membership.conversation_id=conversation.id
		JOIN relay.mail_role_bindings AS binding ON binding.role=membership.role
		JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
		WHERE binding.machine_id=$1 AND binding.lease_until>$2 AND endpoint.machine_id=$1
		  AND endpoint.lease_until>$2 AND endpoint.ownership_generation=binding.ownership_generation
	`
	}
	query += `) AS visible ORDER BY id`
	rows, err := d.relayPool().QueryContext(ctx, query, machineID, now.UTC())
	if err != nil {
		return nil, errors.New("machine conversations are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var conversations []relay.Conversation
	for rows.Next() {
		var conversation relay.Conversation
		if err := rows.Scan(&conversation.ID); err != nil {
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
	if err := tx.QueryRowContext(context.Background(), `SELECT id::text,conversation_id::text,sequence,from_endpoint,body,created_at FROM relay.mail_messages WHERE id=$1::uuid`, messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &message.Body, &message.CreatedAt); err != nil {
		return relay.Message{}, errors.New("idempotent message is unavailable")
	}
	message.CreatedAt = message.CreatedAt.UTC()
	return message, nil
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
	if capabilities < 0 || capabilities > int64(relay.CapSend|relay.CapReceive|relay.CapAdmin) {
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
		   to_regclass('relay.mail_endpoints_machine') AS endpoints_index_oid,
		   to_regclass('relay.mail_role_bindings_session') AS role_bindings_index_oid,
		   to_regclass('relay.mail_deliveries_pending') AS deliveries_index_oid,
           to_regclass('relay.mail_request_nonces_expiry') AS nonces_index_oid,
           to_regprocedure('relay.consume_mail_request_nonce(text,text,timestamp with time zone,timestamp with time zone)') AS consume_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS legacy_guard_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS cutover_guard_oid
), table_ownership AS (
    SELECT count(*)=CASE WHEN $1 >= 40 THEN 12 ELSE 9 END AND bool_and(pg_get_userbyid(relation.relowner)='punaro_owner' AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS relation ON relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
), expected_columns(table_oid,column_name,type_oid,required) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'endpoint','text'::regtype,true),(endpoints_oid,'machine_id','text'::regtype,true),
        (endpoints_oid,'lease_until','timestamptz'::regtype,true),(endpoints_oid,'ownership_generation','bigint'::regtype,true),
        (endpoints_oid,'consumer_id','text'::regtype,false),(endpoints_oid,'consumer_generation','bigint'::regtype,true),
        (endpoints_oid,'consumer_lease_until','timestamptz'::regtype,false),
        (conversations_oid,'id','uuid'::regtype,true),(conversations_oid,'next_sequence','bigint'::regtype,true),(conversations_oid,'created_at','timestamptz'::regtype,true),
        (memberships_oid,'conversation_id','uuid'::regtype,true),(memberships_oid,'endpoint','text'::regtype,true),(memberships_oid,'capabilities','smallint'::regtype,true),
		(roles_oid,'role','text'::regtype,true),(roles_oid,'machine_id','text'::regtype,true),
		(role_memberships_oid,'conversation_id','uuid'::regtype,true),(role_memberships_oid,'role','text'::regtype,true),(role_memberships_oid,'capabilities','smallint'::regtype,true),
		(role_bindings_oid,'role','text'::regtype,true),(role_bindings_oid,'session_endpoint','text'::regtype,true),(role_bindings_oid,'machine_id','text'::regtype,true),(role_bindings_oid,'ownership_generation','bigint'::regtype,true),(role_bindings_oid,'lease_until','timestamptz'::regtype,true),
        (messages_oid,'id','uuid'::regtype,true),(messages_oid,'conversation_id','uuid'::regtype,true),(messages_oid,'sequence','bigint'::regtype,true),
        (messages_oid,'from_endpoint','text'::regtype,true),(messages_oid,'body','text'::regtype,true),(messages_oid,'created_at','timestamptz'::regtype,true),
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
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), actual_columns AS (
    SELECT attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull
    FROM objects JOIN pg_attribute AS attribute
      ON attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
     AND attribute.attnum>0 AND NOT attribute.attisdropped
), columns AS (
    SELECT NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
       AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
       AND (SELECT count(*)=2 FROM pg_attribute WHERE attrelid=ANY(ARRAY[message_idempotency_oid,conversation_idempotency_oid]) AND attname='request_hash' AND atttypid='bpchar'::regtype AND atttypmod=68)
       AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid]) AND attnum>0 AND NOT attisdropped AND atttypid<>'bpchar'::regtype AND atttypmod<>-1) AS exact
    FROM objects
), expected_defaults(table_oid,column_name,expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,'ownership_generation','1'),(endpoints_oid,'consumer_generation','0'),
        (conversations_oid,'id','gen_random_uuid()'),(conversations_oid,'next_sequence','0'),(conversations_oid,'created_at','statement_timestamp()'),
        (messages_oid,'id','gen_random_uuid()'),(deliveries_oid,'id','gen_random_uuid()'),(deliveries_oid,'lease_generation','0'),
        (cursors_oid,'sequence','0')
    ) AS expected(table_oid,column_name,expression)
), actual_defaults AS (
    SELECT default_value.adrelid,attribute.attname,pg_get_expr(default_value.adbin,default_value.adrelid)
    FROM objects JOIN pg_attrdef AS default_value
      ON default_value.adrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
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
        (messages_oid,'u'::"char",ARRAY[2,3]::smallint[]),(deliveries_oid,'u'::"char",ARRAY[2,3]::smallint[]),
        (message_idempotency_oid,'u'::"char",ARRAY[4]::smallint[]),(conversation_idempotency_oid,'u'::"char",ARRAY[4]::smallint[])
    ) AS expected(table_oid,constraint_type,column_keys)
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), actual_keys AS (
    SELECT con.conrelid,con.contype,con.conkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
     AND con.contype IN ('p','u') AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
), expected_foreign_keys(table_oid,column_keys,foreign_table_oid,foreign_column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (memberships_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(memberships_oid,ARRAY[2]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
        (messages_oid,ARRAY[2]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(messages_oid,ARRAY[4]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(role_memberships_oid,ARRAY[1]::smallint[],conversations_oid,ARRAY[1]::smallint[]),(role_memberships_oid,ARRAY[2]::smallint[],roles_oid,ARRAY[1]::smallint[]),
		(role_bindings_oid,ARRAY[1]::smallint[],roles_oid,ARRAY[1]::smallint[]),(role_bindings_oid,ARRAY[2]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(deliveries_oid,ARRAY[2]::smallint[],messages_oid,ARRAY[1]::smallint[]),(deliveries_oid,ARRAY[3]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),
		(cursors_oid,ARRAY[1]::smallint[],endpoints_oid,ARRAY[1]::smallint[]),(cursors_oid,ARRAY[2]::smallint[],conversations_oid,ARRAY[1]::smallint[]),
        (message_idempotency_oid,ARRAY[4]::smallint[],messages_oid,ARRAY[1]::smallint[]),(conversation_idempotency_oid,ARRAY[4]::smallint[],conversations_oid,ARRAY[1]::smallint[])
    ) AS expected(table_oid,column_keys,foreign_table_oid,foreign_column_keys)
    WHERE ($1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid))
      AND ($1 < 40 OR (NOT (expected.table_oid=deliveries_oid AND expected.column_keys=ARRAY[3]::smallint[])
                         AND NOT (expected.table_oid=cursors_oid AND expected.column_keys=ARRAY[1]::smallint[])))
), actual_foreign_keys AS (
    SELECT con.conrelid,con.conkey,con.confrelid,con.confkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[memberships_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid])
     AND con.contype='f' AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
     AND con.confupdtype='a' AND con.confdeltype='a' AND con.confmatchtype='s'
), expected_check_keys(table_oid,column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (endpoints_oid,ARRAY[1]::smallint[]),(endpoints_oid,ARRAY[2]::smallint[]),(endpoints_oid,ARRAY[4]::smallint[]),
        (endpoints_oid,ARRAY[5]::smallint[]),(endpoints_oid,ARRAY[6]::smallint[]),(endpoints_oid,ARRAY[5,7]::smallint[]),
        (conversations_oid,ARRAY[2]::smallint[]),(memberships_oid,ARRAY[3]::smallint[]),
		(roles_oid,ARRAY[1]::smallint[]),(roles_oid,ARRAY[2]::smallint[]),(role_memberships_oid,ARRAY[3]::smallint[]),(role_bindings_oid,ARRAY[4]::smallint[]),
        (messages_oid,ARRAY[3]::smallint[]),(messages_oid,ARRAY[5]::smallint[]),
        (deliveries_oid,ARRAY[6]::smallint[]),(deliveries_oid,ARRAY[4,5,7,8,9]::smallint[]),
        (cursors_oid,ARRAY[3]::smallint[]),(message_idempotency_oid,ARRAY[2]::smallint[]),(message_idempotency_oid,ARRAY[3]::smallint[]),
        (conversation_idempotency_oid,ARRAY[2]::smallint[]),(conversation_idempotency_oid,ARRAY[3]::smallint[]),(nonces_oid,ARRAY[2]::smallint[])
    ) AS expected(table_oid,column_keys)
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), actual_check_keys AS (
    SELECT con.conrelid,con.conkey
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
     AND con.contype='c' AND con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
), check_expressions AS (
    SELECT NOT EXISTS (SELECT * FROM expected_check_keys EXCEPT ALL SELECT * FROM actual_check_keys)
       AND NOT EXISTS (SELECT * FROM actual_check_keys EXCEPT ALL SELECT * FROM expected_check_keys)
       AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid]) AND contype='c' AND (NOT convalidated OR condeferrable OR condeferred))
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[1]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(endpoint) >= 1) AND (char_length(endpoint) <= 512) AND (octet_length(endpoint) <= 2048) AND (endpoint !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(machine_id) >= 1) AND (char_length(machine_id) <= 128) AND (octet_length(machine_id) <= 512) AND (machine_id !~ ''[[:cntrl:]]''::text))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='(ownership_generation > 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[6]::smallint[] AND pg_get_expr(conbin,conrelid)='(consumer_generation >= 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='((consumer_id IS NULL) OR ((char_length(consumer_id) >= 1) AND (char_length(consumer_id) <= 128) AND (octet_length(consumer_id) <= 512) AND (consumer_id !~ ''[[:cntrl:]]''::text)))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=endpoints_oid AND contype='c' AND conkey @> ARRAY[5,7]::smallint[] AND conkey <@ ARRAY[5,7]::smallint[] AND pg_get_expr(conbin,conrelid)='((consumer_id IS NULL) = (consumer_lease_until IS NULL))')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=conversations_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='(next_sequence >= 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=memberships_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='((capabilities >= 1) AND (capabilities <= 7))')
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=roles_oid AND contype='c' AND conkey=ARRAY[1]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(role) >= 1) AND (char_length(role) <= 512) AND (octet_length(role) <= 2048) AND (role !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=roles_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(machine_id) >= 1) AND (char_length(machine_id) <= 128) AND (octet_length(machine_id) <= 512) AND (machine_id !~ ''[[:cntrl:]]''::text))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=role_memberships_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='((capabilities >= 1) AND (capabilities <= 7))'))
	   AND ($1 < 40 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=role_bindings_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND pg_get_expr(conbin,conrelid)='(ownership_generation > 0)'))
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(sequence > 0)')
       AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=messages_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND pg_get_expr(conbin,conrelid)='(octet_length(body) <= 32768)')
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
    SELECT count(*) FILTER (WHERE con.contype='p')=CASE WHEN $1 >= 40 THEN 12 ELSE 9 END
       AND count(*) FILTER (WHERE con.contype='u')=4
	       AND count(*) FILTER (WHERE con.contype='f')=CASE WHEN $1 >= 40 THEN 12 ELSE 10 END
	       AND count(*) FILTER (WHERE con.contype='c')=CASE WHEN $1 >= 40 THEN 22 ELSE 18 END
	       AND NOT EXISTS (SELECT * FROM expected_keys EXCEPT SELECT * FROM actual_keys)
	       AND NOT EXISTS (SELECT * FROM actual_keys EXCEPT SELECT * FROM expected_keys)
	       AND NOT EXISTS (SELECT * FROM expected_foreign_keys EXCEPT SELECT * FROM actual_foreign_keys)
	       AND NOT EXISTS (SELECT * FROM actual_foreign_keys EXCEPT SELECT * FROM expected_foreign_keys)
	       AND bool_and(check_expressions.exact) AS exact
    FROM objects JOIN pg_constraint AS con
      ON con.conrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
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
        (nonces_oid, 'mail_request_nonces_mutation_guard')
    ) AS expected(table_oid, trigger_name)
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), guards AS (
    SELECT count(*)=CASE WHEN $1 >= 40 THEN 12 ELSE 9 END
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
        (memberships_oid,'SELECT'),(memberships_oid,'INSERT'),(messages_oid,'SELECT'),(messages_oid,'INSERT'),
		(roles_oid,'SELECT'),(roles_oid,'INSERT'),(role_memberships_oid,'SELECT'),(role_memberships_oid,'INSERT'),(role_bindings_oid,'SELECT'),(role_bindings_oid,'INSERT'),
        (deliveries_oid,'SELECT'),(deliveries_oid,'INSERT'),(cursors_oid,'SELECT'),(cursors_oid,'INSERT'),
        (message_idempotency_oid,'SELECT'),(message_idempotency_oid,'INSERT'),
        (conversation_idempotency_oid,'SELECT'),(conversation_idempotency_oid,'INSERT')
    ) AS expected(table_oid,privilege_type)
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), actual_table_acl AS (
    SELECT relation.oid,acl.privilege_type
    FROM objects JOIN pg_class AS relation
      ON relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
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
        (conversations_oid,'next_sequence','UPDATE'),
		(role_bindings_oid,'session_endpoint','UPDATE'),(role_bindings_oid,'machine_id','UPDATE'),(role_bindings_oid,'ownership_generation','UPDATE'),(role_bindings_oid,'lease_until','UPDATE'),
        (deliveries_oid,'lease_machine_id','UPDATE'),(deliveries_oid,'lease_token','UPDATE'),(deliveries_oid,'lease_generation','UPDATE'),
        (deliveries_oid,'ownership_generation','UPDATE'),(deliveries_oid,'consumer_generation','UPDATE'),(deliveries_oid,'lease_until','UPDATE'),(deliveries_oid,'acked_at','UPDATE'),
        (cursors_oid,'sequence','UPDATE')
    ) AS expected(table_oid,column_name,privilege_type)
    WHERE $1 >= 40 OR (expected.table_oid IS DISTINCT FROM roles_oid AND expected.table_oid IS DISTINCT FROM role_memberships_oid AND expected.table_oid IS DISTINCT FROM role_bindings_oid)
), actual_column_acl AS (
    SELECT attribute.attrelid,attribute.attname,acl.privilege_type
    FROM objects JOIN pg_attribute AS attribute
      ON attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
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
	       WHERE relation.oid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
	         AND (acl.grantee=0 OR grantee.rolname IS NULL OR grantee.rolname NOT IN ('punaro_owner','punaro_app') OR (grantee.rolname='punaro_app' AND acl.is_grantable))
	   )
	   AND NOT EXISTS (
	       SELECT 1 FROM pg_attribute AS attribute
	       CROSS JOIN LATERAL aclexplode(attribute.attacl) AS acl
	       LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	       WHERE attribute.attrelid=ANY(ARRAY[endpoints_oid,conversations_oid,memberships_oid,roles_oid,role_memberships_oid,role_bindings_oid,messages_oid,deliveries_oid,cursors_oid,message_idempotency_oid,conversation_idempotency_oid,nonces_oid])
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
   AND NOT has_table_privilege('punaro_app',memberships_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',messages_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',deliveries_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',cursors_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',message_idempotency_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_table_privilege('punaro_app',conversation_idempotency_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
FROM objects,table_ownership,columns,defaults,constraints,guards,function_safety,index_safety,table_acl,column_acl`, schemaVersion).Scan(&available)
	return available, err
}
