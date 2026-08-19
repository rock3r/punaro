package postgres

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestRelayInspectSQLComparesMessageMetadataCheckKeysByEquality(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if strings.Contains(src, "column_keys=ANY(ARRAY[ARRAY[") {
		t.Fatal("relay inspect SQL compares smallint[] to smallint via ANY")
	}
	want := "expected.column_keys=ARRAY[7]::smallint[] OR expected.column_keys=ARRAY[8]::smallint[] OR expected.column_keys=ARRAY[9]::smallint[] OR expected.column_keys=ARRAY[10]::smallint[]"
	if !strings.Contains(src, want) {
		t.Fatal("relay inspect SQL missing equality filters for message metadata check keys")
	}
}

func TestPostgresLeaseMessageColumnsIncludeMetadataWhenPresent(t *testing.T) {
	if got := postgresLeaseMessageColumns(false); strings.Contains(got, "from_participant") || strings.Contains(got, "telegram_thread_id") {
		t.Fatalf("pre-046 lease columns included metadata: %s", got)
	}
	got := postgresLeaseMessageColumns(true)
	last := -1
	for _, column := range []string{"from_participant", "in_reply_to_message_id", "in_reply_to_endpoint", "telegram_thread_id"} {
		idx := strings.Index(got, "message."+column)
		if idx < 0 || idx < last {
			t.Fatalf("lease columns missing or out of order %s: %s", column, got)
		}
		last = idx
	}
}

func TestPostgresConversationEndpointLockOrder(t *testing.T) {
	endpoints := map[string]struct{}{
		"agent/z": {},
		"agent/a": {},
		"agent/m": {},
	}
	want := []string{"agent/a", "agent/m", "agent/z"}
	if got := postgresSortedEndpoints(endpoints); !slices.Equal(got, want) {
		t.Fatalf("endpoint lock order=%v, want %v", got, want)
	}
}

func TestPostgresConversationSQLOmitsDisplayNameUntilColumnExists(t *testing.T) {
	if got := postgresConversationInsertSQL(false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 insert referenced display_name: %s", got)
	}
	if got := postgresConversationByIDSQL(false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 by-id referenced display_name: %s", got)
	}
	if got := postgresConversationListSQL(false, false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 list referenced display_name: %s", got)
	}
	if got := postgresConversationInsertSQL(true); !strings.Contains(got, "display_name") {
		t.Fatalf("v45 insert omitted display_name: %s", got)
	}
	if got := postgresConversationListSQL(true, true); !strings.Contains(got, "display_name") {
		t.Fatalf("v45 list omitted display_name: %s", got)
	}
}

func TestPostgresExclusiveConversationPredicateRequiresDisplayName(t *testing.T) {
	if got := postgresExclusiveConversationPredicate("conversation", false, false); got != "FALSE" {
		t.Fatalf("pre-045 exclusive predicate=%s", got)
	}
	got := postgresExclusiveConversationPredicate("conversation", true, false)
	if !strings.Contains(got, "conversation.display_name") || strings.Contains(got, "UNIQUE") {
		t.Fatalf("exclusive predicate=%s", got)
	}
	claimed := postgresExclusiveConversationPredicate("conversation", true, true)
	if !strings.Contains(claimed, "mail_telegram_claims") || !strings.Contains(claimed, "conversation.display_name") {
		t.Fatalf("claimed exclusive predicate=%s", claimed)
	}
}

func TestPostgresPendingTelegramClaimsSQLUsesNullableUUIDCursor(t *testing.T) {
	query := postgresPendingTelegramClaimsSQL()
	compact := strings.ReplaceAll(query, " ", "")
	if strings.Contains(query, "$2 = ''") || strings.Contains(compact, "$2=''") {
		t.Fatalf("pending claims SQL overloads $2 as text: %s", query)
	}
	if !strings.Contains(query, "$2::uuid IS NULL") || !strings.Contains(query, "cursor.conversation_id = $2::uuid") {
		t.Fatalf("pending claims SQL missing nullable uuid cursor: %s", query)
	}
}

func TestPostgresBindRoleTakesDurableRoleAdvisoryLock(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func (d *Database) BindRoleToSession")
	if start < 0 {
		t.Fatal("BindRoleToSession missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("BindRoleToSession unbounded")
	}
	fn := rest[:end+1]
	lockIdx := strings.Index(fn, "postgresDurableRoleLockSQL()")
	occupancyIdx := strings.Index(fn, "postgresLockOccupancy")
	if lockIdx < 0 || occupancyIdx < 0 || lockIdx > occupancyIdx {
		t.Fatal("BindRoleToSession must take the durable-role lock before occupancy")
	}
	if !strings.Contains(postgresDurableRoleLockSQL(), "durable-role") {
		t.Fatal("durable-role lock SQL missing role namespace")
	}
}

func TestPostgresBindRoleLocksAllRoleConversationsNotOnlyExclusive(t *testing.T) {
	query := postgresConversationIDsForRoleSQL()
	compact := strings.ReplaceAll(query, " ", "")
	if strings.Contains(query, "display_name") || strings.Contains(query, "mail_telegram_claims") || strings.Contains(compact, "ISNOTNULL") {
		t.Fatalf("bind occupancy locks filtered exclusive rooms: %s", query)
	}
	if !strings.Contains(query, "mail_role_memberships") || !strings.Contains(query, "conversation_id") {
		t.Fatalf("bind occupancy locks missing role memberships: %s", query)
	}
}

func TestPostgresClaimOccupancyLocksConversationBeforeOccupants(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func postgresRejectExclusiveClaimOccupancy")
	if start < 0 {
		t.Fatal("claim occupancy helper missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("claim occupancy helper unbounded")
	}
	fn := rest[:end+1]
	lockIdx := strings.Index(fn, "postgresLockOccupancy(tx, []string{conversationID}, nil)")
	occupantsIdx := strings.Index(fn, "postgresConversationOccupants")
	if lockIdx < 0 || occupantsIdx < 0 || lockIdx > occupantsIdx {
		t.Fatal("claim occupancy must lock the conversation before reading occupants")
	}
}

func TestRelayInspectSQLIncludesDisplayNameIdempotencyAfter53(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		"to_regclass('relay.mail_conversation_display_name_idempotency') AS display_name_idempotency_oid",
		"CASE WHEN $1 >= 56 THEN 17 WHEN $1 >= 53 THEN 16 WHEN $1 >= 51 THEN 15 WHEN $1 >= 40 THEN 12 ELSE 9 END",
		"CASE WHEN $1 >= 56 THEN 5 WHEN $1 >= 53 THEN 4 WHEN $1 >= 51 THEN 3 ELSE 2 END",
		"count(*) FILTER (WHERE con.contype='c')=CASE WHEN $1 >= 56 THEN 41 WHEN $1 >= 53 THEN 39 WHEN $1 >= 51 THEN 37 WHEN $1 >= 50 THEN 23 WHEN $1 >= 40 THEN 22 ELSE 18 END",
		"(display_name_idempotency_oid, 'mail_conversation_display_name_idempotency_mutation_guard')",
		"$1 >= 53 OR expected.table_oid IS DISTINCT FROM display_name_idempotency_oid",
		"$1 < 53 OR display_name_idempotency_oid IS NOT NULL",
		"$1 < 53 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=display_name_idempotency_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))')",
		"$1 < 53 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=display_name_idempotency_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND pg_get_expr(conbin,conrelid)='(request_hash ~ ''^[0-9a-f]{64}$''::text)')",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("relay inspect SQL missing display-name idempotency check: %s", want)
		}
	}
}

func TestPostgresReserveTelegramClaimSerializesByMachineKey(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func (d *Database) ReserveTelegramClaim(")
	if start < 0 {
		t.Fatal("ReserveTelegramClaim missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("ReserveTelegramClaim unbounded")
	}
	fn := rest[:end+1]
	lock := strings.Index(fn, "telegram-claim-retry")
	lookup := strings.Index(fn, "postgresLookupTelegramClaimIdempotency")
	if lock < 0 || lookup < 0 || lock > lookup {
		t.Fatal("ReserveTelegramClaim must take the (machine, key) advisory lock before the mapping lookup")
	}
	if !strings.Contains(fn, "ON CONFLICT DO NOTHING") {
		t.Fatal("claim insert must ignore unique conflicts so a reused machine/key cannot abort the transaction")
	}
	if strings.Contains(fn, "ON CONFLICT (conversation_id) DO NOTHING") {
		t.Fatal("conversation_id-only ON CONFLICT still aborts on unique (requested_by_machine, idempotency_key)")
	}
}

func TestPostgresBindTelegramClaimIdempotencyUsesOnConflictDoNothing(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func postgresBindTelegramClaimIdempotency(")
	if start < 0 {
		t.Fatal("postgresBindTelegramClaimIdempotency missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("postgresBindTelegramClaimIdempotency unbounded")
	}
	fn := rest[:end+1]
	if !strings.Contains(fn, "ON CONFLICT (machine_id, key) DO NOTHING") && !strings.Contains(fn, "ON CONFLICT (machine_id,key) DO NOTHING") {
		t.Fatal("postgres bind must insert with ON CONFLICT DO NOTHING so a racing unique key does not abort the transaction")
	}
	if strings.Contains(fn, `"23505"`) {
		t.Fatal("postgres bind must not recover a unique violation from an aborted transaction")
	}
}

func TestRelayInspectSQLIncludesTelegramClaimIdempotencyAfter56(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		"to_regclass('relay.mail_telegram_claim_idempotency') AS claim_idempotency_oid",
		"(claim_idempotency_oid, 'mail_telegram_claim_idempotency_mutation_guard')",
		"$1 >= 56 OR expected.table_oid IS DISTINCT FROM claim_idempotency_oid",
		"$1 < 56 OR claim_idempotency_oid IS NOT NULL",
		"$1 < 56 OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=claim_idempotency_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND pg_get_expr(conbin,conrelid)='((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))')",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("relay inspect SQL missing telegram claim idempotency check: %s", want)
		}
	}
}

func TestRelayInspectSQLIncludesTelegramClaimMachineKeyAfter55(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	for _, want := range []string{
		`(telegram_claims_oid,'u'::"char",ARRAY[3,5]::smallint[])`,
		`count(*) FILTER (WHERE con.contype='u')=CASE WHEN $1 >= 55 THEN 5 ELSE 4 END`,
		`$1 >= 55 OR expected.table_oid IS DISTINCT FROM telegram_claims_oid OR expected.constraint_type IS DISTINCT FROM 'u'::"char"`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("relay inspect SQL missing telegram claim machine-key unique: %s", want)
		}
	}
}

func TestPostgresOccupancySQLUsesNullableUUIDExclude(t *testing.T) {
	if postgresNullableUUID("") != nil {
		t.Fatal("empty exclude must bind NULL, not text")
	}
	if got := postgresNullableUUID("019f7f07-4b88-7c12-a394-b663274a6555"); got != "019f7f07-4b88-7c12-a394-b663274a6555" {
		t.Fatalf("uuid exclude=%v", got)
	}
	for _, rolesAvailable := range []bool{false, true} {
		query := postgresSessionOccupiesOtherExclusiveConversationSQL(true, rolesAvailable, true)
		compact := strings.ReplaceAll(query, " ", "")
		if strings.Contains(query, "$2 = ''") || strings.Contains(compact, "$2=''") {
			t.Fatalf("occupancy SQL overloads $2 as text: %s", query)
		}
		if !strings.Contains(query, "$2::uuid IS NULL") || !strings.Contains(query, "membership.conversation_id <> $2::uuid") {
			t.Fatalf("occupancy SQL missing nullable uuid exclude: %s", query)
		}
	}
}

func TestPostgresOccupancyLockSQLUsesForUpdateInStableOrder(t *testing.T) {
	if !strings.Contains(postgresConversationOccupancyLockSQL(), "FOR UPDATE") {
		t.Fatalf("conversation occupancy lock omitted FOR UPDATE: %s", postgresConversationOccupancyLockSQL())
	}
	if !strings.Contains(postgresEndpointOccupancyLockSQL(), "FOR UPDATE") {
		t.Fatalf("endpoint occupancy lock omitted FOR UPDATE: %s", postgresEndpointOccupancyLockSQL())
	}
	conversations, endpoints := postgresOccupancyLockOrder([]string{"b", "a", "a"}, map[string]struct{}{"agent/z": {}, "agent/a": {}})
	if !slices.Equal(conversations, []string{"a", "b"}) {
		t.Fatalf("conversation lock order=%v", conversations)
	}
	if !slices.Equal(endpoints, []string{"agent/a", "agent/z"}) {
		t.Fatalf("endpoint lock order=%v", endpoints)
	}
}

func TestPostgresControlMemberLeaseSQLDoesNotLockEndpoint(t *testing.T) {
	// Bind locks exclusive conversations then the session. Control must take
	// occupancy (conversation then endpoint) before any member-lease lock.
	if strings.Contains(postgresControlMemberLeaseSQL(), "FOR UPDATE") {
		t.Fatalf("control member lease must not lock the endpoint before occupancy: %s", postgresControlMemberLeaseSQL())
	}
	if !strings.Contains(postgresControlMemberLeaseSQL(), "lease_until") {
		t.Fatalf("control member lease omitted live-lease read: %s", postgresControlMemberLeaseSQL())
	}
}
