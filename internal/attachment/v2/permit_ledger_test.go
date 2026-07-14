package v2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLitePermitLedgerIssuesOnceAndRedeemsExactOperationIdempotently(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := samplePermit()
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(30*time.Second))
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	request := sampleOperationRequest(t)
	operation := sampleOperation(permit, request)
	operation.IssuedAt, operation.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(10*time.Second))
	if err := SignOperation(&operation, holderPrivate); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	issuers := permitAuthorityStub{keyID: permit.IssuerKeyID, key: issuerPublic}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	if err := ledger.Issue(permit, issuers, clock); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Issue(permit, issuers, clock); err == nil {
		t.Fatal("duplicate permit serial was issued")
	}
	if _, err := ledger.db.ExecContext(context.Background(), "CREATE TABLE test_effects(value BLOB NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	mutation := func(_ context.Context, tx *sql.Tx) ([]byte, error) {
		calls++
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO test_effects(value) VALUES (?)", []byte("effect")); err != nil {
			return nil, err
		}
		return []byte("result"), nil
	}
	tooSmall := permit
	tooSmall.Serial, tooSmall.MaxBytes = bytes16(98), uint64(len("ciphertext")-1)
	if err := SignPermit(&tooSmall, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	tooSmallOperation := sampleOperation(tooSmall, request)
	if err := SignOperation(&tooSmallOperation, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Issue(tooSmall, issuers, clock); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Redeem(context.Background(), tooSmall, tooSmallOperation, request, issuers, holders, clock, mutation); err == nil || calls != 0 {
		t.Fatalf("over-budget ciphertext request ran: calls=%d err=%v", calls, err)
	}
	result, replayed, err := ledger.Redeem(context.Background(), permit, operation, request, issuers, holders, clock, mutation)
	if err != nil || replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("result=%q replay=%v calls=%d err=%v", result, replayed, calls, err)
	}
	result, replayed, err = ledger.Redeem(context.Background(), permit, operation, request, issuers, holders, clock, mutation)
	if err != nil || !replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("retry result=%q replay=%v calls=%d err=%v", result, replayed, calls, err)
	}
	changed := operation
	changed.BodyCommitment[0] ^= 1
	if err := SignOperation(&changed, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Redeem(context.Background(), permit, changed, request, issuers, holders, clock, mutation); err == nil {
		t.Fatal("changed-body replay was accepted")
	}
	reusedIdempotency := operation
	reusedIdempotency.OperationID = bytes16(99)
	if err := SignOperation(&reusedIdempotency, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Redeem(context.Background(), permit, reusedIdempotency, request, issuers, holders, clock, mutation); err == nil {
		t.Fatal("operation with reused idempotency key was accepted")
	}
	var effects int
	if err := ledger.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM test_effects").Scan(&effects); err != nil || effects != 1 {
		t.Fatalf("effects=%d err=%v", effects, err)
	}
}

func TestSQLitePermitLedgerRejectsObsoleteSchema(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "ledger.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE redeemed_operations (permit_serial BLOB NOT NULL, operation_id BLOB NOT NULL, operation BLOB NOT NULL, path_commitment BLOB NOT NULL, target_commitment BLOB NOT NULL, body_commitment BLOB NOT NULL, idempotency_key BLOB NOT NULL, result BLOB NOT NULL, PRIMARY KEY(permit_serial, operation_id))"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLitePermitLedger(path); err == nil {
		t.Fatal("obsolete permit ledger schema was accepted")
	}
}
