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
	operation := sampleOperation(permit)
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
	issuers := permitIssuerStub{keyID: permit.IssuerKeyID, key: issuerPublic}
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
	result, replayed, err := ledger.Redeem(context.Background(), permit, operation, issuers, holders, clock, mutation)
	if err != nil || replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("result=%q replay=%v calls=%d err=%v", result, replayed, calls, err)
	}
	result, replayed, err = ledger.Redeem(context.Background(), permit, operation, issuers, holders, clock, mutation)
	if err != nil || !replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("retry result=%q replay=%v calls=%d err=%v", result, replayed, calls, err)
	}
	changed := operation
	changed.BodyCommitment[0] ^= 1
	if err := SignOperation(&changed, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Redeem(context.Background(), permit, changed, issuers, holders, clock, mutation); err == nil {
		t.Fatal("changed-body replay was accepted")
	}
	var effects int
	if err := ledger.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM test_effects").Scan(&effects); err != nil || effects != 1 {
		t.Fatalf("effects=%d err=%v", effects, err)
	}
}
