package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testDeviceAuthIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	admin := &Administration{db: ownerDB}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: uuid.NewString(), ClientBinding: uuid.NewString(), Code: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("pristine ownership accepted public redemption: %v", err)
	}
	type bootstrapResult struct {
		owner Principal
		err   error
	}
	bootstrapResults := make(chan bootstrapResult, 2)
	var bootstrapWG sync.WaitGroup
	for _, label := range []string{"installation owner A", "installation owner B"} {
		bootstrapWG.Add(1)
		go func() {
			defer bootstrapWG.Done()
			owner, bootstrapErr := admin.BootstrapOwner(ctx, label)
			bootstrapResults <- bootstrapResult{owner: owner, err: bootstrapErr}
		}()
	}
	bootstrapWG.Wait()
	close(bootstrapResults)
	var owner Principal
	bootstrapSuccesses := 0
	for result := range bootstrapResults {
		if result.err == nil {
			bootstrapSuccesses++
			owner = result.owner
		} else if !errors.Is(result.err, ErrAlreadyInitialized) {
			t.Fatalf("concurrent bootstrap error=%v", result.err)
		}
	}
	if bootstrapSuccesses != 1 {
		t.Fatalf("concurrent bootstrap successes=%d, want 1", bootstrapSuccesses)
	}
	if _, err := admin.BootstrapOwner(ctx, "second owner"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second bootstrap error=%v", err)
	}

	project, err := app.CreateProject(ctx, ProjectCreate{PrincipalID: owner.ID, IdempotencyKey: uuid.NewString(), DisplayName: "enrollment project"})
	if err != nil {
		t.Fatal(err)
	}
	request := EnrollmentRequest{ClientBinding: uuid.NewString(), Label: "laptop", ProjectIDs: []string{project.ProjectID}, TTL: 10 * time.Minute, CredentialTTL: time.Minute}
	preview, previewHash, err := PreviewTrustedAgentEnrollment(request.ProjectIDs, request.AllProjects)
	if err != nil || len(preview) == 0 || previewHash == "" {
		t.Fatalf("preview=%#v hash=%q err=%v", preview, previewHash, err)
	}
	pending, err := admin.CreateEnrollment(ctx, owner.ID, request, previewHash)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Code == "" || pending.PreviewHash != previewHash || len(pending.Grants) != len(preview) {
		t.Fatalf("pending enrollment does not match preview: %#v", pending)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.pending_enrollments SET created_at = created_at - interval '5 minutes' WHERE id = $1`, pending.ID); err != nil {
		t.Fatal(err)
	}
	wrongPrefix := "A"
	if pending.Code[0] == 'A' {
		wrongPrefix = "B"
	}
	wrongCode := wrongPrefix + pending.Code[1:]
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: request.ClientBinding, Code: wrongCode, IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("wrong code error=%v", err)
	}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: uuid.NewString(), Code: pending.Code, IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("wrong client error=%v", err)
	}
	redeemKey := uuid.NewString()
	credential, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: request.ClientBinding, Code: pending.Code, IdempotencyKey: redeemKey})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(credential.ExpiresAt) < 50*time.Second {
		t.Fatalf("credential TTL was anchored to enrollment issuance: expires_at=%s", credential.ExpiresAt)
	}
	replayed, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: request.ClientBinding, Code: pending.Code, IdempotencyKey: redeemKey})
	if err != nil || replayed.Encoded != credential.Encoded || replayed.LookupID != credential.LookupID {
		t.Fatalf("exact redemption retry=%#v err=%v", replayed, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.pending_enrollments SET expires_at = statement_timestamp() - interval '1 second' WHERE id = $1`, pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: request.ClientBinding, Code: pending.Code, IdempotencyKey: redeemKey}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("expired redemption retry error=%v", err)
	}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pending.ID, ClientBinding: request.ClientBinding, Code: pending.Code, IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("single-use replay error=%v", err)
	}
	authenticated, err := app.AuthenticateDevice(ctx, credential.Encoded)
	if err != nil || authenticated.PrincipalID != credential.PrincipalID {
		t.Fatalf("authenticated=%#v err=%v", authenticated, err)
	}
	if ok, err := app.DeviceSessionCurrent(ctx, authenticated); err != nil || !ok {
		t.Fatalf("fresh session current=%t err=%v", ok, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET created_at = statement_timestamp() - interval '2 seconds', expires_at = statement_timestamp() - interval '1 second' WHERE lookup_id = $1`, credential.LookupID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthenticateDevice(ctx, credential.Encoded); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired credential error=%v", err)
	}
	if ok, err := app.DeviceSessionCurrent(ctx, authenticated); err != nil || ok {
		t.Fatalf("expired session current=%t err=%v", ok, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET expires_at = statement_timestamp() + interval '1 hour' WHERE lookup_id = $1`, credential.LookupID); err != nil {
		t.Fatal(err)
	}
	pendingRotation, err := admin.BeginDeviceCredentialRotation(ctx, owner.ID, credential.LookupID, credential.Generation)
	if err != nil {
		t.Fatal(err)
	}
	rotation := RotateCredential{LookupID: credential.LookupID, ExpectedGeneration: credential.Generation, Code: pendingRotation.Code}
	rotated, err := admin.RotateDeviceCredential(ctx, owner.ID, rotation)
	if err != nil {
		t.Fatal(err)
	}
	rotationRetry, err := admin.RotateDeviceCredential(ctx, owner.ID, rotation)
	if err != nil || rotationRetry.Encoded != rotated.Encoded || rotationRetry.Generation != rotated.Generation {
		t.Fatalf("exact rotation retry=%#v err=%v", rotationRetry, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET rotation_expires_at = statement_timestamp() - interval '1 second' WHERE lookup_id = $1`, credential.LookupID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.RotateDeviceCredential(ctx, owner.ID, rotation); !errors.Is(err, ErrCredentialChanged) {
		t.Fatalf("expired rotation retry error=%v", err)
	}
	if _, err := app.AuthenticateDevice(ctx, credential.Encoded); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old rotated credential error=%v", err)
	}
	if ok, err := app.DeviceSessionCurrent(ctx, authenticated); err != nil || ok {
		t.Fatalf("rotated session current=%t err=%v", ok, err)
	}
	if _, err := app.AuthenticateDevice(ctx, rotated.Encoded); err != nil {
		t.Fatal(err)
	}
	if err := admin.RevokeDeviceCredential(ctx, owner.ID, rotated.LookupID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthenticateDevice(ctx, rotated.Encoded); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked credential error=%v", err)
	}

	expiredRequest := EnrollmentRequest{ClientBinding: uuid.NewString(), Label: "expired client", AllProjects: true, TTL: time.Minute}
	_, expiredHash, err := PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	expiredPending, err := admin.CreateEnrollment(ctx, owner.ID, expiredRequest, expiredHash)
	if err != nil {
		t.Fatal(err)
	}
	var redeemedRows, redeemedGrantRows int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
        (SELECT count(*) FROM auth.pending_enrollments WHERE id = $1),
        (SELECT count(*) FROM auth.pending_enrollment_grants WHERE enrollment_id = $1)`, pending.ID).Scan(&redeemedRows, &redeemedGrantRows); err != nil || redeemedRows != 0 || redeemedGrantRows != 0 {
		t.Fatalf("expired redeemed enrollment rows=%d grants=%d err=%v, want pruned", redeemedRows, redeemedGrantRows, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.pending_enrollments SET created_at = statement_timestamp() - interval '2 seconds', expires_at = statement_timestamp() - interval '1 second' WHERE id = $1`, expiredPending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: expiredPending.ID, ClientBinding: expiredRequest.ClientBinding, Code: expiredPending.Code, IdempotencyKey: uuid.NewString()}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("expired enrollment error=%v", err)
	}

	concurrentRequest := EnrollmentRequest{ClientBinding: uuid.NewString(), Label: "desktop", AllProjects: true, TTL: 10 * time.Minute}
	_, concurrentHash, err := PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	concurrentPending, err := admin.CreateEnrollment(ctx, owner.ID, concurrentRequest, concurrentHash)
	if err != nil {
		t.Fatal(err)
	}
	var expiredRows int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM auth.pending_enrollments WHERE id = $1`, expiredPending.ID).Scan(&expiredRows); err != nil || expiredRows != 0 {
		t.Fatalf("expired enrollment rows=%d err=%v, want pruned", expiredRows, err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, redeemErr := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: concurrentPending.ID, ClientBinding: concurrentRequest.ClientBinding, Code: concurrentPending.Code, IdempotencyKey: uuid.NewString()})
			results <- redeemErr
		}()
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for redeemErr := range results {
		if redeemErr == nil {
			succeeded++
		} else if !errors.Is(redeemErr, ErrInvalidEnrollment) {
			t.Fatalf("concurrent redeem error=%v", redeemErr)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent redeem successes=%d, want 1", succeeded)
	}

	legacyPublic, legacyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := admin.RegisterLegacyMachine(ctx, owner.ID, "legacy laptop", legacyPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.DisableLegacyAuthentication(ctx, owner.ID); err == nil {
		t.Fatal("legacy authentication disabled with a pending intended machine")
	}
	legacyRequest := EnrollmentRequest{ClientBinding: uuid.NewString(), Label: "legacy replacement", AllProjects: true, LegacyPrincipalID: legacy.PrincipalID, TTL: 10 * time.Minute}
	legacyPending, err := admin.CreateEnrollment(ctx, owner.ID, legacyRequest, concurrentHash)
	if err != nil {
		t.Fatal(err)
	}
	legacyRedeem := RedeemEnrollment{EnrollmentID: legacyPending.ID, ClientBinding: legacyRequest.ClientBinding, Code: legacyPending.Code, IdempotencyKey: uuid.NewString()}
	if _, err := app.RedeemEnrollment(ctx, legacyRedeem); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("legacy exchange without verified legacy principal error=%v", err)
	}
	legacyCode, err := base64.RawURLEncoding.Strict().DecodeString(legacyRedeem.Code)
	if err != nil {
		t.Fatal(err)
	}
	legacyCodeDigest := sha256.Sum256(legacyCode)
	proof := LegacyExchangeProof{PublicKey: legacyPublic, Signature: ed25519.Sign(legacyPrivate, legacyExchangeTranscript(legacyRedeem, legacyCodeDigest))}
	wrongPublic, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongProof := LegacyExchangeProof{PublicKey: wrongPublic, Signature: ed25519.Sign(wrongPrivate, legacyExchangeTranscript(legacyRedeem, legacyCodeDigest))}
	if _, err := app.RedeemLegacyEnrollment(ctx, wrongProof, legacyRedeem); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("wrong legacy key exchange error=%v", err)
	}
	legacyCredential, err := app.RedeemLegacyEnrollment(ctx, proof, legacyRedeem)
	if err != nil {
		t.Fatal(err)
	}
	legacyRetry, err := app.RedeemLegacyEnrollment(ctx, proof, legacyRedeem)
	if err != nil || legacyRetry.Encoded != legacyCredential.Encoded || legacyRetry.LookupID != legacyCredential.LookupID {
		t.Fatalf("exact legacy exchange retry=%#v err=%v", legacyRetry, err)
	}
	if resolved, err := app.ResolveLegacyMachine(ctx, legacyPublic); err != nil || resolved != legacy.PrincipalID {
		t.Fatalf("resolved legacy principal=%q err=%v", resolved, err)
	}
	inventory, err := admin.ListLegacyMachines(ctx, owner.ID)
	if err != nil || len(inventory) != 1 || inventory[0].State != LegacyMigrated {
		t.Fatalf("legacy inventory=%#v err=%v", inventory, err)
	}
	racePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type registerResult struct {
		machine LegacyMachine
		err     error
	}
	registerResults := make(chan registerResult, 1)
	disableResults := make(chan error, 1)
	go func() {
		machine, registerErr := admin.RegisterLegacyMachine(ctx, owner.ID, "racing legacy", racePublic)
		registerResults <- registerResult{machine: machine, err: registerErr}
	}()
	go func() { disableResults <- admin.DisableLegacyAuthentication(ctx, owner.ID) }()
	registered := <-registerResults
	disableErr := <-disableResults
	if registered.err == nil && disableErr == nil {
		t.Fatal("legacy registration and disable both committed")
	}
	var legacyEnabled bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT enabled FROM auth.legacy_auth_state WHERE singleton`).Scan(&legacyEnabled); err != nil {
		t.Fatal(err)
	}
	var pendingLegacy bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE state = 'pending')`).Scan(&pendingLegacy); err != nil {
		t.Fatal(err)
	}
	if !legacyEnabled && pendingLegacy {
		t.Fatal("legacy gate disabled with a pending intended machine")
	}
	if legacyEnabled {
		if registered.err != nil || !pendingLegacy {
			t.Fatalf("enabled legacy race registration=%#v pending=%t disableErr=%v", registered, pendingLegacy, disableErr)
		}
		if err := admin.RetireLegacyMachine(ctx, owner.ID, registered.machine.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if err := admin.DisableLegacyAuthentication(ctx, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := app.ResolveLegacyMachine(ctx, legacyPublic); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("disabled legacy resolution error=%v", err)
	}
	if _, err := app.AuthenticateDevice(ctx, legacyCredential.Encoded); err != nil {
		t.Fatalf("new device credential failed after legacy disable: %v", err)
	}
}
