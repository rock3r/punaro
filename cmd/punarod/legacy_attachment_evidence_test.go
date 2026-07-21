package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/relay"
)

const (
	attachmentV3ReapInterval = time.Minute
	attachmentV3ReapBatch    = 64
)

type legacyAttachmentConfig struct {
	DataDir                     string
	AttachmentV3Enabled         bool
	AttachmentV3SourceStoreFile string
	DirectoryEnabled            bool
	DirectorySnapshotFile       string
	DirectoryAudience           [32]byte
	DirectoryRootKeyID          [32]byte
	DirectoryRootPublicKey      []byte
	PermitIssuanceEnabled       bool
	PermitIssuerKeyID           [32]byte
	PermitIssuerPrivateKeyFile  string
	PermitMaxLifetimeSeconds    uint64
	PermitMaxBytes              uint64
	PermitMaxChunks             uint64
	PermitMaxOperations         uint64
	PermitMaxActive             uint64
	RelayMachinesJSON           string
	AccessIssuer                string
	AccessAudience              string
	AccessJWKSURL               string
	AccessJWKSFile              string
}

func (cfg legacyAttachmentConfig) accessConfig() config.Config {
	return config.Config{AccessIssuer: cfg.AccessIssuer, AccessAudience: cfg.AccessAudience, AccessJWKSURL: cfg.AccessJWKSURL, AccessJWKSFile: cfg.AccessJWKSFile}
}

// This harness preserves the retired daemon-composition evidence without
// linking the v2/v3 runtime into the production punarod binary.
type permitRouteAuthorizer struct{ authenticator *relay.Authenticator }

// attachmentV3RouteAuthorizer binds an independently authenticated enrolled
// machine to the exact directory device named by a v3 permit. Possession of a
// copied permit/operation is never sufficient for route admission.
type attachmentV3RouteAuthorizer struct{ authenticator *relay.Authenticator }

func (a attachmentV3RouteAuthorizer) AuthorizeAttachmentRequest(ctx context.Context, permit attachmentv3.Permit) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("v3 attachment route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != permit.HolderDeviceID {
		return errors.New("machine is not bound to v3 attachment permit holder")
	}
	return nil
}

// attachmentV3PermitRouteAuthorizer applies the same independent
// machine-to-directory-device binding before the issuer even looks up a
// holder key. This prevents one enrolled machine from submitting a copied
// holder-signed v3 permit request for another machine's device.
type attachmentV3PermitRouteAuthorizer struct{ authenticator *relay.Authenticator }

func (a attachmentV3PermitRouteAuthorizer) AuthorizePermitRequest(ctx context.Context, request attachmentv3.PermitRequest) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("v3 permit route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != request.HolderDeviceID {
		return errors.New("machine is not bound to v3 permit holder")
	}
	return nil
}

func (a permitRouteAuthorizer) AuthorizePermitRequest(ctx context.Context, request attachmentv2.PermitRequest) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("permit route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != request.HolderDeviceID {
		return errors.New("machine is not bound to permit holder")
	}
	return nil
}

func (a permitRouteAuthorizer) AuthorizeAttachmentRequest(ctx context.Context, permit attachmentv2.Permit) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("attachment route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != permit.HolderDeviceID {
		return errors.New("machine is not bound to attachment permit holder")
	}
	return nil
}

// buildPermitHandler exposes only permit issuance, never attachment upload or
// download. It binds an enrolled transport identity to the directory holder
// before issuing a capability and fetches a newly verified directory snapshot
// for every request. The returned closer owns the private checkpoint and
// issuance ledgers.
func buildPermitHandler(cfg legacyAttachmentConfig, store *relay.Store) (http.Handler, func(), func() error, error) {
	if !cfg.PermitIssuanceEnabled {
		return nil, nil, nil, nil
	}
	if store == nil {
		return nil, nil, nil, errors.New("permit issuance requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, nil, err
	}
	boundMachines := 0
	for _, machine := range machines {
		if machine.AttachmentDeviceID != [16]byte{} {
			boundMachines++
		}
	}
	if boundMachines == 0 {
		return nil, nil, nil, errors.New("permit issuance requires an enrolled attachment device binding")
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, nil, nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, nil, nil, err
	}
	privateDir := filepath.Join(cfg.DataDir, "attachment-v2")
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(privateDir, "directory-checkpoints.db"))
	if err != nil {
		return nil, nil, nil, err
	}
	ledger, err := attachmentv2.OpenSQLitePermitLedger(filepath.Join(privateDir, "permit-ledger.db"))
	if err != nil {
		_ = checkpoints.Close()
		return nil, nil, nil, err
	}
	closeStores := func() {
		_ = ledger.Close()
		_ = checkpoints.Close()
	}
	privateKey, err := attachmentv2.LoadPrivateEd25519KeyFile(cfg.PermitIssuerPrivateKeyFile)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	authority, err := attachmentv2.NewFreshDirectoryAuthorityProvider(source, attachmentv2.DirectoryTrust{Audience: cfg.DirectoryAudience, RootKeyID: cfg.DirectoryRootKeyID, RootPublicKey: cfg.DirectoryRootPublicKey, Checkpoints: checkpoints})
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	lifetime, err := permitIssuerLifetime(cfg.PermitMaxLifetimeSeconds)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	issuer, err := attachmentv2.NewPermitIssuer(attachmentv2.PermitIssuerOptions{Ledger: ledger, IssuerKeyID: cfg.PermitIssuerKeyID, PrivateKey: privateKey, MaxLifetime: lifetime, MaxBytes: cfg.PermitMaxBytes, MaxChunks: cfg.PermitMaxChunks, MaxOperations: cfg.PermitMaxOperations, MaxActive: cfg.PermitMaxActive})
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	handler, err := attachmentv2.NewPermitHTTPHandler(issuer, authority, permitRouteAuthorizer{authenticator: authenticator}, nil)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	middleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 4<<10, nil)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	handler = middleware(handler)
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg.accessConfig())
		if err != nil {
			closeStores()
			return nil, nil, nil, err
		}
		handler = verifier.Middleware(handler)
	}
	issuerPublic := privateKey.Public().(ed25519.PublicKey)
	readiness := func() error {
		current, err := authority.ResolvePermitIssuanceAuthority(context.Background(), time.Now().UTC())
		if err != nil {
			return errors.New("fresh permit directory authority is unavailable")
		}
		authorized, err := current.CurrentPermitIssuerKey(cfg.PermitIssuerKeyID)
		if err != nil || !bytes.Equal(authorized, issuerPublic) {
			return errors.New("permit issuer is not directory-authorized")
		}
		return nil
	}
	if err := readiness(); err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	return handler, closeStores, readiness, nil
}

// buildV3AttachmentHandlers constructs the complete v3 permit and transfer
// surface together. It deliberately does not share the v2 ledger or handler:
// only root-verified directory facts are adapted across versions.
func buildV3AttachmentHandlers(cfg legacyAttachmentConfig, store *relay.Store) (http.Handler, http.Handler, func(), func() error, error) {
	if !cfg.AttachmentV3Enabled {
		return nil, nil, nil, nil, nil
	}
	if store == nil {
		return nil, nil, nil, nil, errors.New("v3 attachment runtime requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	boundMachines := 0
	for _, machine := range machines {
		if machine.AttachmentDeviceID != [16]byte{} {
			boundMachines++
		}
	}
	if boundMachines == 0 {
		return nil, nil, nil, nil, errors.New("v3 attachment runtime requires an enrolled attachment device binding")
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	privateDir := filepath.Join(cfg.DataDir, "attachment-v3")
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(privateDir, "directory-checkpoints.db"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	closeStores := func() { _ = checkpoints.Close() }
	privateKey, err := attachmentv2.LoadPrivateEd25519KeyFile(cfg.PermitIssuerPrivateKeyFile)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	directoryProvider, err := attachmentv2.NewFreshDirectoryAuthorityProvider(source, attachmentv2.DirectoryTrust{Audience: cfg.DirectoryAudience, RootKeyID: cfg.DirectoryRootKeyID, RootPublicKey: cfg.DirectoryRootPublicKey, Checkpoints: checkpoints})
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	authority, err := attachmentv3.NewDirectoryAuthorityAdapter(directoryProvider)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	lifetime, err := v3PermitIssuerLifetime(cfg.PermitMaxLifetimeSeconds)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	runtime, err := attachmentv3.NewAttachmentRuntime(attachmentv3.AttachmentRuntimeOptions{SourceStorePath: cfg.AttachmentV3SourceStoreFile, AttachmentAuthority: authority, PermitAuthority: authority, AttachmentAuthorize: attachmentV3RouteAuthorizer{authenticator: authenticator}, PermitAuthorize: attachmentV3PermitRouteAuthorizer{authenticator: authenticator}, IssuerKeyID: cfg.PermitIssuerKeyID, IssuerPrivateKey: privateKey, MaxLifetime: lifetime, MaxBytes: cfg.PermitMaxBytes, MaxChunks: cfg.PermitMaxChunks, MaxOperations: cfg.PermitMaxOperations, MaxActive: cfg.PermitMaxActive})
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	// Recover quota before exposing handlers. Waiting for the first periodic
	// tick after a restart could leave every finite source slot occupied by
	// already-expired state and deny otherwise valid source-init operations.
	if _, err := runtime.ReapExpired(context.Background(), time.Now().UTC(), attachmentV3ReapBatch); err != nil {
		_ = runtime.Close()
		closeStores()
		return nil, nil, nil, nil, fmt.Errorf("recover expired v3 attachment state: %w", err)
	}
	var closeRuntimeOnce sync.Once
	closeRuntime := func() {
		closeRuntimeOnce.Do(func() {
			_ = runtime.Close()
			closeStores()
		})
	}
	permitMiddleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 4<<10, nil)
	if err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	attachmentMiddleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 256<<10+16, nil)
	if err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	permitHandler := permitMiddleware(runtime.PermitHandler())
	attachmentHandler := attachmentMiddleware(runtime.AttachmentHandler())
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg.accessConfig())
		if err != nil {
			closeRuntime()
			return nil, nil, nil, nil, err
		}
		permitHandler = verifier.Middleware(permitHandler)
		attachmentHandler = verifier.Middleware(attachmentHandler)
	}
	issuerPublic := privateKey.Public().(ed25519.PublicKey)
	readiness := func() error {
		current, err := authority.ResolvePermitIssuanceAuthority(context.Background(), time.Now().UTC())
		if err != nil {
			return errors.New("fresh v3 permit directory authority is unavailable")
		}
		authorized, err := current.CurrentPermitIssuerKey(cfg.PermitIssuerKeyID)
		if err != nil || !bytes.Equal(authorized, issuerPublic) {
			return errors.New("v3 permit issuer is not directory-authorized")
		}
		if _, err := authority.ResolveAttachmentAuthority(context.Background(), time.Now().UTC()); err != nil {
			return errors.New("fresh v3 attachment directory authority is unavailable")
		}
		return nil
	}
	if err := readiness(); err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	// Reaping does not decide authorization; every live operation fresh-checks
	// the directory first. It only durably releases expired state in bounded
	// batches so a restart or a long-lived quiet relay cannot accumulate source
	// staging forever. The close function waits for it before closing SQLite.
	// #nosec G118 -- closeRuntime below owns and invokes cancelReaper before
	// closing the dependent SQLite runtime.
	reaperContext, cancelReaper := context.WithCancel(context.Background())
	reaperDone := make(chan struct{})
	previousClose := closeRuntime
	closeRuntime = func() {
		cancelReaper()
		<-reaperDone
		previousClose()
	}
	go func() {
		defer close(reaperDone)
		ticker := time.NewTicker(attachmentV3ReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-reaperContext.Done():
				return
			case now := <-ticker.C:
				_, _ = runtime.ReapExpired(reaperContext, now, attachmentV3ReapBatch)
			}
		}
	}()
	return permitHandler, attachmentHandler, closeRuntime, readiness, nil
}

func v3PermitIssuerLifetime(seconds uint64) (time.Duration, error) {
	if seconds == 0 || seconds > 30 {
		return 0, errors.New("v3 permit issuer lifetime must be between one and thirty seconds")
	}
	return time.Duration(seconds) * time.Second, nil // #nosec G115 -- bound above is safely representable in time.Duration.
}

func permitIssuerLifetime(seconds uint64) (time.Duration, error) {
	if seconds == 0 || seconds > 60 {
		return 0, errors.New("permit issuer lifetime must be between one and sixty seconds")
	}
	return time.Duration(seconds) * time.Second, nil // #nosec G115 -- bound above is safely representable in time.Duration.
}

func buildDirectoryHandler(cfg legacyAttachmentConfig, store *relay.Store) (http.Handler, error) {
	if !cfg.DirectoryEnabled {
		return nil, nil
	}
	if store == nil {
		return nil, errors.New("directory service requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, err
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, err
	}
	handler, err := relay.NewDirectoryHandler(authenticator, source, nil)
	if err != nil {
		return nil, err
	}
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg.accessConfig())
		if err != nil {
			return nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, nil
}
