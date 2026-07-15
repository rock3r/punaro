package v3

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"time"
)

// AttachmentRuntimeOptions are the complete fail-closed inputs for serving
// v3 attachment permits and transfers. The source-store directory must already
// exist with private, non-symlinked permissions; the runtime never widens it.
type AttachmentRuntimeOptions struct {
	SourceStorePath     string
	AttachmentAuthority AttachmentAuthorityProvider
	PermitAuthority     PermitIssuanceAuthorityProvider
	AttachmentAuthorize AttachmentRequestAuthorizer
	PermitAuthorize     PermitRequestAuthorizer
	IssuerKeyID         [32]byte
	IssuerPrivateKey    ed25519.PrivateKey
	MaxLifetime         time.Duration
	MaxBytes            uint64
	MaxChunks           uint64
	MaxOperations       uint64
	MaxActive           uint64
	Now                 func() time.Time
	Random              io.Reader
}

// AttachmentRuntime owns the one private v3 source store shared by issuance
// and redemption. Keeping both handlers in this one runtime prevents an
// issuer from accidentally targeting a different durable ledger.
type AttachmentRuntime struct {
	store             *sourceStore
	attachmentHandler http.Handler
	permitHandler     http.Handler
}

func NewAttachmentRuntime(options AttachmentRuntimeOptions) (*AttachmentRuntime, error) {
	if options.SourceStorePath == "" || options.AttachmentAuthority == nil || options.PermitAuthority == nil || options.AttachmentAuthorize == nil || options.PermitAuthorize == nil {
		return nil, errors.New("v3 attachment runtime requires source store, authorities, and route admissions")
	}
	store, err := openSourceStore(options.SourceStorePath, defaultSourceLimits())
	if err != nil {
		return nil, err
	}
	closeStore := true
	defer func() {
		if closeStore {
			_ = store.close()
		}
	}()
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Store: store, IssuerKeyID: options.IssuerKeyID, PrivateKey: options.IssuerPrivateKey, MaxLifetime: options.MaxLifetime, MaxBytes: options.MaxBytes, MaxChunks: options.MaxChunks, MaxOperations: options.MaxOperations, MaxActive: options.MaxActive, Now: options.Now, Random: options.Random})
	if err != nil {
		return nil, err
	}
	permitHandler, err := NewPermitHTTPHandler(issuer, options.PermitAuthority, options.PermitAuthorize, options.Now)
	if err != nil {
		return nil, err
	}
	attachmentHandler, err := NewAttachmentHTTPHandler(AttachmentHTTPHandlerOptions{Store: store, Authority: options.AttachmentAuthority, Authorize: options.AttachmentAuthorize, Now: options.Now})
	if err != nil {
		return nil, err
	}
	closeStore = false
	return &AttachmentRuntime{store: store, attachmentHandler: attachmentHandler, permitHandler: permitHandler}, nil
}

func (r *AttachmentRuntime) AttachmentHandler() http.Handler {
	if r == nil {
		return nil
	}
	return r.attachmentHandler
}

func (r *AttachmentRuntime) PermitHandler() http.Handler {
	if r == nil {
		return nil
	}
	return r.permitHandler
}

// ReapExpired performs one bounded maintenance batch. It is safe to call
// concurrently with request handlers and intentionally performs no directory
// fetch: all live requests already fresh-check their authority before a state
// transition. Operators schedule this periodically to reclaim expired source
// staging, receipt, operation, and issuance-journal state after crash/restart.
func (r *AttachmentRuntime) ReapExpired(ctx context.Context, now time.Time, limit uint64) (uint64, error) {
	if r == nil || r.store == nil || limit == 0 {
		return 0, errors.New("v3 attachment runtime reaper is not configured")
	}
	return r.store.reapExpired(ctx, now.UTC(), limit)
}

func (r *AttachmentRuntime) Close() error {
	if r == nil || r.store == nil {
		return nil
	}
	return r.store.close()
}
