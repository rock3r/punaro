// Package controller defines the local-only security boundaries for an
// agent-facing v3 attachment workflow. It never exposes device, Access, or
// file-encryption keys to mailbox messages.
package controller

import (
	"context"
	"errors"
	"strings"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

const maxRelayIdentifierBytes = 256

// Mapping is one immutable local policy binding between a text relay
// conversation and the independently authenticated v3 directory membership.
// The mapping must be provisioned by the local operator, never inferred from
// a mailbox offer.
type Mapping struct {
	RelayConversationID  string
	ConversationID       [16]byte
	SenderDeviceID       [16]byte
	SenderGeneration     uint64
	RecipientDeviceID    [16]byte
	RecipientGeneration  uint64
	MembershipCommitment [32]byte
}

// InboundOffer is the minimal inert mailbox information used for discovery.
// It contains no authority: before any permit, output, or decrypt action, a
// caller must additionally fresh-verify the offer against the pinned
// directory and apply its local receipt policy.
type InboundOffer struct {
	PunaroMessageID     string
	RelayConversationID string
	Body                string
}

// TransferBindingResolver must fetch and root-verify a current directory view
// before returning an exact, locally approved transfer relationship. It is
// deliberately narrower than a general directory lookup: callers cannot use
// an offer to select a recipient, device generation, or membership.
type TransferBindingResolver interface {
	ResolveTransferBinding(context.Context, [16]byte, [16]byte, uint64, [16]byte, uint64, [32]byte, time.Time) (attachmentv2.DirectoryTransferBinding, error)
}

func (m Mapping) valid() bool {
	return validRelayIdentifier(m.RelayConversationID) && m.ConversationID != [16]byte{} &&
		m.SenderDeviceID != [16]byte{} && m.SenderGeneration != 0 &&
		m.RecipientDeviceID != [16]byte{} && m.RecipientGeneration != 0 &&
		m.MembershipCommitment != [32]byte{}
}

func validRelayIdentifier(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maxRelayIdentifierBytes && !strings.ContainsAny(value, "\x00\r\n")
}

// ValidateInboundOffer recognizes only an offer carried in the mapped relay
// conversation and bound to every immutable directory identity in Mapping.
// A successful result is discovery data only; it is not acceptance authority.
func ValidateInboundOffer(inbound InboundOffer, mapping Mapping) (attachmentv3.OfferNotice, error) {
	if !mapping.valid() || !validRelayIdentifier(inbound.PunaroMessageID) || !validRelayIdentifier(inbound.RelayConversationID) || inbound.RelayConversationID != mapping.RelayConversationID {
		return attachmentv3.OfferNotice{}, errors.New("unmapped v3 offer delivery")
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		return attachmentv3.OfferNotice{}, errors.New("invalid v3 offer delivery")
	}
	manifest := notice.Manifest
	if manifest.ConversationID != mapping.ConversationID ||
		manifest.SenderDeviceID != mapping.SenderDeviceID || manifest.SenderGeneration != mapping.SenderGeneration ||
		manifest.RecipientDeviceID != mapping.RecipientDeviceID || manifest.RecipientGeneration != mapping.RecipientGeneration ||
		manifest.MembershipCommitment != mapping.MembershipCommitment {
		return attachmentv3.OfferNotice{}, errors.New("v3 offer directory mapping mismatch")
	}
	return notice, nil
}

// VerifyFreshMapping re-establishes the local mapping against a fresh,
// root-verified directory before any sensitive attachment action. The return
// value is intentionally only an error: controller callers must not derive a
// new relationship from directory search results.
func VerifyFreshMapping(ctx context.Context, mapping Mapping, resolver TransferBindingResolver, now time.Time) error {
	if !mapping.valid() || resolver == nil || now.UTC().Unix() < 0 {
		return errors.New("invalid fresh v3 transfer binding")
	}
	binding, err := resolver.ResolveTransferBinding(ctx, mapping.ConversationID, mapping.SenderDeviceID, mapping.SenderGeneration, mapping.RecipientDeviceID, mapping.RecipientGeneration, mapping.MembershipCommitment, now.UTC())
	if err != nil || !exactTransferBinding(mapping, binding, now.UTC()) {
		return errors.New("fresh v3 transfer binding is unavailable")
	}
	return nil
}

func exactTransferBinding(mapping Mapping, binding attachmentv2.DirectoryTransferBinding, now time.Time) bool {
	nowUnix := now.Unix()
	return nowUnix >= 0 && binding.Permit.Audience != [32]byte{} && binding.Permit.DirectoryHead != [32]byte{} && binding.Permit.ExpiresAt > uint64(nowUnix) && // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		!binding.Sender.Revoked && binding.Sender.DeviceID == mapping.SenderDeviceID && binding.Sender.Generation == mapping.SenderGeneration &&
		!binding.Recipient.Revoked && binding.Recipient.DeviceID == mapping.RecipientDeviceID && binding.Recipient.Generation == mapping.RecipientGeneration &&
		!binding.Membership.Revoked && binding.Membership.ConversationID == mapping.ConversationID && binding.Membership.SenderDeviceID == mapping.SenderDeviceID && binding.Membership.SenderGeneration == mapping.SenderGeneration &&
		binding.Membership.RecipientDeviceID == mapping.RecipientDeviceID && binding.Membership.RecipientGeneration == mapping.RecipientGeneration && binding.Membership.Commitment == mapping.MembershipCommitment
}
