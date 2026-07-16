// Package controller defines the local-only security boundaries for an
// agent-facing v3 attachment workflow. It never exposes device, Access, or
// file-encryption keys to mailbox messages.
package controller

import (
	"errors"
	"strings"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

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

func (m Mapping) valid() bool {
	return strings.TrimSpace(m.RelayConversationID) != "" && m.ConversationID != [16]byte{} &&
		m.SenderDeviceID != [16]byte{} && m.SenderGeneration != 0 &&
		m.RecipientDeviceID != [16]byte{} && m.RecipientGeneration != 0 &&
		m.MembershipCommitment != [32]byte{}
}

// ValidateInboundOffer recognizes only an offer carried in the mapped relay
// conversation and bound to every immutable directory identity in Mapping.
// A successful result is discovery data only; it is not acceptance authority.
func ValidateInboundOffer(inbound InboundOffer, mapping Mapping) (attachmentv3.OfferNotice, error) {
	if !mapping.valid() || strings.TrimSpace(inbound.PunaroMessageID) == "" || inbound.RelayConversationID != mapping.RelayConversationID {
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
