package controller

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

func TestValidateInboundOfferRequiresExactImmutableRelayAndDirectoryMapping(t *testing.T) {
	t.Parallel()
	mapping := Mapping{
		RelayConversationID:  "relay-conversation",
		ConversationID:       bytes16(1),
		SenderDeviceID:       bytes16(2),
		SenderGeneration:     1,
		RecipientDeviceID:    bytes16(3),
		RecipientGeneration:  1,
		MembershipCommitment: bytes32(4),
	}
	notice := testOfferNotice(t, mapping)
	if _, err := ValidateInboundOffer(InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: notice}, mapping); err != nil {
		t.Fatalf("valid mapped offer rejected: %v", err)
	}
	if _, err := ValidateInboundOffer(InboundOffer{PunaroMessageID: "message-1", RelayConversationID: "other", Body: notice}, mapping); err == nil {
		t.Fatal("offer with a mismatched relay conversation was accepted")
	}
	mapping.RecipientDeviceID = bytes16(9)
	if _, err := ValidateInboundOffer(InboundOffer{PunaroMessageID: "message-1", RelayConversationID: "relay-conversation", Body: notice}, mapping); err == nil {
		t.Fatal("offer with a mismatched recipient device was accepted")
	}
}

func TestVerifyFreshMappingRequiresTheExactCurrentDirectoryRelationship(t *testing.T) {
	t.Parallel()
	mapping := Mapping{
		RelayConversationID:  "relay-conversation",
		ConversationID:       bytes16(1),
		SenderDeviceID:       bytes16(2),
		SenderGeneration:     1,
		RecipientDeviceID:    bytes16(3),
		RecipientGeneration:  1,
		MembershipCommitment: bytes32(4),
	}
	now := time.Unix(100, 0).UTC()
	resolver := bindingResolverStub{binding: attachmentv2.DirectoryTransferBinding{
		Permit:     attachmentv2.DirectoryPermitBinding{Audience: bytes32(5), DirectoryHead: bytes32(6), RevocationEpoch: 1, ExpiresAt: 101},
		Sender:     attachmentv2.DirectoryDevice{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration, SigningKeyID: bytes32(7), SigningPublicKey: bytes32(8), HPKEKeyID: bytes32(9), HPKEPublicKey: bytes32(10)},
		Recipient:  attachmentv2.DirectoryDevice{DeviceID: mapping.RecipientDeviceID, Generation: mapping.RecipientGeneration, SigningKeyID: bytes32(11), SigningPublicKey: bytes32(12), HPKEKeyID: bytes32(13), HPKEPublicKey: bytes32(14)},
		Membership: attachmentv2.DirectoryMembership{ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, Commitment: mapping.MembershipCommitment},
	}}
	if err := VerifyFreshMapping(context.Background(), mapping, &resolver, now); err != nil {
		t.Fatalf("exact fresh relationship rejected: %v", err)
	}
	if resolver.conversation != mapping.ConversationID || resolver.sender != mapping.SenderDeviceID || resolver.recipient != mapping.RecipientDeviceID || resolver.membership != mapping.MembershipCommitment {
		t.Fatal("mapping was not passed verbatim to the directory resolver")
	}
	resolver.binding.Membership.Revoked = true
	if err := VerifyFreshMapping(context.Background(), mapping, &resolver, now); err == nil {
		t.Fatal("revoked directory membership was accepted")
	}
	resolver.err = errors.New("unavailable")
	if err := VerifyFreshMapping(context.Background(), mapping, &resolver, now); err == nil {
		t.Fatal("unavailable fresh directory was accepted")
	}
}

type bindingResolverStub struct {
	binding      attachmentv2.DirectoryTransferBinding
	err          error
	conversation [16]byte
	sender       [16]byte
	recipient    [16]byte
	membership   [32]byte
}

func (s *bindingResolverStub) ResolveTransferBinding(_ context.Context, conversation, sender [16]byte, senderGeneration uint64, recipient [16]byte, recipientGeneration uint64, membership [32]byte, _ time.Time) (attachmentv2.DirectoryTransferBinding, error) {
	s.conversation, s.sender, s.recipient, s.membership = conversation, sender, recipient, membership
	if senderGeneration == 0 || recipientGeneration == 0 || s.err != nil {
		return attachmentv2.DirectoryTransferBinding{}, s.err
	}
	return s.binding, nil
}

func testOfferNotice(t *testing.T, mapping Mapping) string {
	t.Helper()
	_, signer := testOfferSigner()
	manifest := attachmentv3.Manifest{
		Audience:             bytes32(5),
		TransferID:           bytes16(6),
		ConversationID:       mapping.ConversationID,
		SenderDeviceID:       mapping.SenderDeviceID,
		SenderGeneration:     mapping.SenderGeneration,
		RecipientDeviceID:    mapping.RecipientDeviceID,
		RecipientGeneration:  mapping.RecipientGeneration,
		DirectoryHead:        bytes32(7),
		MembershipCommitment: mapping.MembershipCommitment,
		RevocationEpoch:      1,
		IssuedAt:             100,
		ExpiresAt:            120,
		ContentSalt:          bytes32(8),
		PlaintextCommitment:  bytes32(9),
		ChunkSize:            1,
		ChunkCount:           1,
		PlaintextSize:        0,
		SignerKeyID:          bytes32(10),
	}
	if err := attachmentv3.SignManifest(&manifest, signer); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := attachmentv3.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := attachmentv3.Envelope{
		Audience:            manifest.Audience,
		TransferID:          manifest.TransferID,
		ConversationID:      manifest.ConversationID,
		SenderDeviceID:      manifest.SenderDeviceID,
		SenderGeneration:    manifest.SenderGeneration,
		RecipientDeviceID:   manifest.RecipientDeviceID,
		RecipientGeneration: manifest.RecipientGeneration,
		RecipientHPKEKeyID:  bytes32(11),
		ManifestCommitment:  blake3.Sum256(manifestRaw),
		EncapsulatedKey:     bytes32(12),
		Ciphertext:          make([]byte, 16),
		SignerKeyID:         manifest.SignerKeyID,
	}
	if err := attachmentv3.SignEnvelope(&envelope, signer); err != nil {
		t.Fatal(err)
	}
	raw, err := attachmentv3.EncodeOfferPayload(manifest, envelope, bytes32(13))
	if err != nil {
		t.Fatal(err)
	}
	notice, err := attachmentv3.EncodeOfferNotice(raw)
	if err != nil {
		t.Fatal(err)
	}
	return notice
}

type offerDirectoryStub struct {
	signer    ed25519.PublicKey
	recipient *ecdh.PublicKey
}

func (d offerDirectoryStub) ValidateManifestAuthority(attachmentv3.Manifest, time.Time) (ed25519.PublicKey, error) {
	return d.signer, nil
}
func (d offerDirectoryStub) CurrentRecipientHPKEKey([16]byte, uint64) ([32]byte, *ecdh.PublicKey, error) {
	return bytes32(11), d.recipient, nil
}
func (d offerDirectoryStub) ResolveRecipientHPKEKey(_ [16]byte, _ uint64, id [32]byte) (*ecdh.PublicKey, error) {
	if id != bytes32(11) {
		return nil, errors.New("unknown key")
	}
	return d.recipient, nil
}

func testOfferSigner() (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

func testOfferDirectory(t *testing.T) offerDirectoryStub {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public, _ := testOfferSigner()
	return offerDirectoryStub{signer: public, recipient: private.PublicKey()}
}

func bytes16(value byte) [16]byte {
	var result [16]byte
	for i := range result {
		result[i] = value
	}
	return result
}

func bytes32(value byte) [32]byte {
	var result [32]byte
	for i := range result {
		result[i] = value
	}
	return result
}
