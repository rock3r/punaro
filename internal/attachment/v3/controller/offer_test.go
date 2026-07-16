package controller

import (
	"testing"

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

func testOfferNotice(t *testing.T, mapping Mapping) string {
	t.Helper()
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
