package v3

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

func TestParseAttachmentRouteAcceptsOnlyCanonicalV3Routes(t *testing.T) {
	transfer := testID(5)
	transferHex := "05000000000000000000000000000000"
	valid := []struct {
		method  string
		path    string
		op      uint64
		index   uint64
		attempt uint64
	}{
		{"POST", "/v3/attachments/" + transferHex + "/source", permitOperationSourceInit, 0, 0},
		{"PUT", "/v3/attachments/" + transferHex + "/source/chunks/0", permitOperationSourceUpload, 0, 0},
		{"POST", "/v3/attachments/" + transferHex + "/offer", permitOperationOffer, 0, 0},
		{"POST", "/v3/attachments/" + transferHex + "/accept", permitOperationAccept, 0, 0},
		{"POST", "/v3/attachments/" + transferHex + "/attempts/1/begin", permitOperationBegin, 0, 1},
		{"GET", "/v3/attachments/" + transferHex + "/chunks/7", permitOperationDownload, 7, 0},
		{"POST", "/v3/attachments/" + transferHex + "/complete", permitOperationComplete, 0, 0},
		{"POST", "/v3/attachments/" + transferHex + "/cancel", permitOperationCancel, 0, 0},
	}
	for _, tc := range valid {
		route, err := ParseAttachmentRoute(tc.method, tc.path)
		if err != nil || route.TransferID != transfer || route.Operation != tc.op || route.ChunkIndex != tc.index || route.AttemptGeneration != tc.attempt {
			t.Fatalf("%s %s route=%+v err=%v", tc.method, tc.path, route, err)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v3/attachments/" + transferHex + "/source/chunks/0"},
		{"PUT", "/v3/attachments/" + transferHex + "/chunks/0"},
		{"POST", "/v3/attachments/" + transferHex + "/chunks/00"},
		{"POST", "/v3/attachments/" + transferHex + "/attempts/01/begin"},
		{"POST", "/v3/attachments/" + transferHex + "//offer"},
		{"POST", "/v3/attachments/" + transferHex + "/%6fffer"},
		{"POST", "/v3/attachments/" + transferHex + "/../offer"},
	} {
		if _, err := ParseAttachmentRoute(tc.method, tc.path); err == nil {
			t.Fatalf("accepted non-canonical route: %s %s", tc.method, tc.path)
		}
	}
}

func TestAttachmentOperationRequestEnforcesOperationBodiesAndPermitRoute(t *testing.T) {
	transferHex := "05000000000000000000000000000000"
	if _, _, err := NewAttachmentOperationRequest("POST", "/v3/attachments/"+transferHex+"/source", nil, nil); err == nil {
		t.Fatal("empty source-init body accepted")
	}
	if _, _, err := NewAttachmentOperationRequest("POST", "/v3/attachments/"+transferHex+"/attempts/1/begin", []byte("body"), nil); err == nil {
		t.Fatal("begin body accepted")
	}
	if _, _, err := NewAttachmentOperationRequest("POST", "/v3/attachments/"+transferHex+"/accept", []byte("short"), nil); err == nil {
		t.Fatal("non-nonce accept body accepted")
	}
	if _, _, err := NewAttachmentOperationRequest("GET", "/v3/attachments/"+transferHex+"/chunks/0", []byte("body"), []byte("ciphertext")); err == nil {
		t.Fatal("download body accepted")
	}
	permit := testPermit(time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC))
	permit.Operation = permitOperationOffer
	route, _, err := NewAttachmentOperationRequest("POST", "/v3/attachments/"+transferHex+"/offer", []byte("envelope"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		t.Fatal(err)
	}
	route.TransferID = testID(12)
	if err := VerifyAttachmentRoute(route, permit); err == nil {
		t.Fatal("route for another transfer accepted")
	}
}

func TestSourceInitOperationRequiresCanonicalPermitBoundManifest(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	permit := testPermit(now)
	permit.Operation = permitOperationSourceInit
	permit.Audience, permit.TransferID, permit.ConversationID = manifest.Audience, manifest.TransferID, manifest.ConversationID
	permit.SenderDeviceID, permit.SenderGeneration = manifest.SenderDeviceID, manifest.SenderGeneration
	permit.RecipientDeviceID, permit.RecipientGeneration = manifest.RecipientDeviceID, manifest.RecipientGeneration
	permit.HolderDeviceID, permit.HolderGeneration, permit.HolderRole = manifest.SenderDeviceID, manifest.SenderGeneration, permitHolderSender
	permit.DirectoryHead, permit.MembershipCommitment, permit.RevocationEpoch = manifest.DirectoryHead, manifest.MembershipCommitment, manifest.RevocationEpoch
	permit.ExpiresAt, permit.StagedManifestCommitment = manifest.ExpiresAt, blake3.Sum256(raw)
	route, request, err := NewAttachmentOperationRequest("POST", "/v3/attachments/02000000000000000000000000000000/source", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		t.Fatal(err)
	}
	if err := verifyAttachmentRequestRoute(route, permit, request); err != nil {
		t.Fatal(err)
	}
	permit.StagedManifestCommitment = testHash(99)
	if err := verifyAttachmentRequestRoute(route, permit, request); err == nil {
		t.Fatal("source-init body with a mismatched staged commitment accepted")
	}
}
