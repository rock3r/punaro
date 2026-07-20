package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

func TestMailCutoverRequestValidation(t *testing.T) {
	t.Parallel()
	valid := MailCutoverRequest{
		EpochID:           "019f7f07-4b88-7c12-a394-b663274a6555",
		SourceID:          "019f7f07-5b88-7c12-a394-b663274a6555",
		TargetIdentity:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manifest := relay.MigrationSourceManifest{
		Version: 1, SourceID: valid.SourceID, Phase: relay.MigrationSourcePrepared, EpochID: valid.EpochID,
		TargetIdentity: valid.TargetIdentity, Fingerprint: valid.SourceFingerprint,
		TableSHA256: relay.MigrationSourceHashes{
			Endpoints: strings.Repeat("c", 64), Conversations: strings.Repeat("c", 64), Memberships: strings.Repeat("c", 64),
			Messages: strings.Repeat("c", 64), Deliveries: strings.Repeat("c", 64), RecipientCursors: strings.Repeat("c", 64),
			MessageIdempotency: strings.Repeat("c", 64), ConversationIdempotency: strings.Repeat("c", 64), RequestNonces: strings.Repeat("c", 64),
		},
	}
	valid.Manifest, _ = json.Marshal(manifest)
	digest := sha256.Sum256(valid.Manifest)
	valid.ManifestSHA256 = hex.EncodeToString(digest[:])
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []MailCutoverRequest{
		{},
		func() MailCutoverRequest { changed := valid; changed.EpochID = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.SourceID = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.TargetIdentity = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.SourceFingerprint = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.Manifest = json.RawMessage(`[]`); return changed }(),
		func() MailCutoverRequest {
			changed := valid
			changed.Manifest = json.RawMessage(`{"padding":"` + strings.Repeat("x", 9000) + `"}`)
			return changed
		}(),
		func() MailCutoverRequest { changed := valid; changed.ManifestSHA256 = "bad"; return changed }(),
		func() MailCutoverRequest {
			changed := valid
			changed.SourceFingerprint = strings.Repeat("d", 64)
			return changed
		}(),
	}
	for index, request := range invalid {
		if err := request.Validate(); err == nil {
			t.Fatalf("invalid request %d accepted: %#v", index, request)
		}
	}
}
