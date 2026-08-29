package legacyexchange

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestTranscriptIsLengthStableAndDomainSeparated(t *testing.T) {
	digest := sha256.Sum256([]byte("one-time code"))
	got := string(Transcript("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", digest))
	if !strings.HasPrefix(got, "punaro-legacy-exchange-v1\n") || !strings.HasSuffix(got, "\n"+"3310c0a405f5abb8b2f6519a83b1beecdd94bdd221487b7786eddc8fb6357055") {
		t.Fatalf("transcript=%q", got)
	}
}
