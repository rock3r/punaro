package fleetconfig

import "testing"

func TestParseCommitIDAcceptsFullImmutableIdentities(t *testing.T) {
	t.Parallel()
	sha1 := "0123456789abcdef0123456789abcdef01234567"
	sha256 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, id := range []string{sha1, sha256} {
		got, err := ParseCommitID(id)
		if err != nil || got != id {
			t.Fatalf("id=%q got=%q err=%v", id, got, err)
		}
	}
}

func TestParseCommitIDRejectsMutableAndPartialIdentities(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		"",
		"HEAD",
		"main",
		"origin/main",
		"refs/heads/main",
		"v1.0.0",
		"abc1234",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"0123456789abcdef0123456789abcdef0123456",
		"0123456789abcdef0123456789abcdef012345678",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
		"0123456789abcdef0123456789abcdef01234567\n",
		" 0123456789abcdef0123456789abcdef01234567",
	} {
		if _, err := ParseCommitID(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}
