package v3

import (
	"testing"
)

func TestDecodeTransferResultAcceptsOnlyCanonicalKnownLifecycleState(t *testing.T) {
	t.Parallel()
	raw, err := encodeTransferResult(testID(51), testHash(52), transferOffered, 0, 1_800_000_000)
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeTransferResult(raw)
	if err != nil || result.TransferID != testID(51) || result.ManifestCommitment != testHash(52) || result.State != TransferStateOffered || result.AttemptGeneration != 0 || result.ExpiresAt != 1_800_000_000 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := DecodeTransferResult(append(raw, 0)); err == nil {
		t.Fatal("non-canonical transfer result accepted")
	}
}
