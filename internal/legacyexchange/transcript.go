// Package legacyexchange defines the exact proof transcript used to exchange
// one registered legacy Ed25519 identity for a device credential.
package legacyexchange

import (
	"crypto/sha256"
	"encoding/hex"
)

// Transcript binds the one-time enrollment, device binding, idempotency key,
// and decoded secret-code digest without placing the code in the signature.
func Transcript(enrollmentID, clientBinding, idempotencyKey string, codeDigest [sha256.Size]byte) []byte {
	return []byte("punaro-legacy-exchange-v1\n" + enrollmentID + "\n" + clientBinding + "\n" + idempotencyKey + "\n" + hex.EncodeToString(codeDigest[:]))
}
