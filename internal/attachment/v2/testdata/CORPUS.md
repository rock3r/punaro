# Attachment v2 conformance corpus

`cde/manifest-v2-positive.sha256` fixes the complete canonical byte vector for
a deterministic V2 Manifest record.  It uses the documented `sampleManifest`
fields and an Ed25519 seed of 32 bytes of `0x0a`; the test verifies the exact
encoded-byte digest, signature, and canonical round trip.
`cde/manifest-v2-negative.hex` contains fixed malformed CBOR inputs for empty,
indefinite, tagged, float, null, duplicate-key, unknown-key, and trailing-data
records.  Each must be rejected.

`cde/envelope-v2-negative.hex` applies the same fixed malformed-CBOR corpus to
the Envelope parser.  Together with the raw positive recipient-envelope vector
it tests both V2 record parsers against fixed CDE bytes.

`hpke-envelope-v2-positive.hex` is a fixed recipient-envelope decryption
vector using the V2-selected RFC 9180 base-mode suite.  Its fixed Ed25519 seed
is 32 bytes of `0x0a`, its X25519 recipient private key is 32 bytes of `0x0b`,
and the expected file key is 32 bytes of `0x2a`.  The test must decode,
authenticate, and decrypt it exactly.

HPKE suite selection is checked against the Go 1.26.5 standard-library copy of
the IETF RFC 9180 base-mode vectors at
`src/crypto/hpke/testdata/rfc9180.json`.  Its SHA-256 is
`908a08888ba7406f18a00dcfe13f4e068a892c3ed2ec1312cbf43945596741e7`.
The upstream vector source is RFC 9180, Appendix A:
https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A

The initial offline core is not release evidence.  The release gate still
requires independent cryptography review and complete runtime-state evidence.
