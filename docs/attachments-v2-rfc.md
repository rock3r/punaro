# Attachment transfer v2 RFC

**Status:** pre-release security contract.  Attachment v2 is not available in
`punarod`; enabling it must continue to fail at startup until every release
gate in [`security-release-gates.md`](security-release-gates.md) is satisfied.

This is the single source of truth for a *released* attachment v2.  It
supersedes every issue comment and design draft.  The current Go attachment
foundation predates this RFC, is non-normative and non-conformant, and is not
evidence for any RFC gate.  It must never be promoted unchanged.  Its exact
divergences are recorded in
[`attachment-foundation-gap-matrix.md`](attachment-foundation-gap-matrix.md).
Changes require a new RFC version, matching conformance vectors, an adversarial
review, and an explicit release-gate decision.  Prose elsewhere may summarize
this RFC but must not override it.

## Goals and non-goals

V2 transfers an encrypted artifact from an enrolled sender device to a fixed,
enrolled recipient-device snapshot within one conversation.  The relay may
store ciphertext and bounded signaling only.  It must not receive plaintext,
file keys, unsolicited candidate extensions, or authority to widen recipient
membership.

V2 does not provide public links, browser downloads, Telegram file transport,
anonymous transfer, nor a way to recover bytes already delivered before a
revocation is observed.

## Trust and identity

The root-authorized, append-only device directory is the authority for device
key, generation, membership, permit-issuer key, and revocation state.  A root
public key and root key ID are pinned in protected local configuration.  Root
rotation needs a cross-signed transition from the current root and a recovery
procedure that requires explicit operator approval.

A directory head is a canonical signed record containing version, audience,
root key ID, tree size, tree root, sequence, issued time, expiry, and revocation
epoch.  Its maximum validity is 30 seconds.  Each adapter persists its last
accepted `(sequence, tree root, revocation epoch)` in anti-rollback storage;
every newer head needs a consistency proof from that checkpoint.  The adapter
rejects a head that is expired, has `expires_at > issued_at + 30 seconds`, is
issued more than 120 seconds from trusted local time, is not yet effective
(`issued_at > local_time`), decreases sequence or epoch, lacks a valid
consistency/inclusion proof, or has the wrong audience.  A missing fresh head is a hard failure, not an
offline grace period.  Two valid heads for the same audience and sequence with
different roots are equivocation: freeze that audience, retain the evidence,
and issue or accept no permit until an operator-approved recovery head arrives.

### Directory head and consistency proof encoding

The directory-head record is CDE map `{1=version,2=audience,3=root_key_id,
4=tree_size,5=tree_root,6=sequence,7=issued_at,8=expires_at,
9=revocation_epoch,99=signature}`. `version` is exactly `2`; audience, both
key IDs, and tree root are 32-byte strings; tree size and sequence are non-zero
unsigned integers. Its signature preimage is ASCII
`punaro/attachment/directory-head/v2`, one NUL byte, followed by CDE encoding
of the same map without field `99`. The encoded head is at most 4 KiB.

The initial bounded deployment uses a full consistency proof: an ordered array
of exactly `tree_size` 32-byte leaf hashes, limited to 4096 leaves. The tree
root is the sole leaf hash for a one-leaf tree. Each internal node is
BLAKE3-256 of ASCII `punaro/attachment/directory-node/v2`, one NUL byte,
followed by its left and right child hashes; an odd final node is promoted
unchanged. To advance a checkpoint, a verifier recomputes both the old prefix
root and new full root from this proof. A compact proof format may replace this
only in a future version with equivalent vectors and review; accepting an
underspecified compact proof is forbidden.

Request signatures bind an immutable relay audience/instance ID, protocol
version, method, canonical path, body commitment, device generation, request
nonce, and request expiry.  Replay consumption is durable and shared by every
replica for the audience.  Device keys are never reused across audiences.

### Directory snapshot entries

Every snapshot is an ordered list whose leaf hash is BLAKE3-256 of ASCII
`punaro/attachment/directory-leaf/v2`, one NUL byte, followed by its CDE entry.
The verifier recomputes the entire ordered tree from these leaves and requires
an exact match with the signed head before it writes any anti-rollback
checkpoint. A signed head without its matching snapshot is therefore unusable
and cannot poison a local checkpoint.

A device entry is CDE map `{1=1,2=device_id,3=generation,4=signing_key_id,
5=signing_public_key,6=hpke_key_id,7=hpke_public_key,8=revoked}`. Device IDs
are 16-byte strings; both public keys and key IDs are 32-byte strings; and the
generation is a non-zero unsigned integer. A device generation first appears
unrevoked. A later entry for that exact device generation may only change
`revoked` from false to true: it must reproduce every key field verbatim and
may never revive the generation.

A membership entry is CDE map `{1=2,2=conversation_id,3=sender_device_id,
4=sender_generation,5=recipient_device_id,6=recipient_generation,
7=membership_commitment}`. Conversation and device IDs are 16-byte strings;
generations are non-zero unsigned integers; and the commitment is 32 bytes.
The `(conversation, sender device/generation, recipient device/generation)`
tuple is immutable and must appear no more than once in one snapshot. A
manifest is authorized only when its audience, directory-head commitment,
revocation epoch, signer key ID, sender generation, recipient generation, and
membership commitment all match this fresh, exact snapshot. The recipient's
HPKE key is resolved from that same non-revoked device record.

## Immutable records

All signed records use deterministic CBOR.  A Manifest includes `version`,
`audience`, `transfer_id`, `conversation_id`, sender device and generation,
recipient device and generation, directory-head commitment, membership
commitment, revocation epoch, issued/expiry times, and a domain-separated
Ed25519 signature.  A recipient Envelope binds the complete signed Manifest by
its commitment and repeats the audience, transfer, conversation, sender, and
recipient snapshot; it cannot be accepted without a fresh verification of that
Manifest.  Unknown fields, duplicate map keys, non-canonical CBOR, or an
unsupported version are rejected.

The source creates one CSPRNG 32-byte content salt and file key, reserves their
uniqueness durably before encryption, and creates an immutable manifest.  The
content salt is a public, authenticated manifest field; it is not secret
material.  Per-recipient keys are delivered only in an HPKE recipient envelope whose AAD
binds the manifest commitment, transfer, conversation, recipient generation,
and audience.  The artifact ID is exactly `manifest_commitment`; it is never a
separate caller-selected identifier.  Chunks use an AEAD with a unique nonce
derived from the durable `(transfer_id, manifest_commitment, chunk_index)`
tuple and AAD binding the complete manifest commitment, chunk index/count, and
plaintext length.  The relay stores only ciphertext, ciphertext commitment,
and recipient-specific encrypted envelope.

### V2 algorithm registry

V2 uses only the following identifiers.  There is no algorithm negotiation or
fallback: any other value is rejected before signature verification or HPKE
processing.

| Purpose | Algorithm | Identifier |
| --- | --- | --- |
| Record signature | Ed25519 | `1` |
| Record commitment | BLAKE3-256 | `1` |
| HPKE KEM | DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| HPKE KDF | HKDF-SHA256 | `0x0001` |
| HPKE AEAD | ChaCha20-Poly1305 | `0x0003` |

HPKE is RFC 9180 base mode only.  It authenticates the envelope context but
not the sender; the independently verified Ed25519 manifest and envelope
signatures provide sender authentication.  Signing, HPKE, and directory keys
are distinct key usages and key IDs.

### Canonical records and signatures

All V2 records use RFC 8949 **core deterministic encoding** (CDE), with an
integer-key map.  Receivers reject non-shortest encodings, indefinite lengths,
tags, floats, null/undefined, duplicate or unknown keys, invalid UTF-8,
trailing data, and any byte string exceeding its declared limit.  A receiver
must decode, validate, CDE re-encode, and require byte-for-byte equality before
using a record or verifying its signature.

`device_id`, `transfer_id`, and `conversation_id` are exactly 16-byte opaque
values.  `audience`, key IDs, commitments, and hashes are exactly 32 bytes.
Generations, epochs, timestamps, counts, and sizes are unsigned integers.
`issued_at` and `expires_at` are Unix seconds; expiry must be later than issue.
The manifest's maximum encoded size is 4 KiB and an envelope's is 16 KiB.
`manifest_commitment` is BLAKE3-256 over the complete canonical signed Manifest
encoding, including field `99`; a Manifest is not eligible for commitment until
its signature has been verified against the fresh directory key-ID binding.
Manifests have a maximum 30-second lifetime, may not be issued more than 120
seconds in the future, are not accepted before `issued_at <= local_time`, and
are accepted only when a fresh directory head proves
the sender/recipient inclusions, the exact membership commitment, and the exact
revocation epoch recorded by the Manifest.  A newer head or epoch, a changed
membership commitment, an expired Manifest, or an unprovable historic head is
a hard failure; no stale-head grace applies.
For a non-empty artifact, all chunks before the last are full: its plaintext
size is greater than `(chunk_count - 1) * chunk_size` and no greater than
`chunk_count * chunk_size`.  A zero-byte artifact is represented by exactly one
empty authenticated chunk (`chunk_count=1`, `plaintext_size=0`).

`plaintext_commitment` is exactly BLAKE3-256 of ASCII
`punaro/attachment/plaintext/v2`, one NUL byte, `content_salt`, the eight-byte
big-endian `plaintext_size`, then the plaintext bytes in order.  An AEAD chunk
key is HKDF-SHA256 with `IKM=file_key`, `salt=content_salt`, ASCII info
`punaro/attachment/chunk-key/v2` followed by one NUL byte and
`manifest_commitment`, and length 32.  For chunk index `i`, encoded as an
eight-byte big-endian unsigned integer, the 12-byte ChaCha20-Poly1305 nonce is
the first 12 bytes of BLAKE3-256 over ASCII
`punaro/attachment/chunk-nonce/v2`, one NUL byte, `transfer_id`,
`manifest_commitment`, and `i`.  The chunk AAD is CDE map
`{1=version,2=transfer_id,3=manifest_commitment,4=chunk_index,5=chunk_count,6=plaintext_length}`.
Every value must equal the Manifest; `plaintext_length` is the actual chunk
length.  Implementations reserve this nonce tuple and the file-key commitment
durably before encryption and never reuse either, including after crashes.

The Manifest body is the following required map; its signature is field `99`.
The signature preimage is ASCII `punaro/attachment/manifest/v2`, one NUL byte,
then the CDE encoding of the same map with field `99` omitted.  Its signature
is exactly 64 bytes.

| Key | Field | Type / constraint |
| --- | --- | --- |
| 1 | version | unsigned; exactly `2` |
| 2 | audience | bstr(32) |
| 3 | transfer_id | bstr(16) |
| 4 | conversation_id | bstr(16) |
| 5 | sender_device_id | bstr(16) |
| 6 | sender_generation | unsigned, non-zero |
| 7 | recipient_device_id | bstr(16) |
| 8 | recipient_generation | unsigned, non-zero |
| 9 | directory_head | bstr(32) |
| 10 | membership_commitment | bstr(32) |
| 11 | revocation_epoch | unsigned |
| 12 | issued_at | unsigned |
| 13 | expires_at | unsigned |
| 14 | content_salt | bstr(32) |
| 15 | plaintext_commitment | bstr(32) |
| 16 | chunk_size | unsigned, `1..262144` |
| 17 | chunk_count | unsigned, `1..4096` |
| 18 | plaintext_size | unsigned, at most 64 MiB |
| 19 | signer_key_id | bstr(32) |
| 20 | signature_algorithm | unsigned; exactly `1` |
| 99 | signature | bstr(64) |

The recipient Envelope is independently signed by the sender using the same
manifest signing key.  It carries an RFC 9180 encapsulated key and ciphertext;
only the file key is inside that ciphertext.  The envelope
signature preimage is ASCII `punaro/attachment/envelope/v2`, one NUL byte,
then the CDE encoding of the map with field `99` omitted.

| Key | Field | Type / constraint |
| --- | --- | --- |
| 1 | version | unsigned; exactly `2` |
| 2 | audience | bstr(32) |
| 3 | transfer_id | bstr(16) |
| 4 | conversation_id | bstr(16) |
| 5 | sender_device_id | bstr(16) |
| 6 | sender_generation | unsigned, non-zero |
| 7 | recipient_device_id | bstr(16) |
| 8 | recipient_generation | unsigned, non-zero |
| 9 | recipient_hpke_key_id | bstr(32) |
| 10 | manifest_commitment | bstr(32) |
| 11 | kem_id | unsigned; exactly `0x0020` |
| 12 | kdf_id | unsigned; exactly `0x0001` |
| 13 | aead_id | unsigned; exactly `0x0003` |
| 14 | encapsulated_key | bstr(32) |
| 15 | ciphertext | bstr, `16..256` bytes |
| 16 | signer_key_id | bstr(32) |
| 17 | signature_algorithm | unsigned; exactly `1` |
| 99 | signature | bstr(64) |

For HPKE, `info` is the exact ASCII bytes
`punaro/attachment-envelope/v2/base`.  The AAD is the CDE encoding of a map
with keys `1=version`, `2=audience`, `3=transfer_id`, `4=conversation_id`,
`5=recipient_device_id`, `6=recipient_generation`, `7=manifest_commitment`,
`8=kem_id`, `9=kdf_id`, and `10=aead_id`; its values exactly equal the envelope
fields.  The encrypted plaintext is CDE map `{1=file_key:bstr(32),
2=manifest_commitment:bstr(32), 3=recipient_hpke_key_id:bstr(32),
4=recipient_generation:uint}` and must be
at most 160 bytes before encryption.  Before unsealing, an adapter verifies the
fresh directory record, manifest signature, envelope signature, recipient
generation, all outer bindings, and the recipient HPKE key ID.  After unsealing
it validates and compares every inner binding; no caller-provided outer field
is authority.

The test corpus must include fixed positive and negative CDE and RFC 9180
vectors.  The corpus manifest names its upstream source and SHA-256, and every
dependency/toolchain update must pass it plus decoder fuzzing.

## State machine and authorization

`created -> source-ready -> offered -> accepted -> transferring -> completed`
is the only successful path.  `expired`, `cancelled`, and `revoked` are
terminal.  Source readiness is atomic: the complete immutable artifact and
manifest must exist before an offer can be accepted.

The directory authorizes the sender, conversation, recipient snapshot, and
operation.  A relay-signed, short-lived permit is required for every operation.
A permit record contains version, audience, permit serial, issuer key ID,
holder device/generation/role, transfer and conversation IDs, recipient,
attempt generation, allowed operation, directory-head commitment, membership
commitment, revocation epoch, issued time, expiry, and signature.  Permit
validity is at most 60 seconds and never later than the bound directory head's
expiry.  The issuer verifies a fresh directory head and
atomically records the serial before issuing; a verifier checks the issuer
certificate, all bindings, time, directory checkpoint, and revocation epoch.
Serial reuse, renewal after expiry, and use for another operation/attempt are
hard failures.  Renewal requires a new fresh directory view and a new serial.

A recipient-signed acceptance consumes a one-time redemption nonce.  Retries
use signed idempotency identifiers and return the existing state rather than
rotating an active session.

Permit issuance and permit redemption are separate durable operations.
`issued_serials` records a newly issued serial exactly once and never makes the
permit itself invalid.  Each authorized request instead includes a CSPRNG
`operation_id`, canonical operation/path/target commitment, body commitment,
and idempotency key; all are covered by the holder signature and must match the
permit's allowed operation and quota.  `redeemed_operations` is keyed by
`(permit serial, operation_id)` and atomically transitions `pending` to
`succeeded` with the state mutation.  An identical retry returns the recorded
result.  A different body, target, operation, or idempotency key for a redeemed
operation is rejected.  A permit cannot be used after expiry, for a different
attempt, or beyond its byte/chunk/operation quota.  Conformance vectors must
cover issuance collision, valid retry, changed-body retry, cross-path replay,
expired permit, and exhausted quota.

Revocation stops new offers, acceptances, uploads, downloads, permits, and
signaling immediately after a fresh directory view.  Direct transport closes
on revocation notification or permit expiry.  Because a permit cannot outlive
its 30-second directory head, the documented residual exposure is at most 30
seconds after publication of a correctly authenticated revoking head for bytes
already in flight; delivered plaintext is never recalled.

## Transport and resource safety

WebRTC/TURN is optional after the authenticated relay state machine has chosen
an attempt.  SDP, candidates, and channel transcript are signed and bound to
both permits.  Candidate types are allow-listed.  A data channel has bounded
frame size, total in-flight ciphertext, concurrency, rate, lifetime, and
reassembly memory; any violation closes the channel.

The v2 bounds are: encrypted frame at most 256 KiB; at most 1 MiB aggregate
unacknowledged ciphertext per channel; at most four live attempts per device
and one per `(transfer, recipient)`; 8 MiB/s sustained ciphertext rate with a
16 MiB one-second burst per device; 15-minute maximum channel lifetime; and
256 KiB maximum reassembly memory.  The relay and both peers enforce each bound
independently.  Bounds are part of the signed attempt/permit context, so a
peer cannot negotiate a larger value.

Every offer, artifact, signal, nonce, and attempt has expiry.  Limits are
enforced per sender, recipient, conversation, and relay.  A durable reaper
releases only expired *capacity* reservations, ciphertext, signals, and
idempotency records.  It never releases or reassigns cryptographic
file-key/salt/nonce-tuple commitments: those remain collision-blocking for the
full cryptographic retention period.  Cleanup is crash-safe and auditable.  A
full relay never accepts an operation merely because a global counter is below
its limit.

## Acceptance evidence

Before attachment runtime release, CI and a release drill must demonstrate:

- canonical-vector interoperability and malformed-record rejection;
- replay, audience-confusion, stale-directory, key-rotation, and revocation
  rejection;
- source-ready, retry, crash/restart, lease-fencing, expiry, and reaper paths;
- quota exhaustion and recovery without manual database intervention;
- direct and relay transport bounds, candidate/transcript binding, and permit
  expiry; and
- an independent cryptography/protocol assessment of the implemented RFC.
