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
rejects a head that is expired, issued more than 120 seconds from trusted local
time, decreases sequence or epoch, lacks a valid consistency/inclusion proof,
or has the wrong audience.  A missing fresh head is a hard failure, not an
offline grace period.  Two valid heads for the same audience and sequence with
different roots are equivocation: freeze that audience, retain the evidence,
and issue or accept no permit until an operator-approved recovery head arrives.

Request signatures bind an immutable relay audience/instance ID, protocol
version, method, canonical path, body commitment, device generation, request
nonce, and request expiry.  Replay consumption is durable and shared by every
replica for the audience.  Device keys are never reused across audiences.

## Immutable records

All signed records use deterministic CBOR.  Every record includes `version`,
`audience`, `transfer_id`, `conversation_id`, sender device and generation,
recipient device and generation, directory-head commitment, membership
commitment, revocation epoch, issued/expiry times, and a domain-separated
Ed25519 signature.  Unknown fields, duplicate map keys, non-canonical CBOR,
or an unsupported version are rejected.

The source creates one CSPRNG 32-byte content salt and file key, reserves their
uniqueness durably before encryption, and creates an immutable manifest.
Per-recipient keys are delivered only in an HPKE recipient envelope whose AAD
binds the manifest commitment, transfer, conversation, recipient generation,
and audience.  Chunks use an AEAD with a unique nonce derived from the durable
transfer/artifact/index tuple and AAD binding the complete manifest commitment,
chunk index/count, and plaintext length.  The relay stores only ciphertext,
ciphertext commitment, and recipient-specific encrypted envelope.

Before a runtime is implemented, this section must be expanded with algorithm
identifiers, exact CBOR maps, and cross-language positive and negative test
vectors.  No implementation may invent those details independently.

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
validity is at most 60 seconds.  The issuer verifies a fresh directory head and
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
on revocation notification or permit expiry.  The documented residual exposure
is at most the permit lifetime for bytes already in flight.

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
releases expired reservations, ciphertext, signals, idempotency records, and
nonce records.  Cleanup is crash-safe and auditable.  A full relay never
accepts an operation merely because a global counter is below its limit.

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
