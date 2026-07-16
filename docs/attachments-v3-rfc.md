# Attachment transfer v3: source staging amendment

**Status:** controlled-validation pre-release. This amendment defines the only
acceptable remedy for the v2 source-upload bootstrap cycle. It permits only the
explicit, machine-authenticated v3 validation mount; it does not open the
production attachment release gate.

## Compatibility

V3 is a separate route and signed-record namespace. A v2 implementation must
reject every `/v3/` request, and a v3 implementation must reject every `/v2/`
attachment request. Existing v2 records are never reinterpreted as v3 records.

V3 normatively inherits every unchanged v2 deterministic-CBOR, algorithm,
header-decoding, bounded-body, strict-path, request-admission, and
response-probing control. In particular, it rejects queries, escaped paths,
content encodings, duplicate/padded credential headers, oversized bodies, and
unauthenticated storage lookups. V3 replaces only the source lifecycle and its
route/operation domains below.

V3 retains the v2 trust model: a fresh signed directory, recipient-device
snapshot, machine-bound request admission, one-time signed permits, and
recipient-bound encrypted envelopes. It adds an explicit private source stage
before an offer can exist.

## State machine

```text
created --source-init--> source-uploading --all exact chunks--> source-ready
source-ready --offer--> offered --accept--> accepted --begin--> transferring
transferring --complete--> completed

any non-terminal state --cancel/revoke/expiry--> terminal state
```

`source-uploading` and `source-ready` are not recipient-discoverable. A source
may never replace a staged manifest or ciphertext chunk. An offer is the first
recipient-visible state, and only a complete immutable source can enter it.

## Records and routes

Every v3 signed record uses deterministic CBOR and a v3-specific domain. There
is no separate source-init record: the source-init body is exactly one complete,
canonical signed Manifest (at most 4 KiB), while the v3 permit and operation
headers bind that exact body commitment. A source-init permit has operation
`source-init`; a source-upload permit has operation `source-upload`. Neither
permit is valid for offer, accept, download, begin, completion, or cancellation.

Before any body is read, a relay accepts only the literal fixed route grammar
in the table below: uppercase method, lowercase 32-hex transfer ID, decimal
integers without leading zeroes, and no escape, duplicate separator, dot
segment, query, fragment, `RawPath`, or content encoding. It derives the
operation target from that parsed route; a client never supplies target bytes.
The parser binds route transfer/operation/attempt to the permit before it
checks the signed request commitment. Bodies are exactly: canonical Manifest
(<=4 KiB) for source-init; ciphertext for source-upload; canonical offer CDE
(<=24,555 bytes) for offer; a 32-byte nonce for accept; empty for begin, complete,
and cancel; and empty request body plus stored ciphertext response for download.

`Manifest` and `Envelope` mean v3 records, never v2 bytes: they retain the v2
field tables, byte limits, algorithms, and validation rules, with required
version `3` and every signature/commitment domain's version segment replaced
with `v3`. A v2 decoder must therefore reject them and vice versa.

| Route | Holder | Requirement |
| --- | --- | --- |
| `POST /v3/attachments/{transfer}/source` | sender | Canonical signed Manifest body; creates private staging exactly once. |
| `PUT /v3/attachments/{transfer}/source/chunks/{index}` | sender | Exact ciphertext frame, manifest-bound index, one immutable retry identity. |
| `POST /v3/attachments/{transfer}/offer` | sender | Recipient envelope and one-time nonce; succeeds only after complete staging. |
| `POST /v3/attachments/{transfer}/accept` | recipient | Existing one-time acceptance rules. |
| `POST /v3/attachments/{transfer}/attempts/{attempt}/begin` | recipient | Starts the single fenced relay transfer attempt. |
| `GET /v3/attachments/{transfer}/chunks/{index}` | recipient | Only after accepted, with response-bound operation commitment. |
| `POST /v3/attachments/{transfer}/complete` | recipient | Records verified completion for the fenced attempt. |
| `POST /v3/attachments/{transfer}/cancel` | sender | Cancels a private staged source before offer. |

The source-init body contains the complete canonical signed Manifest. The relay
fresh-verifies it before reserving capacity, derives (rather than duplicates)
the manifest commitment, audience, chunk geometry, identities, membership,
directory head, revocation epoch, and expiry, and stores the exact bytes
immutably. Source-init is strict: its route, permit, operation record, and
body must bind the identical audience, transfer/conversation IDs,
sender/recipient generations, manifest commitment, directory-head commitment,
membership commitment, revocation epoch, and expiry.

An immutable v3 Manifest may live for at most ten minutes. Directory heads and
permits remain independently short-lived (at most 30 seconds). After strict
source-init, each operation obtains a new permit from a fresh current directory
view. That permit remains exactly bound to the Manifest commitment, transfer
identities, and membership commitment, but its directory head and revocation
epoch are the current values and may therefore differ from the Manifest's
admission provenance. Every operation rejects a current missing/revoked
membership, device generation, signer key, or permit issuer; it never accepts a
stale directory head as an offline grace period. Permit and operation expiry
may not outlive either the Manifest or their fresh directory head.

V3 operation identifiers are `1=source-init`, `2=source-upload`,
`3=offer`, `4=accept`, `5=download`, `6=begin`, `7=complete`, and `8=cancel`.
Each uses the inherited CDE permit/operation map with protocol version `3`; its
v2 domain prefix segment is replaced byte-for-byte with `v3`; and map key `24`
is the required 32-byte staged Manifest commitment. No other inherited field
number changes. The v3 vector corpus must cover each identifier and rejection
path.

The offer body is CDE map `{1=3,2=manifest_bytes,3=envelope_bytes,
4=acceptance_nonce}` at most 24,555 bytes. `manifest_bytes` must be byte-identical to
the staged manifest; `envelope_bytes` is canonical and fresh-directory-verified
against its commitment; `acceptance_nonce` is exactly 32 random bytes. The
accept body is exactly that raw 32-byte nonce, preserving an unambiguous
one-time comparison. Cancel has an empty body and is sender-only before offer;
after offer it is forbidden because it cannot recall a delivered envelope.

### Durable offer discovery

After an `offer` operation has succeeded, the sender durably records the exact
raw offer CDE in a local outbox, then places it in its existing authorized
relay conversation as the single text grammar
`punaro/attachment-offer/v3:` followed by unpadded raw-base64url bytes. The
entire text body, including marker, is bounded to 32 KiB. The outbox is deleted
only after the relay accepts the append; a sender retries the same relay append
with a transfer-scoped stable idempotency key and never changes or re-wraps the
offer on retry. This notification is deliberately
outside the attachment authorization state machine: it is recipient discovery,
not an attachment URL, a capability, or permission to decrypt/download.

An adapter may recognize only that literal marker and must reject padded,
whitespace-containing, noncanonical, malformed, oversized, or non-v3 values.
It then treats the recovered offer as untrusted network input and performs the
normal fresh manifest/envelope verification, recipient HPKE open, and
recipient-held permit flow. A mailbox, Telegram gateway, or WebSocket wake
must never interpret the notice as a file payload or proxy attachment bytes.

V3 status values are `1=created`, `2=source-uploading`, `3=source-ready`,
`4=offered`, `5=accepted`, `6=transferring`, `7=completed`, `8=expired`,
`9=cancelled`, and `10=revoked`. Action values are `1=source-init`,
`2=source-ready`, `3=offer`, `4=accept`, `5=begin`, `6=complete`,
`7=expire`, `8=cancel`, and `9=revoke`. Each successful or replayed route
returns CDE map `{1=3,2=transfer_id,3=manifest_commitment,4=status,
5=attempt_generation,6=expires_at}` (at most 256 bytes); the original result
is retained for an idempotent retry.

## Atomicity and quotas

Source-init atomically reserves sender, recipient, conversation, and relay
staging capacity before writing private state. The initial implementation caps
one artifact at 64 MiB, 4096 chunks, and 256 KiB plaintext chunks; deployment
must configure non-zero finite aggregate ciphertext-byte, chunk, and transfer
ceilings for each scope (and reject invalid or absent limits before listener
construction). Source-init derives and reserves `plaintext_size + 16*chunk_count`
ciphertext bytes plus exact chunk/transfer slots in one transaction, using
checked unsigned arithmetic. Configuration has finite implementation maxima;
every overflow fails closed. Those
reservations remain through completed delivery and release only in the terminal
cleanup transaction. A completed relay-blob source remains quota-accounted
until its short Manifest/permit expiry so an exact signed download retry can
return the original immutable ciphertext; the expiry reaper preserves the
durable `completed` status while releasing those rows. Chunk uploads atomically
redeem their operation, enforce exact length and index, and store either the
identical ciphertext or nothing. The final missing chunk atomically verifies
the complete contiguous set and advances `source-uploading` to `source-ready`.
No crash boundary may yield a recipient-visible partial artifact.

Cancellation is sender-only, signed, idempotent, and valid only before offer.
Directory revocation is a fresh-view server transition, never a client claim.
Both cancellation and expiry block new operations and atomically delete staged
metadata, offers/nonces, ciphertext, attempts, signals, permit/idempotency
records, and all capacity reservations. A durable terminal tombstone for each
transfer ID and staged Manifest commitment survives cleanup, together with the
idempotency result until every related Manifest/permit/operation expiry; only
then may a bounded reaper remove it. Cryptographic uniqueness reservations also
survive. A bounded daemon reaper applies expiry, while every fresh
directory check may immediately fence a revoked transfer.
Cryptographic file-key, salt,
and nonce reservations outlive reaping. A replica deployment requires one
shared transactional store or a documented singleton writer with fencing; local
SQLite is not a horizontally scalable release topology.

## Required evidence before release

Implement and test source-init, every crash/retry boundary, concurrent final
upload, changed-chunk rejection, all quota scopes, cancellation/revocation,
restart/reaper recovery, and machine/permit replay rejection. Add fixed v3
positive and negative vectors plus fuzzing for every v3 decoder and route.
Direct WebRTC/TURN remains separately gated by its transcript, candidate,
connection, rate, lifetime, and revocation controls. Complete independent
protocol/cryptography and operations reviews, SBOM/attestation, and restore and
revocation drills before modifying `security-release-gates.md`.

For this relay-blob amendment, downloads require the recipient's single active
fenced attempt: `accepted -> begin -> transferring`, every download binds that
attempt generation, and `complete` succeeds only after all manifest chunks were
downloaded and verified. Direct transport uses a later amendment; it may not
reuse this attempt without its own signed transcript and permit rules.

Exact retry semantics are normative: an identical signed source-init, chunk,
offer, accept, begin, complete, or cancel returns its stored result; a changed
body or binding under the same idempotency identity fails; a second source-init
naming an existing transfer ID or a previously staged Manifest commitment fails,
including after terminal cleanup until its tombstone expires; and concurrent
final uploads yield one
source-ready transition and one capacity reservation.
