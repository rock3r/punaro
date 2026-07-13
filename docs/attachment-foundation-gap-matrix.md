# Attachment foundation gap matrix

The `internal/attachment` package is a deliberately unmounted test foundation,
not an implementation of [attachment v2](attachments-v2-rfc.md).  Passing its
tests proves local helper behavior only.  It is not security-release evidence.

| RFC control | Foundation state | Release action |
| --- | --- | --- |
| Canonical CBOR, signatures, versioning | Uses Go structs and JSON test HTTP bodies | Replace with RFC records and vectors. |
| Recipient-bound HPKE envelope | Absent | Implement and validate before offer storage. |
| Manifest-bound chunk AAD | Current helper binds transfer/artifact/index/length only | Implement manifest commitment binding and vectors. |
| Durable salt/key/nonce reservation | Random values are generated in process | Reserve durable uniqueness before encryption. |
| Fresh directory and anti-rollback | Static startup policy only | Implement signed directory, checkpoints, rotation, and revocation. |
| Permit/capability/attempt state | Ten-minute bearer session only | Implement short-lived permits, one-time redemption, and fenced attempts. |
| Source-ready acceptance | Offers may be accepted before upload completes | Require immutable complete source before acceptance. |
| Expiry, cancellation, reaping, quotas | Global limits have no lifecycle | Add per-principal limits and a crash-safe reaper. |
| Authenticated direct transport | Test WebRTC helper only | Bind signed transcript/candidates; enforce the RFC in-flight, rate, lifetime, and concurrency limits. |

No item in this table may be marked complete by documentation alone.  Each
requires an implementation change, focused tests, conformance vectors where
applicable, and a reviewed release-evidence record.
