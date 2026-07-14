# Security release gates

This checklist is the release authority for Punaro.  A checked box requires a
reviewable, committed evidence record under `docs/release-evidence/` that names
the source commit, target platform, exact commands and artifacts, CI run or
attestation, and security approver.  An unchecked box means the corresponding
feature remains unavailable.  CI verifies the current withheld state and gate
syntax; it cannot make a Git commit immutable or establish independent human
approval.  Before any release, protected branches, required CI, a signed
release tag, and a release environment with independent security and operations
approvals are mandatory.  No runtime-exposure change may merge without that
process, a reviewed evidence record, and an explicit release decision.  The
current attachment gate is intentionally **closed**.

## Current source assertions (not release evidence)

- The source rejects every non-literal-loopback listener. The legacy full
  attachment switch still fails closed before a listener is constructed.
- `punarod` can mount only an explicitly configured pre-release v2 relay
  fallback, behind Access (when configured), durable machine replay checks,
  holder/device binding, fresh directory authority, and short-lived permits;
  it has no WebRTC constructor.
- The container context is allow-listed; Compose has no `.env`, port, or network
  and has a read-only root with no Linux capabilities.
- CI source pins Actions and OCI lint/build inputs to immutable revisions.

These are reviewed source assertions, not a published release decision.  A
future artifact release must create a completed record from the
[`release-evidence template`](release-evidence/README.md) before any box is
checked.

## Attachment v2 (closed)

- [ ] Implement the versioned RFC's canonical CBOR maps, algorithm identifiers,
      positive/negative vectors, recipient-bound HPKE envelopes, and durable
      key/salt reservation.
- [ ] Implement a fresh signed device directory, anti-rollback state, key and
      membership rotation, revocation, audience-bound request signatures, and
      shared durable replay protection.
- [ ] Implement source-ready/attempt/capability/permit state with retry-safe
      acceptance, expiry, cancellation, durable reaping, and per-principal
      quotas.
- [ ] Implement signed WebRTC/TURN transcript and candidate authorization plus
      in-flight, rate, connection, and lifetime limits.
- [ ] Add fuzz, property, load, restart, lock/cancellation, revocation, and
      direct-origin tests; produce an SBOM and scanned, attested release image.
- [ ] Complete an independent cryptography/protocol review and an operator
      restore/revocation exercise against the release candidate.

## Public relay and operations (closed)

- [ ] Add an authenticated public relay runtime; it must explicitly validate
      machine credentials and authorization, not trust proxy headers.
- [ ] Deploy Cloudflare Access, firewall/origin isolation, protected secrets,
      encrypted backups, integrity checks, restore exercises, and credential
      revocation drills as executable, tested infrastructure.
- [ ] Validate the systemd and container sandboxes on the target Linux release
      image with `systemd-analyze security` and SQLite WAL smoke tests.
