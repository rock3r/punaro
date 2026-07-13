# Punaro security review record

This record distinguishes early design review from implementation review.  It
is not a release approval.  The release authority is
[`docs/security-release-gates.md`](docs/security-release-gates.md).

## Adversarial review — incorporated requirements

- Delivery is at-least-once, with immutable message IDs, sender idempotency,
  recipient-specific leases, lease generations, adapter-side durable dedupe,
  and a dead-letter/retry policy.
- Server-side authorization binds a machine credential to allowed endpoint
  namespaces and evaluates every send, fetch, ack, and notification action.
- Attachment controls discovery/presence, not retroactive redirection of work.
  A concrete endpoint snapshot receives queued work; detach behavior must be
  audited and policy-defined.
- The WebSocket is advisory: no cursor movement, payload, or client-selected
  subscriptions. Reconnect is bounded and single-flight.
- Telegram uses idempotent updates, explicit target selection, user-ID checks,
  and opaque callback handles.
- SQLite requires online-consistent backup, disk-pressure behavior, bounded
  queues, metrics, and restore testing.

## Security review — incorporated requirements

- Two authentication layers are mandatory: validated Cloudflare Access JWT plus
  a revocable, enrolled per-machine cryptographic credential.
- The origin is loopback/private-only and firewall-protected; `cloudflared` is
  the only public ingress. Client-supplied proxy or Cloudflare headers are not
  trusted.
- Membership is deny-by-default and agent message content is inert untrusted
  data, never control-plane input or executable instruction.
- Secrets are separate by scope, injected from protected files/keychains,
  excluded from logs and ordinary backups, and independently revocable.
- Required implementation gates include protocol/property tests, HTTP/WebSocket
  fuzzing, dependency/SBOM and secret scanning, cloudflared integration tests,
  a restore drill, and a device-revocation drill.

## Fresh independent review — 2026-07-13

Three independent, read-only reviews covered protocol, implementation, and
operations.  Their shared conclusion was: no currently reachable attachment
vulnerability because the daemon is fail-closed, but neither the attachment
protocol nor the target production relay is release-ready.

The reviews identified the following release blockers, now represented as
explicit gates rather than implied future work:

- a tracked canonical attachment RFC and conformance vectors;
- recipient envelopes, signed directory freshness/rotation/revocation,
  audience-bound request authentication, and permits/capabilities;
- durable lifecycle/reaping, retry-safe acceptance, per-principal quotas, and
  transport rate/in-flight/transcript/candidate controls;
- a public runtime with direct-origin protections, narrowed secrets, pinned
  build inputs, a scanned/attested release artifact, and tested recovery; and
- an independent cryptography/protocol review after the above is implemented.

The implementation in this revision resolves the immediate health-daemon and
build-context exposures by failing closed on non-loopback addresses, testing
the attachment startup gate, avoiding a broad Docker context and `.env`
injection, hardening the container/unit baselines, and pinning CI inputs.

## Remaining implementation decisions

1. Select Ed25519 request signatures versus mTLS for the machine credential.
2. Specify detach semantics for already queued deliveries: drain, expire, or
   administrator-approved transfer. The default should be drain-or-expire;
   never silently transfer to a different endpoint.
3. Set explicit retention, queue-size, retry, and dead-letter policies before
   enabling message bodies from additional users.
