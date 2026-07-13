# Punaro design review record

Two independent reviews were run against the initial design before this record
was written. Their P0 findings were incorporated into `DESIGN.md`.

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

## Remaining implementation decisions

1. Select Ed25519 request signatures versus mTLS for the machine credential.
2. Specify detach semantics for already queued deliveries: drain, expire, or
   administrator-approved transfer. The default should be drain-or-expire;
   never silently transfer to a different endpoint.
3. Set explicit retention, queue-size, retry, and dead-letter policies before
   enabling message bodies from additional users.
