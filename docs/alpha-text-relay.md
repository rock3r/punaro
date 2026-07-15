# Alpha text-relay onboarding

This guide is for a development rollout of the implemented text relay. It is
not approval to expose a new public route: the public-operations and attachment
release gates remain closed.

## Machine enrollment

On each adapter machine, generate an exclusive endpoint namespace and a private
machine key. Use an explicit, machine-scoped `agent/<machine>/` namespace for
the mailbox aliases attached to that machine. Do not enroll a broad client
namespace such as `codex/` or `claude/`: those names are not unique across
machines. The command creates the private file with mode `0600` and prints only
the public record that belongs in the relay configuration:

```sh
go run ./cmd/punaro-keygen \
  --id workstation-review \
  --endpoint-prefix agent/workstation-review/ \
  --private-key-file /secure/service-dir/punaro-machine.key
```

Collect the printed records into `PUNARO_RELAY_MACHINES_JSON` on the relay.
Prefixes must be disjoint; the relay rejects overlapping enrollment to prevent
one machine from claiming another machine's attached session. Never copy a
private key into this JSON, a shell argument, a mailbox message, or source
control.

When an existing mailbox address cannot be moved under the machine-scoped
`agent/<machine>/` namespace, add it as a narrowly delegated exact endpoint
instead of granting its broad client namespace. For example, append only the
specific address to the owning machine's public record:

```json
{"endpoints":["claude/a-specific-session"]}
```

Exact endpoints are compared for equality, not prefix matching. They cannot
overlap an endpoint or endpoint prefix owned by another enrolled machine. This
is an exception for a named legacy session, not a substitute for using
machine-scoped aliases for new onboarding.

## Relay configuration

Run `punarod` as an unprivileged service with a loopback listener and a durable
data directory:

```text
PUNARO_RELAY_ENABLED=true
PUNARO_RELAY_MACHINES_JSON=[public enrollment records]
PUNARO_LISTEN_ADDR=127.0.0.1:8080
PUNARO_DATA_DIR=/var/lib/punaro
```

For a Cloudflare-protected remote route, additionally set the Access issuer,
application audience tag, and JWKS URL. Configure the tunnel origin to require
the Access assertion. The process validates `Cf-Access-Jwt-Assertion` itself;
the tunnel and Access policy are not substitutes for the machine signature.

## Adapter configuration

Create a local `agent-mailbox` group (for example `group/punaro-attached`),
bind machine-scoped aliases such as `agent/workstation-review/agent-a`, and add
those aliases while their agents should be reachable. The adapter polls active
members, renews their relay lease, injects inbound text locally, and only then
acknowledges the relay delivery.

```text
PUNARO_ADAPTER_RELAY_URL=https://relay.example.invalid
PUNARO_MACHINE_ID=workstation-review
PUNARO_MACHINE_PRIVATE_KEY_FILE=/secure/service-dir/punaro-machine.key
PUNARO_ATTACHED_GROUP=group/punaro-attached
PUNARO_ADAPTER_DATA_DIR=/var/lib/punaro-adapter
PUNARO_ADAPTER_POLL_INTERVAL=30s
```

For an Access service-token policy, provision both
`PUNARO_CF_ACCESS_CLIENT_ID` and `PUNARO_CF_ACCESS_CLIENT_SECRET` through the
OS service secret mechanism. The adapter rejects a partial pair. Start the
adapter with `go run ./cmd/punaro-adapter` during development; production
service units are not yet part of the released remote deployment profile.

## Onboard and revoke a machine

Every machine gets one distinct relay enrollment record, one private machine
key, one Access service token, and a non-overlapping `agent/<machine>/`
mailbox namespace. Do not copy a private key or an Access credential between
machines.

1. Generate the enrollment record as shown above and add only its public JSON
   record to `PUNARO_RELAY_MACHINES_JSON` on the relay. Restart the relay and
   verify its readiness endpoint before continuing.
2. On the machine, use the `agent-mailbox` MCP `mailbox_bind` operation to bind
   the explicit alias (for example, `agent/workstation-review/agent-a`). Add it
   to that machine's `group/punaro-attached` group:

   ```sh
   agent-mailbox group add-member \
     --group group/punaro-attached \
     --person agent/workstation-review/agent-a
   ```

3. Create a distinct Cloudflare Access service token and an application policy
   that includes only that token. Inject its client ID and secret through the
   machine's secret mechanism; do not place either in a checked-in env file.
4. Start the adapter. Its first successful poll advertises exactly the active
   attached aliases. Confirm an agent-to-agent text message reaches the local
   mailbox, then acknowledge the mailbox delivery.

This is a manual alpha revocation procedure, not a live control-plane feature.
To revoke a machine, first remove its aliases from `group/punaro-attached` to
stop new relay advertisement. Then remove its public enrollment record from
the relay, revoke/delete its separate Access service token and policy, restart
the relay, and securely erase its machine private key. Verify that requests
signed by the removed machine are rejected and that an already connected
adapter cannot fetch or acknowledge new deliveries. Do not reuse its machine
ID or endpoint prefix until any old endpoint leases have expired or have been
separately purged. Revocation stops future authorization; it cannot recall text
or ciphertext already delivered.

An agent can reply to a conversation it already knows from an inbound envelope:

```sh
punaro-adapter send \
  --conversation CONVERSATION_ID \
  --from agent/workstation-review/session-name \
  --body-file reply.txt \
  --idempotency-key stable-retry-key
```

The explicit idempotency key must be retained for retrying the same logical
reply. The command emits only a message ID and sequence, not the message body.

## Controlled v3 attachment enrollment

V3 attachment validation is separate from text onboarding. In addition to the
normal machine credential, bind exactly one public `attachment_device_id` from
the signed directory to the enrollment record for each participating machine.
Do not bind two machines to one device, and do not treat a mailbox endpoint as
an attachment identity. The relay refuses a permit request unless its enrolled
machine credential is bound to the request holder's directory device.

The sender stages and offers ciphertext via the v3 API, then invokes
`punaro-adapter attachment-notify` (or queues `OfferNoticeOutbox`) with the
exact canonical offer. This persists the notification before the adapter sends
it through the existing conversation; retain a transfer-scoped idempotency key
for that notification. The recipient's normal adapter delivery injects the
bounded `punaro/attachment-offer/v3:` notice into its attached mailbox; its
agent must parse it with `attachment/v3.DecodeOfferNotice` and perform the
fresh directory, HPKE, permit, accept, download, and completion steps locally.
Neither the mailbox nor the Telegram bridge carries file bytes or becomes a
download proxy.

```sh
punaro-adapter attachment-notify \
  --conversation CONVERSATION_ID \
  --from agent/workstation-review/session-name \
  --offer-file canonical-offer.cbor \
  --idempotency-key transfer-notice-TRANSFER_ID
```

If the immediate relay attempt is unavailable, the command exits non-zero but
leaves the exact row in `$PUNARO_ADAPTER_DATA_DIR/attachment-offers.db`; start
or keep the normal adapter running to drain it. Do not delete that database or
reuse its idempotency key with another offer. The private outbox has a strict
64-notice / 2 MiB pending limit including bounded route/idempotency metadata;
repair relay connectivity instead of deleting undelivered entries when
admission is exhausted.

To revoke an attachment participant, remove the directory membership/key or
advance its revocation state and publish the signed snapshot, then remove its
relay enrollment and revoke its Access token as in the preceding section. The
next permit or attachment operation refreshes the directory and fails closed;
the daemon's bounded reaper releases expired state after the short transfer
lifetime. This cannot recall ciphertext already delivered to a recipient.

Create a new explicit conversation from an attached creator endpoint with one
or more declared members:

```sh
punaro-adapter create \
  --creator agent/workstation-review/session-name \
  --member agent/workstation-review/session-name:send,receive,admin \
  --member agent/other-machine/session-name:receive \
  --idempotency-key initial-route-1
```

The owner of each endpoint must currently advertise it, and the creator must
be an attached endpoint on the credentialed machine. Keep the idempotency key
for retrying this exact creation request: the relay returns the original
conversation on an identical retry and rejects a changed request using the
same key.

## Opt-in live wake validation

The opt-in E2E test opens the payload-free WebSocket wake stream, creates a
fresh conversation, and verifies that a wake has only its topic ID and sequence.
It requires an already configured adapter and two machine-scoped attached
aliases; it does not contain any deployment values:

```sh
PUNARO_E2E_SENDER=agent/workstation-review/agent-a \
PUNARO_E2E_RECEIVER=agent/workstation-review/agent-b \
go test -tags=e2e ./cmd/punaro-adapter -run TestE2EPayloadFreeWake
```

When the adapter receives its credentials from an external secret provider,
run that provider's environment wrapper around the test command. A wake is a
best-effort hint only; fetch/lease/ack polling is still authoritative.

## Telegram gateway

The separately enrolled `punaro-telegram` process is described in the
[Telegram gateway guide](telegram-gateway.md). Its gateway endpoint must be a
member of each bridged conversation with `send,receive` rights. It is never a
fallback route for the main chat.

## Current boundaries

- Topic routes are explicit operator state; no automatic picker or target
  discovery is implemented.
- WebSocket hints are best-effort; polling remains correct when a machine
  sleeps or reconnects.
- V2 attachments remain disabled. The distinct v3 runtime is available only
  for controlled validation; its own vector, end-to-end, review, and
  restore/revocation release gates remain closed.
