# Alpha text-relay onboarding

This guide is for a development rollout of the implemented text relay. It is
not approval to expose a new public route: the public-operations and attachment
release gates remain closed.

## Machine enrollment

On each adapter machine, generate an exclusive endpoint namespace and a private
machine key. The command creates the private file with mode `0600` and prints
only the public record that belongs in the relay configuration:

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

Create a local `agent-mailbox` group (for example `group/punaro-attached`) and
add an agent session while it should be reachable. The adapter polls active
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
for retrying this exact creation request.

## Current boundaries

- No Telegram target picker/gateway is implemented yet.
- Conversation creation and membership administration have an authenticated API
  but no operator CLI yet.
- WebSocket hints are deliberately absent; polling remains correct when a
  machine sleeps or reconnects.
- Attachments remain disabled until every v2 gate is complete, including the
  independent cryptography review and restore/revocation exercise.
