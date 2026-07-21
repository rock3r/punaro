# Alpha text-relay onboarding

This guide is for a development rollout of the implemented text relay. It is
not approval to expose a new public route: the public-operations and attachment
release gates remain closed.

## Machine enrollment

For a standard machine, start with the [client installer](installation.md#2-install-one-client-machine). It creates the same exclusive prefix and key below, retains the public enrollment record locally, and deliberately stops before operator approval and service activation. The manual commands remain available for an audited or custom deployment.

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
control. A prefix must end in `/` and authorizes only child aliases: for
example, `agent/workstation-review/agent-a`, not the bare
`agent/workstation-review` label. Add a bare legacy label only through the
explicit `endpoints` exception below.

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
same private environment that starts the adapter. The adapter rejects a partial
pair. Start it with `go run ./cmd/punaro-adapter` during development; the
supplied user service reads the pair from its owner-only environment file.

For a Linux agent machine that should keep its attachment active after logout,
use the supplied user-level `deploy/systemd/user/punaro-adapter.service`
profile. It deliberately runs as the same unprivileged account that owns the
agent and its mailbox state; a privileged system service must never be pointed
at an interactive user's mailbox database. Install the reviewed adapter as
`~/.local/bin/punaro-adapter`, copy the non-secret example to
`~/.config/punaro/adapter.env`, and set both that file and its machine-key file
to mode `0600`. Add that machine's distinct Access client ID and secret only to
the private environment file. The unit limits writable paths to its private
adapter journal and the explicit `agent-mailbox` state path, then starts from
the same session identity as the attached aliases. Install it under
`~/.config/systemd/user/`, run `systemctl --user daemon-reload`, enable it, and
start it with `systemctl --user enable --now punaro-adapter.service`. Use
`loginctl enable-linger <user>` before logout only if the machine should
continue serving after logout. Verify the service is active and the relay
readiness endpoint is healthy. Never reuse the machine key or Access pair on
another machine.

For a macOS agent machine, install the reviewed
`deploy/launchd/punaro-adapter.plist` template as
`~/Library/LaunchAgents/org.punaro.adapter.plist`. It sources the same
owner-only `~/.config/punaro/adapter.env` rather than embedding credentials in
the plist. Validate it with `plutil -lint`, then bootstrap it as the interactive
user with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.punaro.adapter.plist`.
Use `launchctl print gui/$(id -u)/org.punaro.adapter` to verify it is running.
Keep adapter logs in an owner-only state directory configured by the process,
not a shared temporary directory. Boot it out with
`launchctl bootout gui/$(id -u)/org.punaro.adapter` before replacing the
plist. The same per-machine key, Access pair, and mailbox namespace rules
apply; never copy this owner-only environment file to another Mac.

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

## Retired v3 attachment evidence

V2/v3 file transfer is separate from text onboarding and has no production
activation path. Its packages, vectors, RFCs, controller tests, and CLI test
harnesses remain source-level evidence only. `punarod` rejects all former
attachment, directory, and permit settings and mounts none of their routes.
Use `punaro-trusted-attachment` with fixed operator-provisioned trust and
explicit task-owner authorization for supported file operations.

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
- V2/v3 attachment settings are rejected and their routes are unmounted. Their
  source-level protocol evidence is retained but cannot authorize deployment.
