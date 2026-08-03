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

To enable offline-role invocation, additionally configure
`PUNARO_INVOKER_COMMAND` with an absolute, protected executable owned by the
local operator. Punaro invokes it only as:

```text
COMMAND invoke --invocation-id ID --conversation ID --endpoint ENDPOINT --fence FENCE
```

It receives no message body. It must persist the fence before starting or
attaching the role, treat the same fence as an idempotent no-op after a crash,
and return success only after that durable acceptance. Without this local
runtime configuration the adapter continues normal mail delivery but does not
lease invoke work.

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
`~/Library/LaunchAgents/org.punaro.adapter.plist`. The adapter itself validates
and reads the same owner-only `~/.config/punaro/adapter.env` profile used by
interactive commands, rather than embedding or shell-sourcing credentials in
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
It automatically uses the installed adapter profile. A deliberately supplied
non-empty adapter environment setting overrides its matching profile value;
use `PUNARO_ADAPTER_PROFILE_FILE` only to select another absolute, owner-only
profile.

## Durable conversation roles

Endpoint members keep the existing behavior: membership follows that exact
currently attached mailbox address. To keep a conversation member stable while
an agent process reconnects, create a role member owned by its enrolled machine
instead. The role is a durable identity, not a mailbox address:

Role members may use `send`, `receive`, and `admin`; `invoke` is reserved for
an exact endpoint member because invoking needs a concrete process target.

```sh
punaro-adapter create \
  --creator agent/workstation-review/operator-session \
  --member agent/workstation-review/operator-session:send,receive,admin \
  --role-member '{"role":"role/plan-reviewer","machine_id":"workstation-review","capabilities":["send","receive"]}' \
  --idempotency-key create-review-room-1
```

Whenever the reviewer has a current attached session, renew its explicit
binding before it sends or receives for that role:

```sh
punaro-adapter bind-role \
  --role role/plan-reviewer \
  --session agent/workstation-review/reviewer-session
```

Only the role's configured machine may bind it, and only to one of that
machine's currently advertised sessions. The binding has the same bounded
renewal horizon as endpoint advertisement: later advertisements renew a binding
only for that exact still-owned session. It expires on missed renewal and is
replaced (not inherited) when a new session is bound. After an adapter or relay
restart, advertise the new session and bind the role again. No membership edit
is needed, but a stale session can neither send, receive, nor acknowledge as
the role.

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

## Disposable two-client lifecycle smoke test

For release-candidate validation on macOS, run the disposable smoke test from
an otherwise unused GUI login:

```sh
make test-real-relay-e2e
```

It builds a temporary loopback `punarod`, installs two independent fresh client
homes with the supported client installer, and runs the receiving adapter with
an isolated copy of the installed LaunchAgent definition. Its test-only label,
disposable-profile source, and installed temporary binary path are the only
changes, so it can exercise the supported service lifecycle without colliding
with or inheriting settings from an operator's adapter in the same GUI login.
The test creates and sends a conversation message,
proves an enrolled but unauthorized client cannot lease the receiver endpoint,
waits for and claims/acknowledges the local mailbox delivery, faults the first
relay acknowledgement, restarts the installed receiver service, and verifies
the durable retry completes after the relay's bounded lease-recovery window
without another local handoff. The relay, client keys, mailbox state, and
message input are generated inside a temporary directory and removed at
completion. It prints neither their values nor mailbox contents.

The test's isolated LaunchAgent carries the path to its disposable profile; it
does not alter the user's LaunchAgent environment. The installer first creates
an HTTPS relay profile; the test then redirects only that disposable profile to
its private loopback relay proxy. This does not relax production installation
or trust requirements.
It never stops or replaces an operator's installed adapter. It is intentionally
not a CI job: it exercises the actual local service manager and is independent
of any deployment hostname, credentials, ingress, or operator topology.

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
