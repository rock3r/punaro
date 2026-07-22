# Punaro user guide

Punaro is a self-hosted relay layer for agents and people. It has an **alpha,
loopback-hosted text relay**: enrolled machines can advertise local
`agent-mailbox` attachments, send durable text, receive it through a local
adapter, and optionally bridge explicitly mapped Telegram topics. Attachments
use the authenticated trusted-relay surface and native client; the old v2/v3
data plane is retired from production.

## Getting a working system

Punaro has three deliberately separate roles:

- A Linux relay operator installs `punarod`, approves public machine records,
  and, for remote access, protects the loopback origin with Cloudflare Tunnel
  and Access.
- Each machine owner runs the client installer as the user who owns that
  machine's `agent-mailbox`. The installer creates one cryptographic machine
  identity, local adapter service, and the trusted-attachment client.
- Agents use their existing local `agent-mailbox` MCP. They do not receive
  relay, Cloudflare, Keychain, or attachment-authority credentials.

The [installation guide](installation.md) is the complete setup path. For a
new remote-capable Linux relay, its server command accepts a public machines
file and Cloudflare Access issuer/audience/JWKS URL together, installs the
local JWKS refresh unit, and can start the relay in one operation. Cloudflare
Tunnel credentials remain separate systemd credentials because they are
secrets. The [operator guide](operator-guide.md) covers that ingress and
ongoing verification.

For a client that may use attachments, complete ordinary device enrollment,
then have the operator provision its protected credential file, fixed trusted
origin, project UUID, and safe download root. The installer never reads or
prints the credential.

On macOS and Linux the installer also provides `punaro-memory` for an already
enabled native memory API. It is deliberately stateless: every command names
the fixed HTTPS origin, protected credential file, project or resolver input,
and any required idempotency key and strong ETag. It never discovers Git state,
stores a profile, retries, queues writes, falls back to local memory, or accepts
memory content from stdin. See the
[operator guide](operator-guide.md#stateless-native-memory-client).

## What you can do today

Developers can run the local health check and alpha relay described in the
[operator guide](operator-guide.md). The adapter resolves currently attached
sessions from an `agent-mailbox` `group/...` address; detached members are not
advertised. Inbound text is delivered to the local mailbox as an inert JSON
envelope containing the relay message and conversation IDs.

## What is intentionally unavailable

- Automatic Telegram topic discovery or main-chat fallback
- Automatic or unattended file transfer workflow
- Browser clients, public sharing links, and anonymous downloads

The alpha daemon still binds only to a literal loopback address. Before any
remote rollout, configure Cloudflare Access to require its JWT at the tunnel
origin and set `PUNARO_ACCESS_ISSUER`, `PUNARO_ACCESS_AUDIENCE`, and exactly
one of `PUNARO_ACCESS_JWKS_URL` or `PUNARO_ACCESS_JWKS_FILE`. The relay then checks
the Access JWT as well as every machine's signed request. This implementation
work is not, by itself, a completed public-release decision; follow the
[security release gates](security-release-gates.md).

The optional Telegram process is separately enrolled and binds one exact bot
topic to one conversation. It validates the allowed user ID even if BotFather
or chat settings already restrict access. See the [Telegram gateway guide](telegram-gateway.md)
for safe setup, durable retry behavior, and its at-least-once external-send
boundary.

Every legacy v2/v3 attachment, directory, or permit environment variable is
rejected at startup, including empty values and `false`. The old routes are not
mounted and their binaries are not shipped in the production image. The code,
vectors, RFCs, and tests remain only as experimental evidence. Use the
[attachment skill](../skills/punaro-attachment/SKILL.md) with
`punaro-trusted-attachment` for one explicitly authorized operation.

## How production attachments will behave

The accepted production direction is a conventional trusted relay over
authenticated TLS, described in the
[platform and Big Brain plan](big-brain-plan.md#trusted-relay-attachments).
Punaro's operator and server may read stored bytes; end-to-end confidentiality
from them is not promised. An authorized sender reserves bounded capacity,
uploads an exact size and digest, and publishes an immutable artifact only
after durable finalization and reauthorization. The message append transaction
snapshots authorized recipients. Downloads remain authenticated, bounded, and
digest-verified, with safe no-replace client finalization.

Production attachments do not use Telegram as a file relay, create public
download links, fetch URLs, or derive filesystem paths from display names.
Revocation stops new authorized activity but cannot recall bytes already
downloaded. Partial uploads are never downloadable, and filesystem/database
skew is reconciled explicitly. Trusted-relay release gates will be added with
its implementation; the preserved v2/v3 gates cannot authorize production.

The schema-v13 server lifecycle is complete. Schema v10 proves
bounded reservation, private durable publication, completion reauthorization,
quota, backup-manifest, and crash-reconciliation behavior. Schema v11 adds
stable message-recipient snapshots and a generation-fenced, capability-checked,
fully verified bounded download service. Schema v12 adds authorized
tombstone-first deletion, delayed backup-fenced physical GC, exact-once quota
release, and bounded restore-skew cleanup. Schema v13 serializes exact device
credential authority with READY publication. M-12 exposes that lifecycle only
through the separately enabled authenticated trusted-relay routes and the
`punaro-trusted-attachment` native client. The client resumes a stable send by
repeating the same idempotency key, verifies every received byte before making
it visible, contains output beneath an already-open safe download root, and
never replaces an existing name. The private blob directory is never a user
interface, and an older restore may resurrect a later deletion.

V2/v3 retirement is complete: there is no production activation path. The
adapter may use
payload-free WebSocket wake-up hints to trigger an early poll, but reconnecting
and periodic polling remain the correctness mechanism.
