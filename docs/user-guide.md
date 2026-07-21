# Punaro user guide

Punaro is a self-hosted relay layer for agents and people. It has an **alpha,
loopback-hosted text relay**: enrolled machines can advertise local
`agent-mailbox` attachments, send durable text, receive it through a local
adapter, and optionally bridge explicitly mapped Telegram topics. A controlled
v3 attachment data-plane is available to operators who complete its setup, but
it is not yet a released remote service or production attachment system.

## Getting a working system

Punaro has three deliberately separate roles:

- A Linux relay operator installs `punarod`, approves public machine records,
  and, for remote access, protects the loopback origin with Cloudflare Tunnel
  and Access.
- Each machine owner runs the client installer as the user who owns that
  machine's `agent-mailbox`. The installer creates one cryptographic machine
  identity, local adapter service, and optional attachment controller material.
- Agents use their existing local `agent-mailbox` MCP. They do not receive
  relay, Cloudflare, Keychain, or attachment-authority credentials.

The [installation guide](installation.md) is the complete setup path. For a
new remote-capable Linux relay, its server command accepts a public machines
file and Cloudflare Access issuer/audience/JWKS URL together, installs the
local JWKS refresh unit, and can start the relay in one operation. Cloudflare
Tunnel credentials remain separate systemd credentials because they are
secrets. The [operator guide](operator-guide.md) covers that ingress and
ongoing verification.

For a client that may send attachments, use the client installer with an
explicit `both` role. macOS creates a device-only Keychain wrapping key;
Windows creates a DPAPI CurrentUser-protected wrapping key. In both cases the
raw key is never printed or given to an agent, and the public device enrollment
still needs authority approval before attachments can be exchanged.

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

Setting `PUNARO_ATTACHMENTS_ENABLED=true` is expected to fail. Setting
`PUNARO_ATTACHMENT_RELAY_ENABLED=true` also fails closed. This protects you
from mistaking the tested attachment foundation for a released file-transfer
feature.

V3 is deliberately separate: a configured operator can enable
`PUNARO_ATTACHMENT_V3_ENABLED=true` with the private source-store path and the
directory/issuer material in the [operator guide](operator-guide.md). Agents
use holder-signed v3 permits and exact signed operations; the Go adapter client
exposes `IssueV3Permit`, `DoV3Attachment`, and the v3 artifact helpers for
integrations. It never gives an agent a public link, a Telegram file upload, or
access to another machine's mailbox/database. Offer notification and local UI
integration remain application-level workflow: after a successful `offer`, the
sender uses the adapter's durable `OfferNoticeOutbox` (or
`punaro-adapter attachment-notify`) for that same conversation. An incoming
body with the exact `punaro/attachment-offer/v3:` marker can be parsed by
`attachment/v3.DecodeOfferNotice`; it is untrusted discovery data until the
recipient completes fresh directory verification, opens its own HPKE envelope,
and obtains recipient-specific permits. The attachment bytes never travel via
Telegram or the mailbox relay. A provisioned agent may use the controlled
[attachment skill](../skills/punaro-attachment/SKILL.md) for one explicit,
task-owner-approved send or receipt; it is not an automatic download or a
substitute for operator enrollment.

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

Production attachments will not use Telegram as a file relay, create public
download links, fetch URLs, or derive filesystem paths from display names.
Revocation stops new authorized activity but cannot recall bytes already
downloaded. Partial uploads are never downloadable, and filesystem/database
skew is reconciled explicitly. Trusted-relay release gates will be added with
its implementation; the preserved v2/v3 gates cannot authorize production.

The current schema-v11 implementation is intentionally dark. Schema v10 proves
bounded reservation, private durable publication, completion reauthorization,
quota, backup-manifest, and crash-reconciliation behavior. Schema v11 adds
stable message-recipient snapshots and a generation-fenced, capability-checked,
fully verified bounded download service. It still mounts no production upload
or download route and implements no delete operation. Passing those tests does
not make the private blob directory a supported user interface.

Until then, v3 remains only a separately enabled controlled validation surface.
Use the established mailbox and Telegram workflows for text-only
coordination and keep files in an approved storage system. The adapter may use
payload-free WebSocket wake-up hints to trigger an early poll, but reconnecting
and periodic polling remain the correctness mechanism.
