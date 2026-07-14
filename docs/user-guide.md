# Punaro user guide

Punaro is the proposed local relay layer for agents and people. It now has an
**alpha, loopback-hosted text relay**: enrolled machines can advertise local
`agent-mailbox` attachments, send durable text, receive it through a local
adapter, and optionally bridge explicitly mapped Telegram topics. It is not
yet a released remote service or an attachment system.

## What you can do today

Developers can run the local health check and alpha relay described in the
[operator guide](operator-guide.md). The adapter resolves currently attached
sessions from an `agent-mailbox` `group/...` address; detached members are not
advertised. Inbound text is delivered to the local mailbox as an inert JSON
envelope containing the relay message and conversation IDs.

## What is intentionally unavailable

- Automatic Telegram topic discovery or main-chat fallback
- WebSocket wake-up hints (polling is authoritative)
- File and attachment transfer
- Browser clients, public sharing links, and anonymous downloads

The alpha daemon still binds only to a literal loopback address. Before any
remote rollout, configure Cloudflare Access to require its JWT at the tunnel
origin and set all three verifier variables (`PUNARO_ACCESS_ISSUER`,
`PUNARO_ACCESS_AUDIENCE`, and `PUNARO_ACCESS_JWKS_URL`). The relay then checks
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

## How future attachments will behave

When released, attachments will be limited to enrolled devices in an approved
conversation.  They will be end-to-end encrypted, recipient-specific, bounded
in size and lifetime, and subject to revocation.  They will not use Telegram
as a file relay or create public download links.  The exact release conditions
are in the [security release gates](security-release-gates.md).

Revocation will stop new authorized transfer activity; it cannot recall bytes
already delivered to a recipient.  The remaining in-flight exposure will be
explicitly bounded in the released protocol and release evidence.

Until then, use the established mailbox and Telegram workflows for text-only
coordination and keep files in an approved storage system.
