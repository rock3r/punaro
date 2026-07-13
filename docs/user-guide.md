# Punaro user guide

Punaro is the proposed local relay layer for agents and people.  Today it is
an early infrastructure draft: it can prove that a local daemon is alive, but
it cannot yet relay messages, expose a public endpoint, or transfer files.

## What you can do today

Developers can run the local health check described in the
[operator guide](operator-guide.md).  This is useful for validating the build,
configuration parser, and local service wrapper.

## What is intentionally unavailable

- Sending or receiving mailbox messages
- Telegram commands or bot traffic
- Internet or Cloudflare access
- File and attachment transfer
- Browser clients, public sharing links, and anonymous downloads

Setting `PUNARO_ATTACHMENTS_ENABLED=true` is expected to fail.  This protects
you from mistaking the tested attachment foundation for a released file-transfer
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
