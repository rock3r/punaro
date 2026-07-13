# Telegram gateway

`punaro-telegram` is a separately enrolled bridge between one Telegram bot and
the central Punaro relay. It deliberately does not access an agent-mailbox
database. It uses a single explicitly configured gateway endpoint, so each
Telegram topic maps to exactly one Punaro conversation.

This is alpha text-relay functionality. Run it only behind the same protected
loopback relay and origin controls described in [the operator guide](operator-guide.md).
Attachment transfer remains unavailable.

## Enroll the gateway

Generate a dedicated key and namespace on the gateway host. Do not reuse an
agent machine key:

```sh
go run ./cmd/punaro-keygen \
  --id telegram-gateway \
  --endpoint-prefix telegram/ \
  --private-key-file /secure/service-dir/punaro-telegram.key
```

Add the printed public record, and only the public record, to the relay's
machine enrollment configuration. Start the gateway before creating a bridged
conversation, so its endpoint is actively attached.

## Configure and run

Provision values through your usual secret mechanism. The following names are
illustrative and contain no deployment identity or secret values:

```text
PUNARO_ADAPTER_RELAY_URL=https://relay.example.invalid
PUNARO_MACHINE_ID=telegram-gateway
PUNARO_MACHINE_PRIVATE_KEY_FILE=/secure/service-dir/punaro-telegram.key
PUNARO_TELEGRAM_GATEWAY_ENDPOINT=telegram/primary
PUNARO_TELEGRAM_STATE_DIR=/var/lib/punaro-telegram
PUNARO_TELEGRAM_ALLOWED_USER_ID=your-telegram-numeric-user-id
PUNARO_TELEGRAM_BOT_TOKEN=injected-secret
```

For a Cloudflare Access service-token policy, additionally provision both
`PUNARO_CF_ACCESS_CLIENT_ID` and `PUNARO_CF_ACCESS_CLIENT_SECRET`. A partial
pair is rejected. `PUNARO_TELEGRAM_API_URL` is optional and defaults to the
official HTTPS Bot API.

Run `punaro-telegram` with no arguments. The process long-polls only `message`
updates, checks the numeric user ID itself, renews the gateway endpoint lease,
and fetches durable relay replies. It does not log tokens, Access headers,
message text, or Bot API response bodies.

## Bind a topic to a conversation

Create the conversation with an attached agent endpoint and the attached
Telegram endpoint. The agent needs `send,receive,admin`; the Telegram endpoint
needs `send,receive`:

```sh
punaro-adapter create \
  --creator agent/workstation/session \
  --member agent/workstation/session:send,receive,admin \
  --member telegram/primary:send,receive \
  --idempotency-key create-with-telegram-1
```

Persist the exact topic-to-conversation mapping:

```sh
punaro-telegram route \
  --chat-id CHAT_ID \
  --thread-id MESSAGE_THREAD_ID \
  --conversation CONVERSATION_ID
```

The route command rejects missing thread IDs, and durable state rejects mapping
one conversation to multiple topics. There is no main-chat fallback. Incoming
questions use the Telegram update ID as the durable relay idempotency key. A
failed submission is retried; a crash after submission is safely deduplicated
by the relay.

Outgoing agent replies are sent using Telegram's `sendRichMessage` to that
exact `message_thread_id`. The bridge renders opaque agent content as escaped
HTML, disables automatic entity detection, and asks Telegram to protect
content. Telegram has no send-idempotency key, therefore this external boundary
is explicitly at-least-once: a crash after Telegram accepts a reply but before
relay acknowledgement can repeat that reply on recovery.

Telegram Bot API rich messages support structured HTML/Markdown content,
topic-bound delivery via `message_thread_id`, and up to 32,768 UTF-8 characters
per rich message. Punaro uses only its minimal safe subset and splits an
oversized reply instead of turning agent text into bot control input.
