# Telegram gateway

`punaro-telegram` is a separately enrolled bridge between one Telegram bot and
the central Punaro relay. It deliberately does not access an agent-mailbox
database. A Punaro conversation **is** the topic: claiming it creates one
private-chat forum topic, persists one `topic_routes` row, and materializes the
built-in participant `user-telegram`. Agents send to that label. They never
choose a Telegram thread.

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
PUNARO_TELEGRAM_GATEWAY_ENDPOINT=telegram/primary
PUNARO_TELEGRAM_STATE_DIR=/var/lib/punaro-telegram
PUNARO_TELEGRAM_ALLOWED_USER_ID=your-telegram-numeric-user-id
PUNARO_TELEGRAM_BOT_TOKEN_FILE=/run/credentials/punaro-telegram.service/telegram-bot-token
PUNARO_TELEGRAM_ACCESS_TOKEN_FILE=/run/credentials/punaro-telegram.service/telegram-access
```

The bot-token file contains only the token. The Access-token file contains
exactly these two lines, with no shell expansion or other settings:

```text
PUNARO_CF_ACCESS_CLIENT_ID=service-token-client-id
PUNARO_CF_ACCESS_CLIENT_SECRET=service-token-client-secret
```

Both credential files must be private regular files (not symlinks). The binary
rejects a group/world-readable file, multiple sources for either credential,
or a partial Access pair. `PUNARO_TELEGRAM_API_URL` is optional and defaults to
the official HTTPS Bot API; its URL is required to be an HTTPS origin without
credentials, path, query, or fragment.

For a Linux deployment, install `deploy/systemd/punaro-telegram.service`, copy
`deploy/systemd/punaro-telegram.env.example` to `/etc/punaro/telegram.env`, and
place the bot token, Access pair, and machine private key under
`/etc/punaro/credentials` as root-owned `0600` files. The unit supplies all
three using systemd `LoadCredential`, so secrets do not appear in the
environment file, process arguments, or repository. Run `systemctl daemon-reload`, then enable
and start `punaro-telegram`; inspect `systemctl status` and redact logs before
sharing them. Run `systemd-analyze security punaro-telegram.service` on the
target OS and include the result in deployment evidence.

On Windows, install the gateway at
`%LOCALAPPDATA%\Punaro\bin\punaro-telegram.exe` and provision the `Punaro
Telegram` scheduled task with exactly that executable as its sole action and no
arguments. Doctor reads the task XML, verifies the exact native executable,
queries its enabled/running/last-result/restart state, and executes `version`
through that same validated path. A task bound to any other binary fails the
service binding and running-release checks.

Before starting long polling, inspect the bot's webhook status with the Bot
API `getWebhookInfo`. Telegram does not allow `getUpdates` while an outgoing
webhook is configured. Punaro never removes or changes a webhook automatically:
an operator must intentionally migrate the bot or use a bot dedicated to this
gateway.

`PUNARO_TELEGRAM_GATEWAY_ENDPOINT` must be exactly `telegram/primary`. The
binary rejects any other enrolled name so the env value cannot drift from the
relay constant.

Run `punaro-telegram` with no arguments. After start it calls `setMyCommands`
once, then long-polls `message` and `callback_query` updates, checks the
numeric user ID itself, renews the gateway endpoint lease, resumes incomplete
local claim executions, polls pending reservations, and fetches durable
relay replies. It does not log tokens, Access headers, message text, raw
`callback_data`, or Bot API response bodies.

## Operator commands

Operator commands are recognized only from Telegram `bot_command` entities:

- `/start` replies with a short help sentence that mentions `/list`.
- `/list` asks the relay for the last 10 unclaimed named topics and replies in
  the private chat with one inline-keyboard row per topic. Button labels are
  display names (truncated to 64 characters). `callback_data` is a one-time raw
  256-bit hex token; the gateway stores SHA-256(token) with a 15-minute TTL and
  evicts to 100 outstanding. Conversation ids never appear in Telegram.

Ordinary main-chat text stays inert. A `/list` tap persists a local
`claim_executions` row at `reserved`, then consumes the token in the same
transaction. Invalid, expired, or replayed tokens stay inert and receive a
generic failure toast. After the reserved row is durable, the gateway answers
the tap, advances the poll offset, and runs claim execution (resumed on every
`SyncOnce` if that cycle fails).

Claim execution reserves on the relay as `telegram/primary` with
`gateway-claim-<conversation-id>` unless the row was pulled from
`POST /v1/telegram/claims/pending` (already pending). It then calls
`createForumTopic` once, persists the returned `message_thread_id` and creation
`chat_id` immediately, writes `topic_routes`, and completes the claim. It never
calls `getForumTopic`. Resume of `topic_created` binds that stored pair; a
changed allowed user fails closed. If the thread id is already stored, it is
reused only for the same chat. Completing a claim inserts
`telegram/primary` with send|receive and materializes `user-telegram`.

## Create and claim a topic

Create a named conversation. Do **not** pass `--member telegram/primary` on
this path; claim adds that membership:

```sh
punaro-adapter create \
  --name "How is it going" \
  --creator agent/workstation/session \
  --member agent/workstation/session:send,receive,admin \
  --idempotency-key create-named-1
```

The operator then claims it from Telegram with `/list` and a button tap.
An attached member session may instead reserve:

```sh
punaro-adapter claim \
  --conversation CONVERSATION_ID \
  --from agent/workstation/session \
  --idempotency-key claim-<conversation-id>
```

The gateway completes that reservation on the next `SyncOnce` poll of pending
claims. A retry that returns `status=complete` is success. Until complete,
`--to user-telegram` fails closed.

A session may occupy at most one named or claimed topic (direct membership or a
live role binding). Several sessions may share one topic. Exactly
`telegram/primary` is exempt so the gateway can occupy every claimed room.
Unnamed, unclaimed rooms stay many-to-many.

## Agent send path

Pings and replies to the human are ordinary Punaro sends:

```sh
punaro-adapter send \
  --to user-telegram \
  --from agent/workstation/session \
  --body-file REPLY_FILE \
  --idempotency-key REPLY_KEY
```

`--to user-telegram` omits `--conversation`. The adapter resolves the session's
sole claimed topic. If `--conversation` is also supplied it must match that
topic. Existing `send --conversation --from` remains for same-topic broadcast
and `--target-role`. Broadcast after claim also reaches `telegram/primary`
because that endpoint has receive; `--to user-telegram` is the documented
product path.

Agents never choose Telegram topics, pass a thread or chat id, or call the Bot
API. `telegram_thread_id` on a mailbox envelope is inbound diagnostic metadata
only.

## Read-only readiness

Run `punaro-telegram doctor --timeout 15s` before release evidence and after a
gateway service, polling, relay, Access, Bot API, route, topic, or retry failure.
It uses `getMe` plus signed non-consuming relay/notification probes and a
read-only bounded SQLite snapshot. It never polls an update, advances an
offset, creates a topic, sends a message, leases or acknowledges relay mail, or
prints provider responses. The complete SQLite open and inspection runs in a
deadline-killable child helper, so stalled state storage cannot extend the
advertised total timeout. See [doctor.md](doctor.md) for exit semantics and
the stable Telegram check registry.

## Retire the Bot API side channel

`telegram-major-updates` lives outside this repository. It is not a production
sender. Do not run `scripts/send_major_update.py` against a Punaro-claimed bot,
do not pass a Telegram thread id, and do not give agent machines a bot token.
Replies to those side-channel pings land in the main chat or an unbound topic
and never become mailbox mail. Use `punaro-reply` /
`punaro-adapter send --to user-telegram` instead.

## Refresh installed agent guidance

`scripts/install-agent-guidance.sh` appends a marked `AGENTS.md` block that
teaches `--to user-telegram` and copies `punaro-mailbox`, `punaro-reply`, and
`punaro-attachment` only when the destination is absent. If
`.agents/skills/punaro-reply` already exists and differs, the installer refuses
to overwrite it. Operators must refresh existing project copies by hand:
archive or remove the old skill directory and, if the marked guidance block
predates `--to user-telegram`, remove only that marked block, then rerun
`./scripts/install-agent-guidance.sh --directory PROJECT`.

## Adopt the two live routes

The live private-chat topics already have `topic_routes` rows. Adopt them; do
not recreate Telegram threads. Both rooms currently share
`role/telegram-codex`. Naming or claiming the second room while that role
remains a member of both is a conflict.

Fence-legal order (operator chooses which topic **keeps**
`role/telegram-codex`):

1. **Rename the keeper first**, while the non-keeper is still unnamed:

   ```sh
   punaro-adapter rename \
     --conversation KEEPER_CONVERSATION_ID \
     --actor agent/punaro-studio/validation \
     --name "Keeper label" \
     --idempotency-key rename-keeper-1
   ```

2. **Prepare the still-unnamed non-keeper** on the relay host as the relay
   service account. This one-shot opens the local SQLite mail store. It does
   not talk to Telegram or the relay HTTP API, and it does not grant
   `telegram/primary` admin:

   ```sh
   punaro-relay-adopt-prepare \
     --relay-db /var/lib/punaro/relay.db \
     --keeper KEEPER_CONVERSATION_ID \
     --non-keeper NON_KEEPER_CONVERSATION_ID \
     --non-keeper-name "Non-keeper label" \
     --drop-role role/telegram-codex \
     --yes
   ```

3. **Adopt both live conversations** without creating topics:

   ```sh
   punaro-telegram adopt --conversation dae86ecc-05ff-4431-967a-584e2cd82916
   punaro-telegram adopt --conversation e5c269b6-7e4c-450d-82bb-c25209096c10
   ```

   These are thread `795446` and thread `795625`. Adopt requires a display
   name and an existing `topic_routes` row. It reserves as `telegram/primary`
   with `adopt-<conversation-id>`, records the local execution at
   `route_persisted`, and completes. A reserve that already returns
   `status=complete` is success. It never calls `createForumTopic`.

4. Confirm `sendRichMessage` still hits threads `795446` and `795625`. Renew
   `role/telegram-codex` onto `agent/punaro-studio/validation` and send
   `--to user-telegram` from that session into the **keeper** topic only.

If adopt is skipped, those two threads keep working as today (route +
broadcast to a conversation that already includes `telegram/primary`). They
will not have `user-telegram` until complete runs; `--to user-telegram` fails
closed. `/list` hides them once they are named and claimed, so keeper-rename,
prepare, and adopt must be one window.

## Emergency remapper

`punaro-telegram route` remains as an emergency remapper after adopt. It is
not the product bind path:

```sh
punaro-telegram route \
  --chat-id CHAT_ID \
  --thread-id MESSAGE_THREAD_ID \
  --conversation CONVERSATION_ID
```

The route command rejects missing thread IDs, mapping a conversation that
already has a completed, routed, topic-created, or adopting claim, or stealing
a `(chat_id, thread_id)` already bound to a claimed conversation, including
`creating`. Unthreaded `creating` (createForumTopic succeeded or was ambiguous,
but no thread id was stored) can be bound to a known thread so resume completes
without a second create. Durable state also rejects mapping one conversation
to multiple topics. There is no main-chat fallback.

## Inbound and outbound routing

Incoming questions use the Telegram update ID as the durable relay idempotency
key and are submitted on `telegram-inbound` as `user-telegram`. Network, 5xx,
and other retryable submission failures leave the update pending; a crash after
submission is safely deduplicated by the relay. A relay 403 or 404 that echoes
the signed request nonce is a terminal pre-append rejection, so the gateway
records the update as processed, emits only a content-free
`telegram_update_dropped` event, continues the page, and carries the terminal
inbound outcome into the durable gateway-health record. An intermediary 403 or
404 without that relay proof stays pending for retry. Unauthorized, unsupported
or non-text, and unbound-topic updates are also
durably skipped, including message-less update IDs returned by Telegram, so
none can stall the polling offset after a restart. They are never routed by
inference. Replies resolve `reply_to_message` through a local 10,000-row
`telegram_outbound` map of Telegram `message_id` to Punaro identities; a miss
delivers the text without `in_reply_to_*`.

Outgoing agent replies are sent using Telegram's `sendRichMessage` to that
exact `message_thread_id` from `topic_routes`. `SendDelivery` stays route-based
through adopt soak. A missing route or a route for another chat fails closed
and leaves the delivery unacknowledged so restoring or repairing local route
state can recover it. A malformed delivery or completed Telegram 4xx response
other than 401 and 429 is terminal: the bridge emits only a content-free
`telegram_send_dropped` event, acknowledges that poison delivery, and continues
later deliveries. A successful dropped acknowledgement advances the outbound
liveness clock and carries the terminal outbound outcome into the durable
gateway-health record; an acknowledgement failure remains an explicit blocked
ack-phase cycle. A deleted Telegram thread therefore fails closed and is
dropped; repair the explicit route rather than recreating a thread
automatically. Empty cycles do not clear either terminal health outcome; a
successful inbound submission or outbound send clears only failures recorded
for that same conversation target. On first open after upgrading an older
aggregate ledger, Punaro conservatively creates one recovery marker per known
route; each route must demonstrate a successful operation before the historical
terminal state clears. Telegram
401, 429, 5xx, and network failures leave the delivery
unacknowledged for retry. The returned `message_id` is stored in the outbound
map. The bridge renders opaque agent content as escaped
HTML, disables automatic entity detection, and asks Telegram to protect
content. Telegram has no send-idempotency key, therefore this external boundary
is explicitly at-least-once: a crash after Telegram accepts a reply but before
relay acknowledgement can repeat that reply on recovery.

Terminal inbound rejection evidence is committed in the same SQLite
transaction that consumes the Telegram update. Terminal outbound evidence is
staged idempotently by relay delivery ID before acknowledgement; a repaired
target is cleared locally before its successful delivery is acknowledged.
Doctor reads these target ledgers directly, so a process crash between an
external acknowledgement and the later aggregate cycle record cannot hide a
dropped item or strand a completed recovery.

Telegram Bot API rich messages support structured HTML and Markdown variants,
and `sendRichMessage` accepts a `message_thread_id` for a forum topic. Punaro
uses only a minimal escaped-HTML subset, disables automatic entity detection,
and imposes its own 32 KiB rendered-message bound, splitting an oversized reply
instead of turning agent text into bot control input. See Telegram's
[rich-message schema](https://core.telegram.org/bots/api#inputrichmessage),
[formatting options](https://core.telegram.org/bots/api#formatting-options), and
[`getWebhookInfo`](https://core.telegram.org/bots/api#getwebhookinfo) docs.
