<img width="192" src="https://github.com/user-attachments/assets/338bebec-7f54-48b8-b9d8-dc83859e9e7f" />

# Punaro

Punaro is a self-hosted relay for durable conversations between coding agents
across multiple computers, with an optional Telegram gateway for a human
operator.

It is not a remote MCP server and does not share a local agent mailbox database
over the network. A local adapter on each machine communicates with its own
mailbox implementation and with the central Punaro relay.

> Status: alpha text-relay foundation. Enrolled adapters can exchange durable
> text through the loopback relay, with signed requests, payload-free wake
> hints, local `agent-mailbox` handoff, and a separately enrolled Telegram
> gateway process. Public rollout and attachment transfer remain closed by the
> release gates.

## Architecture

```text
local agent mailbox <-> adapter -- HTTPS + WebSocket hints --> Punaro relay
                                                        |
                                              optional Telegram gateway
```

HTTPS fetch/lease/ack is authoritative. WebSocket frames are lossy, payload-free
wake-up hints containing an opaque conversation ID and sequence only.

Read the [architecture and security design](DESIGN.md),
[user guide](docs/user-guide.md), [operator guide](docs/operator-guide.md),
[alpha text-relay onboarding](docs/alpha-text-relay.md),
[Telegram gateway guide](docs/telegram-gateway.md),
[attachment RFC](docs/attachments-v2-rfc.md),
[security release gates](docs/security-release-gates.md), and
[review record](REVIEWS.md).

## Quick start

Requires Go 1.26 or later.

```sh
cp .env.example .env
go run ./cmd/punarod --env-file .env
curl http://127.0.0.1:8080/healthz
```

The development container is a hardened build/run baseline:

```sh
docker compose up --build
```

It deliberately publishes no port and does not load `.env`.  It is not a
public deployment. See the operator guide before using containers or systemd.

## Configuration and secrets

Punaro reads ordinary environment variables. For local development, pass an
explicit dotenv file with `--env-file PATH` or set `PUNARO_ENV_FILE=PATH`.
It deliberately does not auto-load `.env`; this avoids accidental secret
selection in services and test processes. Existing environment variables take
precedence over dotenv values.

| Variable | Default | Description |
| --- | --- | --- |
| `PUNARO_LISTEN_ADDR` | `127.0.0.1:8080` | Loopback-only HTTP listener address. |
| `PUNARO_DATA_DIR` | `./data` | Relay SQLite state location when `PUNARO_RELAY_ENABLED=true`. |
| `PUNARO_LOG_LEVEL` | `info` | Validated reserved setting; current standard logging does not filter by it. |
| `PUNARO_ENV_FILE` | unset | Optional dotenv file when no CLI flag is used. |
| `PUNARO_RELAY_ENABLED` | `false` | Enables the loopback text relay; requires public machine enrollment records. |
| `PUNARO_RELAY_MACHINES_JSON` | unset | Explicit public-key machine enrollment records for the alpha relay. |
| `PUNARO_ATTACHMENTS_ENABLED` | `false` | Reserved for attachment v2; the daemon fails closed if set until the remaining release gates are implemented. |
| `PUNARO_ATTACHMENT_DEVICE_KEYS_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |
| `PUNARO_ATTACHMENT_MEMBERSHIP_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |

The optional `punaro-telegram` process takes its bot token from
`PUNARO_TELEGRAM_BOT_TOKEN`; use an injected environment variable, protected
service environment file, Docker/Kubernetes secret, or OS credential store.
Never place it in source control, a CLI argument, an agent prompt, logs, or a
message body. See the [Telegram gateway guide](docs/telegram-gateway.md).

## Security model

Cloudflare Access is optional admission, not complete application authorization.
When configured, the relay validates its JWT and also requires a separate
enrolled per-machine cryptographic identity. Conversation membership is
server-enforced and deny-by-default. All message content remains inert
untrusted data, not an instruction to alter routing, run a command, or fetch a
URL.

See `DESIGN.md` for required origin isolation, delivery semantics, and
adversarial test gates before remote exposure.

## Development

Punaro follows a strict test-first discipline. See [AGENTS.md](AGENTS.md) for
the required red-green-refactor workflow, security invariants, and handoff
rules.

```sh
make ci
```

The Makefile also exposes individual `test`, `test-race`, `staticcheck`,
`security`, `dockerfile-lint`, and `workflow-lint` targets.

## License

MIT. See [LICENSE](LICENSE).
