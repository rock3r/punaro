<img width="192" src="https://github.com/user-attachments/assets/338bebec-7f54-48b8-b9d8-dc83859e9e7f" />

# Punaro

Punaro is a self-hosted relay for durable conversations between coding agents
across multiple computers, with an optional Telegram gateway for a human
operator.

It is not a remote MCP server and does not share a local agent mailbox database
over the network. A local adapter on each machine communicates with its own
mailbox implementation and with the central Punaro relay.

> Status: health-only infrastructure draft. The daemon serves local health
> checks only. Messaging, adapters, Telegram, public ingress, WebSocket hints,
> and attachments are specified but unavailable. Attachment enablement exits
> before an HTTP listener starts.

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
| `PUNARO_DATA_DIR` | `./data` | Reserved state location; the health daemon does not persist data yet. |
| `PUNARO_LOG_LEVEL` | `info` | Validated reserved setting; current standard logging does not filter by it. |
| `PUNARO_ENV_FILE` | unset | Optional dotenv file when no CLI flag is used. |
| `PUNARO_ATTACHMENTS_ENABLED` | `false` | Reserved for attachment v2; the daemon fails closed if set until the remaining release gates are implemented. |
| `PUNARO_ATTACHMENT_DEVICE_KEYS_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |
| `PUNARO_ATTACHMENT_MEMBERSHIP_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |

Future gateways and authentication features will use narrowly scoped
environment/file-provisioned secrets. They are not accepted by the current
daemon. Keep all future credentials in a secret manager, protected service
file, Docker/Kubernetes secret, or OS credential store — never source control,
CLI arguments, agent prompts, logs, or message bodies.

## Security model

Cloudflare Access is planned admission, not complete application authorization.
A future production relay must validate the Access JWT and require a separate
enrolled, revocable per-machine cryptographic identity. Conversation membership
will be server-enforced and deny-by-default. All message content must remain
inert untrusted data, not an instruction to alter routing, run a command, or
fetch a URL.

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
