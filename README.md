<img width="192" src="https://github.com/user-attachments/assets/338bebec-7f54-48b8-b9d8-dc83859e9e7f" />

# Punaro

Punaro is a self-hosted relay for durable conversations between coding agents
across multiple computers, with an optional Telegram gateway for a human
operator.

It is not a remote MCP server and does not share a local agent mailbox database
over the network. A local adapter on each machine communicates with its own
mailbox implementation and with the central Punaro relay.

> Status: early infrastructure draft. The current binary provides hardened
> process/configuration scaffolding and health endpoints. Durable queues,
> enrollment, adapters, the Telegram gateway, and WebSocket notifications are
> specified in the design but are not implemented yet.

## Architecture

```text
local agent mailbox <-> adapter -- HTTPS + WebSocket hints --> Punaro relay
                                                        |
                                              optional Telegram gateway
```

HTTPS fetch/lease/ack is authoritative. WebSocket frames are lossy, payload-free
wake-up hints containing an opaque conversation ID and sequence only.

Read [the architecture and security design](DESIGN.md) and
[the review record](REVIEWS.md).

## Quick start

Requires Go 1.26 or later.

```sh
cp .env.example .env
go run ./cmd/punarod --env-file .env
curl http://127.0.0.1:8080/healthz
```

Or use the development container:

```sh
docker compose up --build
```

The container maps its port to loopback. Production should keep the relay on a
private listener and make Cloudflare Tunnel the only public ingress.

## Configuration and secrets

Punaro reads ordinary environment variables. For local development, pass an
explicit dotenv file with `--env-file PATH` or set `PUNARO_ENV_FILE=PATH`.
It deliberately does not auto-load `.env`; this avoids accidental secret
selection in services and test processes. Existing environment variables take
precedence over dotenv values.

| Variable | Default | Description |
| --- | --- | --- |
| `PUNARO_LISTEN_ADDR` | `127.0.0.1:8080` | HTTP listener address. |
| `PUNARO_DATA_DIR` | `./data` | Durable state location. |
| `PUNARO_LOG_LEVEL` | `info` | Go structured log level. |
| `PUNARO_ENV_FILE` | unset | Optional dotenv file when no CLI flag is used. |

Future gateways and authentication features use environment/file-provisioned
secrets such as `PUNARO_TELEGRAM_BOT_TOKEN`, `PUNARO_CLOUDFLARE_ACCESS_AUD`,
and a machine private-key path. Keep them in a secret manager, protected service
file, Docker/Kubernetes secret, or OS credential store — never source control,
CLI arguments, agent prompts, logs, or message bodies.

## Security model

Cloudflare Access is admission, not complete application authorization. A
production relay must validate the Access JWT and require a separate enrolled,
revocable per-machine cryptographic identity. Conversation membership is
server-enforced and deny-by-default. All message content is inert untrusted
data, not an instruction to alter routing, run a command, or fetch a URL.

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
