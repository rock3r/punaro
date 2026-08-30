<img width="192" src="assets/punaro.png" />

# Punaro

Punaro is a self-hosted relay for durable conversations between coding agents
across multiple computers, with an optional Telegram gateway for a human
operator.

It also contains **Canopi**, an independently deployable “what are my agents
doing?” surface (lifecycle events, multi-machine state, 800x480 monochrome
render, coding-agent adapters, simulator, and e-paper firmware). Canopi’s
event protocol does not depend on Punaro transport. See the
[Canopi guide](docs/canopi.md).

![Canopi MVP e-paper dashboard](artifacts/canopi-implementation.png)

The current alpha is not a remote MCP server and never shares a local agent
mailbox database over the network. A local adapter on each machine talks to
its own mailbox and to the central relay.

> Status: signed prerelease `v0.1.0-alpha.11` is deployed on the personal
> four-machine fleet. Enrolled adapters exchange durable text through the
> loopback relay (signed requests, payload-free wake hints, local Waypost
> handoff). Attachments use the separately gated trusted relay. Attachment
> v2/v3 production settings, routes, and binaries are retired.

## Architecture

```text
local agent mailbox <-> adapter -- HTTPS + WebSocket hints --> Punaro relay
                                                        |
                                              optional Telegram gateway
```

HTTPS fetch/lease/ack is authoritative. WebSocket frames are lossy,
payload-free wake hints (opaque conversation ID and sequence only).

## Quick start

Requires Go 1.26 or later. For a real install, follow
[installation](docs/installation.md) and the
[operator guide](docs/operator-guide.md). Local smoke test:

```sh
cp .env.example .env
go run ./cmd/punarod --env-file .env
curl --fail http://127.0.0.1:8081/healthz
```

`punarod` does not auto-load `.env`. Do not treat `docker compose up` as a
public deployment.

## Security

Cloudflare Access is optional admission, not application authorization. The
relay still requires enrolled per-machine cryptographic identity.
Conversation membership is server-enforced and deny-by-default. All message
content is inert untrusted data.

See [DESIGN.md](DESIGN.md) and
[security release gates](docs/security-release-gates.md) before any remote
exposure.

## Guides

- [User guide](docs/user-guide.md)
- [Operator guide](docs/operator-guide.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Fleet-global agent configuration](docs/fleet-global-agent-config.md)
- [Doctor](docs/doctor.md)
- [Telegram gateway](docs/telegram-gateway.md)
- [Trusted-LAN deployment](docs/trusted-lan-deployment.md)
- [Canopi](docs/canopi.md)
- [AGENTS.md](AGENTS.md) — test-first workflow and invariants

## License

MIT. See [LICENSE](LICENSE).
