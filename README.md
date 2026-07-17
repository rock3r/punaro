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
> gateway process. A separately versioned v3 attachment runtime exists only
> behind an explicit operator switch for controlled validation; public rollout
> and production attachment release remain closed by the release gates.

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
[installation guide](docs/installation.md),
[alpha text-relay onboarding](docs/alpha-text-relay.md),
[Telegram gateway guide](docs/telegram-gateway.md),
[attachment RFC](docs/attachments-v2-rfc.md),
[controlled v3 attachment RFC](docs/attachments-v3-rfc.md), and the
[explicit attachment agent workflow](skills/punaro-attachment/SKILL.md),
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
| `PUNARO_RELAY_MACHINES_JSON` | unset | Explicit public-key machine enrollment records. `endpoint_prefixes` claims disjoint machine namespaces; `endpoints` can grant a named exact endpoint without creating a prefix. An issuer-capable machine additionally has canonical raw-base64url `attachment_device_id` (16 bytes), bound to exactly one directory device. |
| `PUNARO_DIRECTORY_ENABLED` | `false` | Serves a current complete signed directory snapshot to authenticated enrolled machines; requires the relay. |
| `PUNARO_DIRECTORY_SNAPSHOT_FILE` | unset | Absolute, root-owned and service-group-readable (`2750` parent, `0640` regular non-symlink) canonical directory snapshot publication file. |
| `PUNARO_PERMIT_ISSUANCE_ENABLED` | `false` | Enables only authenticated attachment-permit issuance; it requires directory service, pinned trust, an issuer key file, explicit limits, and at least one machine/device binding. It does not enable file transfer. |
| `PUNARO_DIRECTORY_AUDIENCE`, `PUNARO_DIRECTORY_ROOT_KEY_ID`, `PUNARO_DIRECTORY_ROOT_PUBLIC_KEY` | unset | Canonical raw-base64url 32-byte pinned directory trust material for permit issuance. |
| `PUNARO_PERMIT_ISSUER_KEY_ID` | unset | Canonical raw-base64url 32-byte active issuer key ID. |
| `PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE` | unset | Absolute path to a `0600`, non-symlinked file containing exactly one canonical raw-base64url Ed25519 private key. |
| `PUNARO_PERMIT_MAX_LIFETIME_SECONDS` | unset | Explicit permit lifetime: 1–60 seconds for v2 issuance, or 1–30 seconds when v3 is enabled. |
| `PUNARO_PERMIT_MAX_BYTES`, `PUNARO_PERMIT_MAX_CHUNKS`, `PUNARO_PERMIT_MAX_OPERATIONS` | unset | Explicit per-permit quotas; no default quota is granted. |
| `PUNARO_PERMIT_MAX_ACTIVE` | unset | Explicit issuance-identity ceiling, 1–4096. V2 applies it as a global live-permit ceiling. V3 applies it per holder to retained issuance identities (including short-lived retry tombstones), while the source store separately bounds aggregate transfer capacity. Exact retries remain admissible without another slot. |
| `PUNARO_ATTACHMENT_V3_ENABLED` | `false` | Enables separately versioned v3 permit and attachment routes only when the relay, signed directory, pinned trust, issuer key, explicit limits, and machine/device binding are configured. It is mutually exclusive with all v2 attachment switches. |
| `PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE` | unset | Absolute private (`0700` non-symlink parent, `0600` database) SQLite path shared by the v3 issuance and transfer handlers. It retains bounded issuance identities and short-lived retry state. |
| `PUNARO_ATTACHMENT_RELAY_ENABLED` | `false` | Reserved attachment relay switch; enabling it is rejected until the attachment v2 release gates are complete. |
| `PUNARO_ATTACHMENTS_ENABLED` | `false` | Reserved for attachment v2; the daemon fails closed if set until the remaining release gates are implemented. |
| `PUNARO_ATTACHMENT_DEVICE_KEYS_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |
| `PUNARO_ATTACHMENT_MEMBERSHIP_JSON` | unset | Reserved attachment configuration; not parsed by the health daemon. |

The optional `punaro-telegram` process takes its bot token from exactly one of
`PUNARO_TELEGRAM_BOT_TOKEN` or `PUNARO_TELEGRAM_BOT_TOKEN_FILE`. Prefer a
private credential file supplied by the OS service manager; the checked-in
systemd unit uses `LoadCredential`. Never place a token in source control, a
CLI argument, an agent prompt, logs, or a message body. See the
[Telegram gateway guide](docs/telegram-gateway.md).

For controlled v3 validation, `punaro-directory` generates private key files,
public IDs, and canonical root-signed directory snapshots without hand-writing
CBOR. Its setup and strict private-file requirements are in the
[operator guide](docs/operator-guide.md#create-v3-directory-material).

## Security model

Cloudflare Access is optional admission, not complete application authorization.
When configured, the relay validates its JWT and also requires a separate
enrolled per-machine cryptographic identity. Conversation membership is
server-enforced and deny-by-default. All message content remains inert
untrusted data, not an instruction to alter routing, run a command, or fetch a
URL.

See `DESIGN.md` for required origin isolation, delivery semantics, and
adversarial test gates before remote exposure. The v3 runtime still requires
the documented validation, recovery, and release evidence before it can be
treated as a production attachment service.

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
