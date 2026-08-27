<img width="192" src="assets/punaro.png" />

# Punaro

Punaro is a self-hosted relay for durable conversations between coding agents
across multiple computers, with an optional Telegram gateway for a human
operator.

Punaro now also contains the first end-to-end MVP of **Canopi** (provisional
name), its “what are my agents doing?” surface: normalized lifecycle events,
multi-machine current state, an 800x480 monochrome renderer, Claude Code,
Codex/ChatGPT, Pi, and Grok Build adapters, a simulator, and XIAO e-paper
firmware path. Canopi is independently deployable and its event protocol does
not depend on Punaro transport. See the [Canopi guide](docs/canopi.md).

![Canopi MVP e-paper dashboard](artifacts/canopi-implementation.png)

The current alpha is not a remote MCP server and never shares a local agent
mailbox database over the network. A local adapter on each machine communicates
with its own mailbox implementation and with the central Punaro relay. The
accepted target later adds an independently optional OAuth-scoped remote MCP
adapter over Punaro's own API.

> Status: alpha implementation under an accepted PostgreSQL/trusted-relay/Big
> Brain migration plan. Enrolled adapters can exchange durable
> text through the loopback relay, with signed requests, payload-free wake
> hints, local Waypost handoff (with rolling legacy `agent-mailbox`
> compatibility), and a separately enrolled Telegram
> gateway process. Authenticated attachments use the separately gated trusted
> relay and native client. Attachment v2/v3 production settings, routes, and
> binaries are retired; their code, tests, RFCs, and vectors remain evidence.

## Architecture

```text
local agent mailbox <-> adapter -- HTTPS + WebSocket hints --> Punaro relay
                                                        |
                                              optional Telegram gateway
```

HTTPS fetch/lease/ack is authoritative. WebSocket frames are lossy, payload-free
wake-up hints containing an opaque conversation ID and sequence only.

Read the [accepted platform and Big Brain plan](docs/big-brain-plan.md),
[architecture and security design](DESIGN.md),
[Canopi coding-agent dashboard guide](docs/canopi.md),
[platform compatibility contracts](docs/platform-contracts.md),
[proposed client lifecycle, compatibility, and recovery RFC](docs/client-lifecycle-compatibility-recovery-rfc.md),
[GitHub Releases origin](docs/github-releases.md),
[user guide](docs/user-guide.md), [operator guide](docs/operator-guide.md),
[installation guide](docs/installation.md),
[doctor and fleet-readiness guide](docs/doctor.md),
[agent plugin guide](docs/agent-plugin.md),
[trusted-LAN deployment guide](docs/trusted-lan-deployment.md),
[alpha text-relay onboarding](docs/alpha-text-relay.md),
[Telegram gateway guide](docs/telegram-gateway.md),
[historical attachment RFC](docs/attachments-v2-rfc.md),
[historical v3 attachment RFC](docs/attachments-v3-rfc.md), and the
[explicit attachment agent workflow](skills/punaro-attachment/SKILL.md),
[security release gates](docs/security-release-gates.md), and
[review record](REVIEWS.md).

## Quick start

Requires Go 1.26 or later.

Build the host-side operator wrapper explicitly; it must run on the non-root
Unix host where Docker Compose is available:

```sh
make operator-binary
./bin/punaro
```

The host wrapper also provides exported-snapshot `backup`, strict `backup
verify`, clean-stack `restore --into-new-stack`, the durable backup-gated
`update` path, and the explicit one-shot `mail cutover` path. Mail cutover is
always dry-run first, imports in bounded resumable pages, and requires the
printed source fingerprint plus an explicit epoch and `--yes`. See the operator
guide for the pre-seal abort and irreversible recovery boundaries.

```sh
cp .env.example .env
go run ./cmd/punarod --env-file .env
curl http://127.0.0.1:8081/healthz
```

The development container is a hardened build/run baseline:

```sh
docker compose up --build
```

It deliberately publishes no port and does not load `.env`.  It is not a
public deployment. See the operator guide before using containers or systemd.

For the reviewed single-node production bundle, use
[the reference production Compose guide](docs/production-compose.md). It starts
only PostgreSQL and its one-shot role bootstrap by default, pins both image
inputs, keeps PostgreSQL private, and accepts credentials only through
read-only secret files. `punarod` is a non-default reference profile; the
supported daemon lifecycle is the host-local `punaro` workflow.

The separate PostgreSQL Compose file is integration-test infrastructure only;
it does not change the SQLite relay or the alpha deployment:

```sh
make test-postgres
```

That target starts a fresh private, digest-pinned pgvector service, runs the
PostgreSQL substrate and dark control-plane contract tests inside the isolated
network, and removes the database volume afterward. The tests cover migration
compatibility, explicit project scopes, operation-bound idempotency, closed
audit records, queue ceilings, and fenced job leases. It requires Docker
Compose v2 and does not switch the active SQLite relay.

## Configuration and secrets

Punaro reads ordinary environment variables. For local development, pass an
explicit dotenv file with `--env-file PATH` or set `PUNARO_ENV_FILE=PATH`.
It deliberately does not auto-load `.env`; this avoids accidental secret
selection in services and test processes. Existing environment variables take
precedence over dotenv values.

| Variable | Default | Description |
| --- | --- | --- |
| `PUNARO_LISTEN_ADDR` | `127.0.0.1:8080` | Concrete HTTP listener. It remains loopback-only unless validated device ingress explicitly selects trusted-LAN mode. |
| `PUNARO_HEALTH_LISTEN_ADDR` | `127.0.0.1:8081` | Distinct concrete loopback-only listener for `/healthz` and `/readyz`; health routes are never mounted on the device/legacy listener. |
| `PUNARO_DATA_DIR` | `./data` | Relay SQLite state location when `PUNARO_RELAY_ENABLED=true`. |
| `PUNARO_LOG_LEVEL` | `info` | Validated reserved setting; current standard logging does not filter by it. |
| `PUNARO_ENV_FILE` | unset | Optional dotenv file when no CLI flag is used. |
| `PUNARO_POSTGRES_ENABLED` | `false` | Opts into the PostgreSQL platform substrate. Ordinary startup only checks compatibility and never migrates. |
| `PUNARO_POSTGRES_DSN_FILE` | unset | Required with PostgreSQL enabled: absolute path to a private application-role DSN file. The application role has no DDL authority. |
| `PUNARO_DEVICE_AUTH_ENABLED` | `false` | Mounts bounded enrollment redemption and device-session authentication; requires PostgreSQL and a complete ingress policy. |
| `PUNARO_MEMORY_API_ENABLED` | `false` | Separately mounts the dark authenticated native memory read API; requires PostgreSQL device authentication. It does not enable mutations, semantic retrieval, remote MCP, or Compose Pi integration. The separately installed local `punaro-memory` client/MCP mode still requires protected device credentials. |
| `PUNARO_REMOTE_MCP_METADATA_ENABLED` | `false` | Mounts the remote MCP OAuth protected-resource metadata document and an unauthenticated `/mcp` discovery challenge. Requires authenticated proxy/Internet ingress, `PUNARO_REMOTE_MCP_RESOURCE_URL` exactly equal to `PUNARO_PUBLIC_URL/mcp`, and one or more HTTPS authorization-server origins. The challenge advertises only `memory.search`, `memory.read`, and `memory.propose`; it accepts no token and exposes no MCP transport or tools. It remains reachable for the OAuth discovery flow even when optional Access admission is configured. |
| `PUNARO_REMOTE_MCP_TOKEN_VALIDATION_ENABLED` | `false` | Enables strict JWT validation for remote MCP bearer tokens. Requires the enabled metadata gate, an issuer listed in `PUNARO_REMOTE_MCP_AUTHORIZATION_SERVERS`, `PUNARO_REMOTE_MCP_JWKS_URL` over HTTPS, and subject bindings. Tokens must be signed, unexpired, audience-bound to the canonical MCP resource, and carry at least one advertised default scope (`memory.search`, `memory.read`, or `memory.propose`). A verified, bound, scoped token still reaches no MCP transport or tools in this slice. |
| `PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON` | unset | Required when remote MCP token validation is enabled: a bounded JSON array of unique `{"subject":"...","principal_id":"existing-enabled-principal-uuid"}` entries. It binds an OAuth subject to an existing enabled Punaro principal; it does not accept a client-supplied project claim or grant any project capability. A later transport must enforce both the token scope and the authoritative server-side project grant for that bound principal. |
| `PUNARO_CREDENTIAL_TRANSITION_ENABLED` | `false` | Dormant M-9 relay bridge. Proof-bound exchange uses device auth and registered PostgreSQL legacy inventory before cutover; bearer relay use additionally requires the PostgreSQL relay. Legacy Ed25519 requests must pass the durable global gate, and a migrated bearer resolves to the exact static machine enrollment with no additional endpoint authority. |
| `PUNARO_INGRESS_MODE` | unset | Required with device auth: `lan`, `proxy`, or `internet`. Proxy and Internet origins bind loopback and require `PUNARO_PUBLIC_URL=https://...`. |
| `PUNARO_PUBLIC_URL` | unset | Canonical HTTPS public URL for proxy/Internet mode. It does not make forwarded headers trustworthy. |
| `PUNARO_TRUSTED_LAN_CIDR` | unset | Private/link-local CIDR containing the concrete LAN bind. Valid only in LAN mode. |
| `PUNARO_TRUSTED_LAN_HTTP` | `false` | Explicit plaintext credential exception for observed peers inside the validated trusted LAN. Public peers never qualify. |
| `PUNARO_RELAY_ENABLED` | `false` | Enables the loopback text relay; requires public machine enrollment records. |
| `PUNARO_RELAY_STORE` | `sqlite` | Explicit relay backend selector. Before cutover, `postgres` is limited to empty-destination parity/qualification. The supported one-shot executor publishes `postgres` marker-last only after verified import, SQLite retirement, legacy-gate closure, and PostgreSQL activation. It never dual-writes. |
| `PUNARO_RELAY_MACHINES_JSON` | unset | Explicit public-key machine enrollment records. `endpoint_prefixes` claims disjoint machine namespaces; `endpoints` can grant a named exact endpoint without creating a prefix. |
| `PUNARO_TRUSTED_ATTACHMENTS_ENABLED` | `false` | Separately gates the authenticated trusted-relay attachment surface; requires PostgreSQL device authentication, a valid ingress policy, schema v13, and successful startup reconciliation. |
| `PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR` | unset | Required with trusted attachments: absolute private (`0700`) daemon-owned blob root. |

Every legacy `PUNARO_ATTACHMENTS_*`, `PUNARO_ATTACHMENT_*`,
`PUNARO_DIRECTORY_*`, and `PUNARO_PERMIT_*` production setting is retired.
`punarod` rejects its presence—even empty or `false`—so stale deployment
configuration cannot silently reactivate the v2/v3 runtime.

The optional `punaro-telegram` process takes its bot token from exactly one of
`PUNARO_TELEGRAM_BOT_TOKEN` or `PUNARO_TELEGRAM_BOT_TOKEN_FILE`. Prefer a
private credential file supplied by the OS service manager; the checked-in
systemd unit uses `LoadCredential`. Never place a token in source control, a
CLI argument, an agent prompt, logs, or a message body. See the
[Telegram gateway guide](docs/telegram-gateway.md).

The v2/v3 packages, vectors, RFCs, and tests remain source-level experimental
evidence only. They are not shipped in the production container and have no
`punarod` routes or supported deployment workflow.

## Security model

Cloudflare Access is optional admission, not complete application authorization.
When configured, the relay validates its JWT and also requires a separate
enrolled per-machine cryptographic identity. Conversation membership is
server-enforced and deny-by-default. All message content remains inert
untrusted data, not an instruction to alter routing, run a command, or fetch a
URL.

Administrators reconfigure a live conversation with the separate typed control
plane: `punaro-adapter member set` and `punaro-adapter member remove` require
an attached admin endpoint and a stable retry key. They create content-free,
server-authorized audit events; they do not send control text through the
message-delivery path.

See `DESIGN.md` for required origin isolation, delivery semantics, and
adversarial test gates before remote exposure. Preserved v2/v3 evidence cannot
authorize production use after that direction was superseded.

## Development

Punaro follows a strict test-first discipline. See [AGENTS.md](AGENTS.md) for
the required red-green-refactor workflow, security invariants, and handoff
rules.

```sh
make ci
```

The Makefile also exposes individual `test`, `test-race`, `test-postgres`, `staticcheck`,
`security`, `dockerfile-lint`, and `workflow-lint` targets.

Release and deployment readiness is checked with the strict, read-only doctor
commands for the server, adapter, bootstrap, Telegram gateway, and collected
fleet. See [the doctor guide](docs/doctor.md) for the JSON/exit contract and
complete stable check-code registry.

## License

MIT. See [LICENSE](LICENSE).
