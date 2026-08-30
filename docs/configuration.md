# Configuration and secrets

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
[Telegram gateway guide](telegram-gateway.md).

The v2/v3 packages, vectors, RFCs, and tests remain source-level experimental
evidence only. They are not shipped in the production container and have no
`punarod` routes or supported deployment workflow.

Operator lifecycle, Compose, Cloudflare Access, doctor, and incident response
live in the [operator guide](operator-guide.md). Server and client installers
live in the [installation guide](installation.md).
