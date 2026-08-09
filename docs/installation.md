# Installation guide

Punaro has a supported unified server lifecycle and separate per-machine client
installers:

- **Server**: one Linux operator lifecycle, initialized once with `punaro init`.
  It generates the complete daemon configuration from explicit inputs and
  keeps the service, database, health listener, and credentials host-local.
- **Client**: one adapter for each agent machine and user account. Each gets a
  unique machine key, Access token, and `agent/<machine>/` endpoint namespace.

The scripts build from the source checkout you run them from. Use a reviewed,
pinned checkout or a verified release artifact; do not pipe a network download
into a shell. Neither installer accepts or prints secret values. For the
supported fresh server path, follow the [production Compose lifecycle](production-compose.md#first-installation).
It is the sole path that configures relay authority, device authentication,
trusted attachment storage, memory APIs, ingress, and lifecycle recovery
together. `scripts/install-server.sh` below is retained only for historical
alpha relay deployments; do not use it for a new unified server.

## Historical alpha server installer (not for new unified servers)

First collect the **public** client enrollment records into one JSON array on
the relay host. The client installer prints each record; it contains a public
key and endpoint prefix, never a private key or Access token. On the Linux
relay host, as root:

```sh
git clone https://github.com/rock3r/punaro.git
cd punaro
git checkout <reviewed-release-or-commit>
./scripts/install-server.sh \
  --machines-file /root/punaro/public-machines.json \
  --access-issuer https://team.cloudflareaccess.example \
  --access-audience <access-application-audience> \
  --access-jwks-url https://team.cloudflareaccess.example/cdn-cgi/access/certs \
  --enable
```

This creates the unprivileged `punaro` service account, installs `punarod` and
its hardened unit, creates `/etc/punaro/punaro.env`, installs the hardened
local JWKS refresh service and timer, refreshes JWKS once, and starts the relay
only after the public enrollment array is present. The relay remains bound to
loopback. It does **not** accept or install a Cloudflare Tunnel token, create a
Cloudflare Access application, or copy any client secret.

On a later `--enable` run, the installer restarts the relay after updating the
configuration so the requested enrollment and Access settings take effect.

`--access-*` is strongly recommended for an internet-reachable deployment.
All three Access options are required together; they are public identifiers and
URLs. The installer writes the JWKS URL only to root-owned
`/etc/punaro/jwks-refresh.env`, while the relay reads the refreshed local
snapshot. If you are deliberately deploying only on a trusted LAN, omit all
three `--access-*` options. `--machines-file` is optional when staging files,
but required to enable a relay without manually editing configuration.

Configure Cloudflare Tunnel and its Access policy separately to route the
chosen hostname to `http://127.0.0.1:8080`. Put the tunnel token into the
documented systemd `LoadCredential` location, never in the installer, an env
file, shell history, or source control. See the [operator guide](operator-guide.md)
for the tunnel service and maintenance checks.

Verify the finished server:

```sh
curl --fail http://127.0.0.1:8081/readyz
systemctl status punarod.service punaro-jwks-refresh.timer
```

The server installer also supports `--root /absolute/staging-root` to build a
package image without creating users, changing systemd, or starting services.

## 2. Install one client machine

Install `agent-mailbox` first. Then, as the same unprivileged user that owns
that mailbox state, run from the reviewed Punaro checkout:

```sh
./scripts/install-client.sh \
  --relay-url https://relay.example.invalid \
  --machine-id laptop-review \
  --agent-guidance-dir /path/to/agent-project
```

The machine ID must be unique. The script derives the exclusive endpoint
namespace `agent/laptop-review/`, builds `punaro-adapter`, creates the local
`group/punaro-attached` group, writes owner-only local state, installs the
launchd (macOS) or user-systemd (Linux) service definition, and prints a
public enrollment JSON record. It does not start the adapter yet.

### Windows 10/11 client

Install `agent-mailbox.exe` and Go first. Run this from the reviewed checkout
in a normal interactive PowerShell session for the Windows user that owns that
mailbox:

```powershell
powershell -NoProfile -File .\scripts\install-client.ps1 `
  -RelayUrl https://relay.example.invalid `
  -MachineId windows-review `
  -AgentGuidanceDir C:\src\agent-project
```

The installer writes private state below `%LOCALAPPDATA%\Punaro`, applies an
exclusive ACL for the current user, and registers the **Punaro Adapter** task
to run only in that user's interactive session. It does not weaken PowerShell
execution policy, accept Access secrets as arguments, or run as a Windows
service. Add that machine's distinct Access token pair manually to
`%LOCALAPPDATA%\Punaro\config\adapter.env`, then rerun with `-Enable` and
verify with:

```powershell
Get-ScheduledTask -TaskName 'Punaro Adapter'
```

The installer also builds `%LOCALAPPDATA%\Punaro\bin\punaro-trusted-attachment.exe`.
After ordinary device enrollment, the operator separately provisions its fixed
HTTPS origin, protected credential file, project UUID, and safe download root.
The installer never accepts or prints the credential. For example:

```powershell
& "$env:LOCALAPPDATA\Punaro\bin\punaro-trusted-attachment.exe" receive `
  --origin https://punaro.example `
  --credential-file C:\protected\punaro-device `
  --artifact 00000000-0000-4000-8000-000000000003 `
  --download-root C:\private\downloads
```

`--agent-guidance-dir` is optional and explicit. It adds a marked block to the
project's `AGENTS.md` and any existing `CLAUDE.md`, `GEMINI.md`, or `CODEX.md`,
then installs the portable `punaro-mailbox`, `punaro-reply`, and
`punaro-attachment` skills below that project's `.agents/skills`. It never
overwrites a differing local skill.
Run `./scripts/install-agent-guidance.sh --directory /path/to/project` later
if you decline it during client setup.

## 3. Approve and configure the client

1. For a new unified server, add the printed JSON record to the protected
   relay-machine file before the initial `punaro init --relay-machines-file`.
   Before mail cutover, to add or revoke a client later, replace that complete protected file and
   run `punaro relay configure --directory INSTALLATION_DIR
   --relay-machines-file RELAY_MACHINES_FILE --yes`, followed by `punaro up`.
   Use the explicit JSON value `[]` to revoke the final client; the restarted
   relay then accepts no signed machine requests.
   After mail cutover, this command can only retain or remove already registered
   keys. New mailbox clients are currently unavailable until a durable
   post-cutover authority-registration workflow is delivered.
   Do not hand-edit `PUNARO_RELAY_MACHINES_JSON` or widen a namespace to
   `codex/` or `claude/`.
2. Create a **distinct** Cloudflare Access service token and policy for this
   machine, if the relay is Access-protected. Use a secret manager or editor to
   add its paired client ID and secret to the owner-only
   `~/.config/punaro/adapter.env`. Do not pass them as command-line arguments
   or reuse a token on another machine.
3. Bind each reachable agent to an explicit address under that machine's
   namespace, then attach it to the local group. For example:

   ```sh
   agent-mailbox group add-member \
     --group group/punaro-attached \
     --person agent/laptop-review/agent-a
   ```

   Use `mailbox_bind` in the local `agent-mailbox` MCP to create the explicit
   address first. The installer cannot infer which agent sessions should be
   reachable.
4. Re-run the same client command with `--enable`, then verify the user
   service:

   ```sh
   # macOS
   launchctl print gui/$(id -u)/org.punaro.adapter

   # Linux
   systemctl --user status punaro-adapter.service
   ```

The client installer is idempotent only for the same machine ID, relay URL,
and local paths. It refuses to overwrite an existing key, enrollment record,
configuration file, or project skill that does not match. To revoke a client,
follow the [alpha onboarding revocation procedure](alpha-text-relay.md#onboard-and-revoke-a-machine): remove attached aliases, remove the relay enrollment, revoke the machine's Access token, stop the service, and securely erase its key.

### Adapter profile for direct commands and the service

The installed `punaro-adapter` validates and reads the same owner-only,
non-symlinked profile for direct `create`, `send`, and `attachment-notify`
commands and for the managed adapter service. On macOS and Linux that profile
is `~/.config/punaro/adapter.env`; on Windows it is
`%LOCALAPPDATA%\Punaro\config\adapter.env`. Do not source the file in a shell
or copy its values into a command line.

A non-empty adapter setting in the process environment intentionally overrides
the corresponding profile setting, for controlled service-manager or debugging
use. `PUNARO_ADAPTER_PROFILE_FILE` is the explicit alternative profile path;
it must be absolute and satisfy the same private regular-file checks. The
default profile remains the supported interactive path.

### Unified client identity transition contract

Device credentials and the existing mailbox Ed25519 key are distinct
per-device credentials. Neither may be copied between machines or derived from
the other. The supported enrollment workflow will write a private, non-secret client
identity sidecar and adds both of these profile entries together:

```text
PUNARO_CLIENT_IDENTITY_FILE=/absolute/private/client-identity.json
PUNARO_CLIENT_BINDING=the-enrollment-client-binding
```

The sidecar contains only version `1`, the fixed canonical HTTPS origin, the
opaque client binding, and (during a legacy transition) the exact legacy
machine ID. It never contains an enrollment code, bearer credential, private
key, Access token, project grant, or mailbox address. The adapter refuses a
missing pair, unsafe sidecar, unknown version, or origin/binding/machine
mismatch before it opens a transport client. Existing legacy profiles without
both entries continue their existing path; adding the sidecar alone neither
changes relay authority nor grants access.

The server's owner-controlled mail cutover remains the only action that can
activate the PostgreSQL relay transition. Credential rotation, revocation,
disabled principals, or an unavailable authority fail the server bridge closed;
the local sidecar cannot repair, bypass, or broaden those decisions. After
SQLite retirement, rollback is restore or forward repair, not a client profile
edit.

### Supported device-credential enrollment

Installers now include `punaro-enroll` (`punaro-enroll.exe` on Windows). It is
the supported way to make the public per-device enrollment binding and persist
the returned bearer credential. It never accepts an enrollment code, bearer
credential, private key, or Access secret in an argument or environment
variable.

On the client, create state for the fixed origin. The directory must be new or
private and owned by the current user. On macOS/Linux use a directory below
`~/.config/punaro`; on Windows use one below `%LOCALAPPDATA%\Punaro`:

```sh
punaro-enroll prepare \
  --origin https://punaro.example \
  --state-dir "$HOME/.config/punaro/device-enrollment"
```

The command prints only the canonical origin and an opaque `client_binding`.
Give that public value to the server owner. The owner previews and creates the
least-privilege grant with `punaro-admin client add`; the owner chooses the
projects and cannot be overridden by the client. With `--yes`, that command
prints the confirmed preview followed by the pending enrollment object. Treat
the complete exact output as short-lived enrollment material: transfer it
unchanged through an approved protected channel into a current-user-only regular
file on that client. Do not paste it
into terminal commands, shell history, environment variables, diagnostic
bundles, or source-controlled configuration.

Redeem that protected file on the client:

```sh
punaro-enroll redeem \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --enrollment-file /absolute/private/enrollment-material.json \
  --credential-file "$HOME/.config/punaro/device-enrollment/device.credential"
```

If the public origin is protected by Cloudflare Access, create a distinct
service token for this device and have its secret manager write the paired
values into a current-user-only, non-symlinked JSON file such as:

```json
{"client_id":"...","client_secret":"..."}
```

Pass only that protected file path to the same command:

```sh
punaro-enroll redeem \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --enrollment-file /absolute/private/enrollment-material.json \
  --credential-file "$HOME/.config/punaro/device-enrollment/device.credential" \
  --access-file /absolute/private/cloudflare-access.json
```

The command uses the service token only to establish an origin-scoped Access
session and send the admission headers; it never accepts, prints, or stores
either value in arguments, environment variables, generated profile defaults,
or diagnostics. Continue to keep the token in the owner-only adapter profile
for the installed relay adapter; do not reuse it on another device.

`punaro-enroll` checks the exact binding before any network request, contacts
only the canonical HTTPS origin selected during `prepare`, and writes a private
recovery journal before redemption. If a network interruption occurs, rerun
the same `redeem` command; if the transfer file is gone, use `punaro-enroll
recover` with the state and credential paths, and include the same
`--access-file` when the origin is Access-protected. The retry has the same
idempotency key, so it cannot mint a second device credential. The server retains that
recovery record while its credential and principal remain active; after either
expires, is revoked, or is disabled, request a new enrollment. A rejected
(including
expired, already-used, or revoked) enrollment fails closed and tells the user
to request a new enrollment; its private recovery journal is removed so the
replacement material is not blocked. After success, remove the transferred material
through its approved secret-handling process; the identity sidecar remains
non-secret and the recovery journal is removed.

The server owner rotates or revokes a device with `punaro-admin credential
rotate` or `punaro-admin credential revoke`, using the content-free credential
inventory. Rotation and revocation are server-controlled: a local identity
sidecar or copied credential cannot restore access.

## 4. Retired v2/v3 attachment evidence

Do not execute the historical provisioning helpers retained in the source tree
on a production host. `punarod` rejects all legacy attachment, directory, and permit settings;
the old routes are unmounted, and production installers do not ship their
controller, directory, DPAPI helper, or runner. Those helpers are preserved
only to reproduce protocol tests and RFC evidence.

For supported attachment operations, use the native trusted client installed
by the client installer and the operator-provisioned fixed origin, protected
credential, project UUID, and safe download root. See the
[`punaro-attachment` skill](../skills/punaro-attachment/SKILL.md).

### Supported native client

The client installer builds `punaro-trusted-attachment` (or the Windows
`.exe`). After operator device enrollment, use the fixed trusted HTTPS origin,
absolute protected credential file, project UUID, stable idempotency UUID, and
an existing private download root. Follow the
[`punaro-attachment` skill](../skills/punaro-attachment/SKILL.md) for the exact
send, receive, and delete safety boundaries. No production installer accepts
legacy v2/v3 authority, role, directory, wrapping-key, or permit options.

On macOS and Linux the same installer also builds `punaro-memory`, the native
client for an already enabled M-17 memory API. Supply the fixed HTTPS origin,
an absolute owner-only device credential file, and explicit project/key/ETag
coordinates, or write a protected non-secret profile containing only the
origin, credential-file path, and optional default project; see the
[operator guide](operator-guide.md#native-memory-client). The same binary can
run as a local stdio MCP server with `punaro-memory mcp --profile ...`; this is
local profile-backed MCP, not the later remote OAuth MCP gateway. Windows memory
credential loading remains fail-closed until a later slice adds paired ACL and
reparse-point provisioning and verification, so the Windows installer does not
install this binary yet.

## Agent mailbox behavior

Agents use the local `agent-mailbox` MCP, not a remote Punaro MCP. Call
`mailbox_status` once, then use bounded `mailbox_wait` calls to block until
mail is available. Call `mailbox_recv` to claim it and `mailbox_ack` after
handling it. A WebSocket wake is only an optimization; the durable fetch/ack
path remains correct through sleep, reconnect, or missed wake events.
