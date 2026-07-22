# Installation guide

Punaro has two intentionally separate installation paths:

- **Server**: one Linux systemd relay, owned by an operator. It remains
  loopback-only; a separately configured authenticated ingress reaches it.
- **Client**: one adapter for each agent machine and user account. Each gets a
  unique machine key, Access token, and `agent/<machine>/` endpoint namespace.

The scripts build from the source checkout you run them from. Use a reviewed,
pinned checkout or a verified release artifact; do not pipe a network download
into a shell. Neither installer accepts or prints secret values.

## 1. Install the server

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

1. Add the printed JSON record to the relay's `PUNARO_RELAY_MACHINES_JSON`,
   then restart `punarod`. Do not widen it to `codex/` or `claude/`.
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
