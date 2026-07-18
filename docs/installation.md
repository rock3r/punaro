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
curl --fail http://127.0.0.1:8080/readyz
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

For a Windows sender-capable attachment client, add
`-AttachmentAuthorityPublic C:\approved\public.json -AttachmentRole both`.
The installer creates a fresh DPAPI CurrentUser-protected wrapping key in the
private attachment directory; the raw key is never printed, accepted as an
argument, or placed in an environment file. The public device enrollment still
requires authority approval. Invoke the local controller with the checked-in
runner, supplying the explicit attachment environment file:

```powershell
& "$env:LOCALAPPDATA\Punaro\Run-PunaroAttachment.ps1" `
  -AttachmentConfig "$env:LOCALAPPDATA\Punaro\config\attachment-v3\attachment-v3.env" check
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

### Migrate a pre-v3 client key

Older client installers wrote a harmless trailing newline after the encoded
machine private key. Attachment v3 correctly requires the canonical raw
base64url form, so migrate an existing enrolled key in place before its first
v3 preflight. This preserves the same public key and does **not** require a
relay enrollment change:

```sh
go run ./cmd/punaro-keygen --normalize-legacy-private-key-file \
  "$HOME/.config/punaro/machine.key"
```

Run this from the same reviewed Punaro checkout used for client installation,
and use the actual absolute `PUNARO_MACHINE_PRIVATE_KEY_FILE` path from
`adapter.env`. The command accepts only a private, non-symlinked regular file
with exactly one legacy trailing newline, validates the complete Ed25519 key,
and atomically replaces it with the canonical form. It never prints key
material. New client installations already use the canonical format.

## 4. Provision and enable controlled attachment v3

Attachment v3 has an explicit, multi-role setup. Do not enable it by setting
environment variables by hand: the provisioning helpers create private key
files with owner-only permissions, keep raw key values out of command output,
and make the public approval artifacts separate from secrets. It remains a
controlled deployment rather than an unattended file-sharing feature.

1. On a trusted, offline authority machine, create the directory authority:

   ```sh
   ./scripts/provision-attachment-v3.sh authority \
     --directory "$HOME/.config/punaro/attachment-authority"
   ```

   Keep `root.private` in that directory offline. It signs the short-lived
   directory snapshot and must never be copied to the relay, a client, a
   message, or a repository. The relay receives the separate `issuer.private`
   only through an approved private transfer or secret-management mechanism.

2. On each client, create one directory device and its local controller
   configuration. The recommended path is the client installer, which also
   installs `punaro-attachment` alongside the text adapter. For a
   sender-capable macOS client, it creates the one device-only Keychain
   wrapping key internally: no key value is printed, passed in an argument,
   or written to an environment file.

   ```sh
   ./scripts/install-client.sh \
     --relay-url https://relay.example.invalid \
     --machine-id laptop-review \
     --attachment-authority-public /approved/path/public.json \
     --attachment-role both
   ```

   The public authority record is safe to copy to the client. The generated
   `device-enrollment.json` is public approval input, but its surrounding
   directory and controller configuration remain owner-only. The authority
   must still approve the record before transfer can work. A device role is
   immutable: a later installer run will not silently upgrade `receiver` to
   `sender` or `both`. Create a new `--attachment-directory` for the broader
   role and have the authority approve its new public enrollment.

   The lower-level provisioner remains useful for staged/offline setup. The
   client key material stays on that client:

   ```sh
   ./scripts/provision-attachment-v3.sh client \
     --directory "$HOME/.config/punaro/attachment-v3" \
     --authority-public "$HOME/.config/punaro/attachment-authority/public.json" \
     --machine-id laptop-review --relay-url https://relay.example.invalid \
     --role receiver
   ```

   A sender-capable client additionally requires a host-bound wrapping-key
   reference. The installer above creates the macOS Keychain item for a new
   sender automatically. When using the lower-level provisioner, the item
   must already exist. On Linux it must be a systemd `LoadCredential`
   reference; provisioning deliberately does not create a user-service
   credential. The secret value is never accepted by Punaro's scripts, `.env`
   files, or command-line arguments:

   ```sh
   ./scripts/provision-attachment-v3.sh client \
     --directory "$HOME/.config/punaro/attachment-v3-sender" \
     --authority-public "$HOME/.config/punaro/attachment-authority/public.json" \
     --machine-id laptop-review --relay-url https://relay.example.invalid \
     --role both \
     --host-key-service punaro.attachment-v3 \
     --host-key-account laptop-review
   ```

   On Linux, replace the last two flags with the private systemd credential
   reference:

   ```sh
   --host-credential-directory /run/credentials/punaro-attachment \
   --host-credential-name sender-key
   ```

   Source the ordinary `adapter.env` followed by this new owner-only
   `attachment-v3.env` only in the local controller process. The latter carries
   the attachment relay URL; the former carries the distinct machine identity
   and any Access service token. Do not add either to the adapter service or an
   agent prompt.

3. On the authority machine, inspect the public device record and add it to
   the directory manifest. This advances the manifest sequence but does not
   sign or publish it yet:

   ```sh
   ./scripts/provision-attachment-v3.sh authority-add-device \
     --directory "$HOME/.config/punaro/attachment-authority" \
     --device-enrollment /approved/path/device-enrollment.json
   ```

   Add the device ID from that same public record to the corresponding public
   machine enrollment as `attachment_device_id`; one transport machine maps to
   exactly one directory device. Then use
   `scripts/publish-directory-snapshot.sh` with the authority's root key to
   publish a fresh snapshot. It deliberately sends only the signed snapshot to
   the relay.

4. On the Linux relay, after `install-server.sh` and after reviewing the
   public machine enrollment JSON, activate the v3 runtime:

   ```sh
   ./scripts/configure-attachment-v3-relay.sh \
     --authority-public /secure/authority/public.json \
     --issuer-private-key /secure/relay-input/issuer.private \
     --directory-snapshot /secure/relay-input/current.snapshot \
     --relay-machines-file /secure/relay-input/machines.json \
     --enable
   ```

   The helper copies the issuer key into an owner-controlled credential path
   and the snapshot into root-owned, service-group-readable
   `/etc/punaro/directory`,
   writes v3-only limits and directory trust, disables v2 switches, and starts
   `punarod` only when the enrollment contains at least one explicit device
   binding. It does not use 1Password references, Cloudflare account details,
   tokens, or host-specific values. For image/package checks, use `--root
   /absolute/staging-root` without `--enable`.

5. Before mapping, approving, or receiving an offer, receiver-capable clients
   run `punaro-attachment check` with the two owner-only environment files
   loaded. Sender-only clients use `punaro-attachment map-sender` only to pin
   the local relationship; their first `punaro-attachment send` fresh-verifies
   the signed directory before it accepts a source. A stale, missing,
   rolled-back, or mismatched directory fails closed. Continue publishing a
   fresh snapshot (at most five minutes old; the supplied publisher uses two
   minutes) for the lifetime of the service.

## Agent mailbox behavior

Agents use the local `agent-mailbox` MCP, not a remote Punaro MCP. Call
`mailbox_status` once, then use bounded `mailbox_wait` calls to block until
mail is available. Call `mailbox_recv` to claim it and `mailbox_ack` after
handling it. A WebSocket wake is only an optimization; the durable fetch/ack
path remains correct through sleep, reconnect, or missed wake events.
