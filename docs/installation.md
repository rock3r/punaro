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

On the Linux relay host, as root:

```sh
git clone https://github.com/rock3r/punaro.git
cd punaro
git checkout <reviewed-release-or-commit>
./scripts/install-server.sh
```

This creates the unprivileged `punaro` service account, installs `punarod` and
its hardened unit, creates `/etc/punaro/punaro.env` as an owner-managed file,
and leaves the service stopped. It does not install a public listener,
Cloudflare Tunnel, Access policy, or any machine enrollment.

Configure the relay before starting it. Add only public enrollment records to
`PUNARO_RELAY_MACHINES_JSON`; never place a client private key, Access service
token, or message body in this file. If internet-facing, configure a
Cloudflare Tunnel to the loopback origin and configure Access issuer, audience,
and protected JWKS refresh/file according to the [operator guide](operator-guide.md).

After at least one machine record is present:

```sh
systemctl daemon-reload
systemctl enable --now punarod.service
curl --fail http://127.0.0.1:8080/readyz
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

`--agent-guidance-dir` is optional and explicit. It adds a marked block to the
project's `AGENTS.md` and any existing `CLAUDE.md`, `GEMINI.md`, or `CODEX.md`,
then installs the portable `punaro-mailbox` and `punaro-reply` skills below
that project's `.agents/skills`. It never overwrites a differing local skill.
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
   configuration. The client key material stays on that client:

   ```sh
   ./scripts/provision-attachment-v3.sh client \
     --directory "$HOME/.config/punaro/attachment-v3" \
     --authority-public "$HOME/.config/punaro/attachment-authority/public.json" \
     --machine-id laptop-review --relay-url https://relay.example.invalid \
     --role receiver
   ```

   A sender-capable client additionally requires an existing host-bound
   wrapping-key reference. On macOS this names a Keychain generic-password
   item; on Linux it must be a systemd `LoadCredential` reference. The secret
   value is never accepted by Punaro's scripts, `.env` files, or command-line
   arguments:

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

   The helper copies the issuer key and snapshot into service-private paths,
   writes v3-only limits and directory trust, disables v2 switches, and starts
   `punarod` only when the enrollment contains at least one explicit device
   binding. It does not use 1Password references, Cloudflare account details,
   tokens, or host-specific values. For image/package checks, use `--root
   /absolute/staging-root` without `--enable`.

5. Before mapping, approving, sending, or receiving an offer on every client,
   run `punaro-attachment check` with the two owner-only environment files
   loaded. A stale, missing, rolled-back, or mismatched signed directory fails
   closed. Continue publishing a fresh snapshot (at most five minutes old;
   the supplied publisher uses two minutes) for the lifetime of the service.

## Agent mailbox behavior

Agents use the local `agent-mailbox` MCP, not a remote Punaro MCP. Call
`mailbox_status` once, then use bounded `mailbox_wait` calls to block until
mail is available. Call `mailbox_recv` to claim it and `mailbox_ack` after
handling it. A WebSocket wake is only an optimization; the durable fetch/ack
path remains correct through sleep, reconnect, or missed wake events.
