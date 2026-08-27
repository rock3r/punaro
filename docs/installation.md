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
into a shell. `punaro-bootstrap` pulls from GitHub Releases, documented in
[github-releases.md](github-releases.md). The one-time client installer seeds a
reviewed checkout; after a signed catalog/manifest pair is published, use
`punaro-bootstrap update` for release changes instead of rebuilding in place.
Neither installer accepts or prints secret values. For the
supported fresh server path, follow the [production Compose lifecycle](production-compose.md#first-installation).
It is the sole path that configures relay authority, device authentication,
trusted attachment storage, memory APIs, ingress, and lifecycle recovery
together. `scripts/install-server.sh` below is retained only for historical
alpha relay deployments; do not use it for a new unified server.

For direct private-network operation before Internet ingress is configured,
follow the separate [trusted-LAN deployment profile](trusted-lan-deployment.md).
It requires explicit, matching server and client CIDR policy and documents the
plaintext boundary.

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

That restart is safe only when the installed database already matches the
replacement binary. The historical installer replaces `punarod`; it does not
install the unified `punaro` lifecycle wrapper, create an update journal or
backup, or migrate PostgreSQL. Before rebuilding an existing PostgreSQL-backed
alpha relay from a newer checkout, compare the installed schema with the target
release metadata. If the target requires a newer schema, leave the last
compatible binary running and adopt the supported production Compose lifecycle;
then perform the upgrade with `punaro update`. Do not run `punaro-migrate`
directly, grant schema ownership to `punaro_app`, or repeatedly restart a new
binary that reports `upgrade_required`. A direct binary replacement may be
rolled back only while no schema migration has started.

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

Install Waypost 0.8 or newer first. Then, as the same unprivileged user that
owns that mailbox state, run from the reviewed Punaro checkout:

```sh
./scripts/install-client.sh \
  --relay-url https://relay.example.invalid \
  --machine-id laptop-review \
  --agent-guidance-dir /path/to/agent-project
```

The machine ID must be unique. The script derives the checked-in plugin release
and skill digest and embeds them into the fixed bootstrap and adapter binaries,
so doctor can compare the installed supervisor to signed-release compatibility
policy. It also derives the exclusive endpoint namespace
`agent/laptop-review/`, builds `punaro-adapter` and
`punaro-bootstrap`, seeds the current bootstrap slot from that checkout,
creates the local `group/punaro-attached` group, writes owner-only local
state, installs the launchd (macOS) or user-systemd (Linux) service
definition that launches `punaro-bootstrap run`, and prints a public
enrollment JSON record. launchd declares it as a background process;
systemd disables terminal input and sends output only to the journal. It does
not start the adapter yet.

New installs auto-detect `waypost` before the legacy `agent-mailbox` binary and
use `~/.local/state/waypost` for Waypost state. Use `--waypost-bin` and
`--mailbox-state-dir` when the reviewed executable or state lives elsewhere.
`--agent-mailbox-bin` remains a deprecated option alias so an existing legacy
installation can be reinstalled without changing its mailbox boundary.

When the signed release catalog is available, install it into the managed slot
and keep the fixed bootstrap-owned service lifecycle:

```sh
punaro-bootstrap update \
  --directory "$HOME/.local/state/punaro-bootstrap" \
  --keys-file /absolute/private/punaro-release.pub \
  --release v0.1.0-alpha.4
punaro-bootstrap doctor \
  --directory "$HOME/.local/state/punaro-bootstrap" \
  --keys-file /absolute/private/punaro-release.pub \
  --machine-id laptop-review
punaro-adapter doctor --plugin-root /absolute/installed/punaro-plugin
```

The update verifies the signed catalog and manifest plus every exact artifact
length/digest before changing slots. Do not download a binary named `latest`,
replace current-slot files manually, or run a versioned adapter directly from
the service. See [GitHub Releases](github-releases.md) and
[doctor](doctor.md).

### Windows 10/11 client

Install `waypost.exe` 0.8 or newer and Go first. Run this from the reviewed checkout
in a normal interactive PowerShell session for the Windows user that owns that
mailbox:

```powershell
powershell -NoProfile -File .\scripts\install-client.ps1 `
  -RelayUrl https://relay.example.invalid `
  -MachineId windows-review `
  -AgentGuidanceDir C:\src\agent-project
```

The Windows installer auto-detects `waypost.exe` before a legacy
`agent-mailbox.exe` and uses `%LOCALAPPDATA%\waypost` for new Waypost state.
Use `-WaypostBin` and `-MailboxStateDir` for explicit reviewed locations;
`-AgentMailboxBin` remains a deprecated PowerShell alias.

The installer writes private state below `%LOCALAPPDATA%\Punaro`, applies an
exclusive ACL for the current user, and registers the hidden **Punaro Adapter**
task to start at that user's sign-in without showing a PowerShell console. It
runs in that user's interactive security context because the adapter must
access that user's mailbox and private credentials; it is not a privileged
Windows service. It does not weaken PowerShell execution policy or accept
Access secrets as arguments. Add that machine's distinct Access token pair
manually to `%LOCALAPPDATA%\Punaro\config\adapter.env`, then rerun with `-Enable` and
verify with:

```powershell
Get-ScheduledTask -TaskName 'Punaro Adapter'
& "$env:LOCALAPPDATA\Punaro\bin\punaro-bootstrap.exe" doctor `
  --directory "$env:LOCALAPPDATA\Punaro\bootstrap" `
  --keys-file C:\absolute\private\punaro-release.pub `
  --machine-id windows-review
& "$env:LOCALAPPDATA\Punaro\bin\punaro-adapter.exe" doctor `
  --plugin-root C:\absolute\installed\punaro-plugin
```

When reinstalling over an enabled repeating task, the installer disables it
for the complete replacement critical section. It then stops every task instance,
including one that started while the disable fence was being acquired, and every
process using the exact installed bootstrap image before replacing any managed
executable. It verifies process image identity and bounded exit first, restores
the prior enabled and running state on failure, reports restoration failures with
the original installer error, and does not terminate unrelated processes or
weaken the binary replaceability fence.

An alpha.8 failure may leave that bootstrap image running after the scheduled
task has already returned to **Ready**. When the enabled repeating task still
exists, alpha.9 fences it and terminates only the process whose image is exactly
`%LOCALAPPDATA%\Punaro\bin\punaro-bootstrap.exe`. If that task definition no
longer exists or is deliberately disabled, verify and stop that exact image
manually before rerunning the installer. Do not disable the replaceability fence
or terminate by name.

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

Agents with plugin support can instead load the repository's
[Punaro agent plugin](agent-plugin.md). It provides the same three skills plus
the local Waypost MCP declaration without modifying a project's
guidance files. Use one skill-installation method for a project so the same
skills are not discovered twice.

### Migrate an existing agent-mailbox state to Waypost

This is an operator migration, not an agent-message action. Stop the Punaro
adapter and every agent application or MCP process using the legacy mailbox,
then take an owner-only recovery copy of the complete legacy state directory.
Run Waypost's durable migration with both custom paths explicit:

```sh
waypost --state-dir "$HOME/.local/state/waypost" migrate \
  --from "$HOME/.local/state/ai-agent/mailbox"
```

On Windows, stop the **Punaro Adapter** Scheduled Task and every client using
the mailbox, then run:

```powershell
& waypost.exe --state-dir "$env:LOCALAPPDATA\waypost" migrate `
  --from "$env:LOCALAPPDATA\ai-agent\mailbox"
```

Waypost refuses overlapping paths, an existing unrelated destination, or an
ambiguous interrupted copy. Rerun the same command to resume only a migration
it owns. Windows cross-volume migration may deliberately retain the old source
as a recovery copy; do not delete it until the rollout and rollback drill are
complete.

With the service still stopped, edit only `PUNARO_AGENT_MAILBOX_BIN` and
`PUNARO_MAILBOX_STATE_DIR` in the owner-only Punaro `adapter.env` to the exact
reviewed Waypost executable and migrated directory. Preserve mode `0600` on
Unix or the current-user-only Windows ACL, and never print or rewrite the
Access secret lines. Rerun the client installer with the same machine/relay and
the explicit `--waypost-bin` / `--mailbox-state-dir` (or `-WaypostBin` /
`-MailboxStateDir`) values, enable the service, then run adapter doctor with the
installed plugin root. Rollback restores the complete private backup and both
profile paths together; never point a legacy binary at `waypost.db` or Waypost
at an unmigrated `mailbox.db`.

## 3. Approve and configure the client

1. For a new unified server, add the printed JSON record to the protected
   relay-machine file before the initial `punaro init --relay-machines-file`.
   Before mail cutover, to add or revoke a client later, replace that complete protected file and
   run `punaro relay configure --directory INSTALLATION_DIR
   --relay-machines-file RELAY_MACHINES_FILE --yes`, followed by `punaro up`.
   Use the explicit JSON value `[]` to revoke the final client; the restarted
   relay then accepts no signed machine requests.
   After mail cutover, this command can only retain or remove already registered
   keys. Register one genuinely new installer-produced public record through
   the owner-controlled workflow instead:

   ```sh
   punaro relay register \
     --directory INSTALLATION_DIR \
     --machine-enrollment-file /absolute/private/new-machine.json \
     --yes
   punaro up --directory INSTALLATION_DIR
   ```

   The input is the single JSON object printed by that machine's installer,
   protected as an owner-only regular file. The command first records its exact
   public key in the active PostgreSQL transition authority, then marker-last
   publishes the merged static enrollment. Exact retries recover safely; a
   changed retry or conflicting machine/key/namespace fails closed.
   Relay-authority changes are serialized by a host-local installation lock.
   If another configure, cutover-publication, or registration command is
   already running, the later command fails before database or file mutation;
   rerun its exact command after the first operation finishes.
   Do not hand-edit `PUNARO_RELAY_MACHINES_JSON` or widen a namespace to
   `codex/` or `claude/`.
2. Create a **distinct** Cloudflare Access service token and policy for this
   machine, if the relay is Access-protected. Use a secret manager or editor to
   add its paired client ID and secret to the owner-only
   `~/.config/punaro/adapter.env`. Do not pass them as command-line arguments
   or reuse a token on another machine.

   Cloudflare uses two different credentials in this workflow. The operator's
   account API key/token is used only to administer Access. A current
   account-scoped value has the `cfat_` prefix, is sent as an `Authorization:
   Bearer` credential, and is verified at the account-scoped
   `/client/v4/accounts/<account-id>/tokens/verify` endpoint. Do not test it at
   the user-token endpoint. The per-machine Access service-token pair is the
   `CF-Access-Client-Id` and `CF-Access-Client-Secret` admitted by a Service
   Auth (`non_identity`) policy on the relay application; it is not the
   account API key and must never be reused as one. The Access application
   policy action must be **Service Auth** and its include rule must name this
   exact service token; an ordinary Allow policy sends the adapter to an
   interactive identity-provider login. One Service Auth policy may contain
   several exact service-token include rules, but every enrolled machine still
   needs a different token pair. Never use `any_valid_service_token`: adding an
   unrelated token to the account would then silently grant it admission to
   Punaro. The native clients send both service-token headers on every
   protected request. They do not establish or replay a browser
   `CF_Authorization` cookie with those headers; mixed cookie and Service Auth
   identity can be rejected by Access before a signed request reaches Punaro.

   Test the device application, not only `/readyz`. Make a header-authenticated
   request to `/v1/conversations` without a Punaro machine signature and with
   redirects disabled. The expected result is Punaro's application-level JSON
   `401`: that proves Access admitted the service token and the device route
   reached Punaro, while Punaro still rejected the unsigned caller. A `3xx`,
   HTML response, identity-provider page, or Cloudflare policy error means the
   Service Auth rule is missing or does not include that token. Never print the
   two headers while testing. `/readyz` may use a separate route or bypass
   policy and is only a health check; it cannot prove device admission.
3. Bind each reachable agent to an explicit address under that machine's
   namespace, then attach it to the local group. For example:

   ```sh
   waypost group add-member \
     --group group/punaro-attached \
     --person agent/laptop-review/agent-a
   ```

   Use `waypost_bind` in the local Waypost MCP to create the explicit
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

## 4. New-machine, upgrade, and rollback runbook

Use this sequence for every new adapter machine and for an adapter upgrade. It
keeps the machine identity and its private configuration in place while
replacing only reviewed binaries and service definitions. Do not deploy from a
dirty checkout, reuse another machine's key or Access token, or copy an
`adapter.env` file between machines.

1. Record the exact 40-character source commit and obtain a clean checkout of
   it on the target. Confirm it before installing:

   ```sh
   git rev-parse HEAD
   git status --porcelain
   ```

   On Windows, run the same commands in PowerShell from the checkout. An empty
   `git status --porcelain` is required. Keep the previously installed commit
   available until post-upgrade verification succeeds; it is the rollback
   source, not a backup of credentials or mailbox state.
   Build macOS clients natively on the target architecture by running the
   installer there. Do not substitute a `CGO_ENABLED=0` cross-build: Punaro's
   platform-specific private-file checks are part of the security boundary,
   and a cross-built binary is not a valid deployment candidate merely because
   its process starts. Windows releases must likewise use the repository's
   Windows installer/build path and retain the current-user ACL checks.
   Before changing any service, map the public adapter URL to its exact daemon
   and listener. A tunnel may route `/readyz` to a separate health origin, so a
   successful readiness request alone does not prove which daemon handles
   signed `/v1/` requests. Record the service manager, process, listener, and
   deployed commit or image for the device origin and health origin separately;
   prove the device origin with one harmless signed request before treating it
   as release evidence. If two `punarod` processes or installations exist on
   one host, stop and identify their routes rather than upgrading both by
   assumption.
2. For a **new** machine, first check whether the server has completed mail
   cutover. Run the client installer *without* enablement only when the machine
   can still be enrolled safely. It creates a fresh machine key and prints the
   public enrollment record. Before cutover, add only that record to the
   complete relay enrollment set, apply it through `punaro relay configure`
   and `punaro up`, and verify relay readiness. Then create a new Access
   service token for the machine, install it only in that machine's owner-only
   profile, bind and attach its aliases, and enable the adapter. Verify the
   Service Auth rule with the unsigned-API `401` check above before interpreting
   adapter failures as machine-enrollment failures.

   After mail cutover, use `punaro relay register` with that single public
   enrollment object, followed by `punaro up`; ordinary `relay configure`
   deliberately rejects the unknown key. Device-credential enrollment remains
   separate and does not make a mailbox Ed25519 key eligible. Do not copy
   another machine's key, edit `punarod.env`, alter the installation marker, or
   write authority rows by hand. Keep the adapter disabled until registration,
   relay readiness, its distinct Access Service Auth probe, and endpoint
   attachment all succeed.
   The authenticated device listener must remain loopback-only. When a legacy
   tunnel still targets a private-LAN listener, first stage the candidate on an
   unused loopback address, update the tunnel origin with an explicit rollback
   to the prior origin, and prove a signed request reaches the staged process.
   Do not make a LAN listener acceptable by editing generated environment or
   marker files; current candidates deliberately refuse that topology.
3. For an **existing** machine, rerun the same installer from the clean
   checkout using the original relay URL and machine ID. The installer proves
   that the existing key, enrollment record, and profile still belong to those
   values before it replaces the adapter binary and managed service file. It
   does not rewrite the token pair. Never delete an existing key merely to
   make this check pass.
4. Enable or restart only through the installed platform service:

   ```sh
   # macOS and Linux: append --enable to the installer invocation.
   # macOS verification
   launchctl print gui/$(id -u)/org.punaro.adapter

   # Linux verification
   systemctl --user status punaro-adapter.service
   ```

   ```powershell
   # Windows: append -Enable to the installer invocation.
   Get-ScheduledTask -TaskName 'Punaro Adapter'
   Get-Process punaro-adapter -ErrorAction SilentlyContinue
   ```

   The Windows task is intentionally per-user and interactive; a disabled task
   or missing process is not a deployed adapter. For a Linux machine that must
   remain available after logout, enable user lingering before relying on it.
5. Confirm the adapter has advertised only the newly attached aliases, then
   run a disposable, harmless message/acknowledgement check. For release
   candidates, use the [durable-role LAN validation runbook](durable-role-lan-e2e.md)
   rather than reusing a production conversation or endpoint.

If a binary or service update fails before the adapter is healthy, stop the
updated service, return to the retained clean checkout at the prior verified
commit, rerun the same installer with the same identity values, and verify the
service again. Do not restore, edit, or copy private keys, Access tokens,
mailbox state, relay databases, or production conversations as part of an
adapter rollback. Relay rollback follows the owner-managed deployment's
recorded image/commit and database recovery process; it is not an adapter
installer operation.

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

The sidecar contains only version `1`, the fixed canonical HTTPS or literal
loopback HTTP origin, the opaque client binding, and (during a legacy
transition) the exact legacy machine ID. Non-loopback trusted-LAN HTTP uses
version `2` with its explicit acknowledgement and containing CIDR. It never
contains an enrollment code, bearer credential, private key, Access token,
project grant, or mailbox address. The adapter refuses a
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

For a same-host listener, literal loopback HTTP uses the same zero-policy
version-one state and needs no trusted-LAN flags:

```sh
punaro-enroll prepare \
  --origin http://127.0.0.1:8080 \
  --state-dir "$HOME/.config/punaro/device-enrollment"
```

This exception is limited to literal loopback addresses. DNS names and private
or link-local addresses still fail unless they use HTTPS or the explicit
trusted-LAN policy described below.

For a registered legacy adapter or gateway, bind preparation to its exact
existing machine ID:

```sh
punaro-enroll prepare \
  --origin https://punaro.example \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --legacy-machine-id EXISTING_MACHINE_ID
```

The command prints only the canonical origin and an opaque `client_binding`.
Give that public value to the server owner. The owner previews and creates the
least-privilege grant with `punaro-admin client invite --machine-id ID`; the
owner chooses the unique machine ID and projects, and neither can be overridden
by the client. With `--yes`, that command
prints the confirmed preview followed by the pending enrollment object. Treat
the complete exact output as short-lived enrollment material: transfer it
unchanged through an approved protected channel into a current-user-only regular
file on that client. Do not paste it
into terminal commands, shell history, environment variables, diagnostic
bundles, or source-controlled configuration.
For a legacy exchange the owner also supplies the exact content-free
`--legacy-principal-id` from `punaro-admin legacy list`; the new machine ID must
remain the existing registered machine ID.

For a non-agent service probe such as server doctor, the owner uses
`--service` instead of `--project` or `--all-projects`. Its exact preview has an
empty `grants` array and grants no project, conversation, memory, attachment,
or installation capability. `--service` is mutually exclusive with project
scope and legacy exchange; the resulting device credential authenticates only
routes that require no capability grant.

Windows file transfer tools commonly leave the destination with an inherited
ACL. Before redemption, tighten that exact transferred file without displaying
or parsing its contents:

```powershell
punaro-enroll protect-material `
  --file C:\absolute\private\enrollment-material.json
```

The command accepts only an absolute regular file within the enrollment size
bound, refuses a directory, reparse point, or replacement race, and replaces
the inherited ACL with exactly one protected FullControl ACE for the current
user. It does not weaken or modify parent directories. `redeem` then performs
the normal strict private-file and enrollment-document validation. On
macOS/Linux the same command is available when a transfer tool has broadened
the mode; it verifies current-user ownership and changes only that exact file
to `0600`.

Redeem that protected file on the client:

```sh
punaro-enroll redeem \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --enrollment-file /absolute/private/enrollment-material.json \
  --credential-file "$HOME/.config/punaro/device-enrollment/device.credential"
```

For the legacy state prepared above, add only the absolute protected old-key
file path. The client signs a transcript binding the one-time material,
idempotency key, and decoded code digest, and sends the public key and signature
to the dedicated exchange route; it never sends or prints the private key:

```sh
punaro-enroll redeem \
  --state-dir "$HOME/.config/punaro/device-enrollment" \
  --enrollment-file /absolute/private/enrollment-material.json \
  --credential-file "$HOME/.config/punaro/device-enrollment/device.credential" \
  --legacy-private-key-file /absolute/private/existing-machine.key
```

Repeat the same legacy-key-file option with `recover` after an interrupted
exchange. A wrong key, unregistered key, stale material, or already retired
identity returns the same content-free rejection.

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
only the canonical validated origin selected during `prepare`, and writes a
private recovery journal before redemption. If a network interruption occurs,
rerun the same `redeem` command; if the transfer file is gone, use `punaro-enroll
recover` with the state and credential paths, and include the same
`--access-file` when the origin is Access-protected. The retry has the same
idempotency key, so it cannot mint a second device credential. A legacy journal
also binds the non-secret public key; supplying a different private-key file is
rejected locally without contacting the server or discarding recovery state.
The server retains that
recovery record while its non-expiring credential and principal remain active;
after revocation or disablement, request a new enrollment. A rejected (including
expired-first-use, already-used, or revoked) enrollment fails closed and tells the user
to request a new enrollment; its private recovery journal is removed so the
replacement material is not blocked. After success, remove the transferred material
through its approved secret-handling process; the identity sidecar remains
non-secret and the recovery journal is removed.

For a legacy adapter or Telegram gateway, successful redemption only marks the
server inventory `migrated` and stages the protected bearer credential. Keep
the service running with its unchanged `PUNARO_MACHINE_PRIVATE_KEY_FILE` while
the remaining legacy machines migrate. A bearer cannot authenticate the relay
until the owner completes mail cutover and restarts the server with the
published PostgreSQL relay and credential-transition settings; switching the
profile earlier takes the client offline.

Only after that server activation succeeds, replace
`PUNARO_MACHINE_PRIVATE_KEY_FILE=...` with exactly one absolute
`PUNARO_DEVICE_CREDENTIAL_FILE=/absolute/private/device.credential` entry, keep
the same `PUNARO_MACHINE_ID`, relay origin, Access pair, and endpoint authority,
then restart the client service and require its doctor report to pass. Never
retain both credential entries. The adapter and gateway load the bearer only
from the protected file, send it only in the `Authorization` header, and never
place it in argv, environment values, reports, or logs. Keep the old private
key until the new doctor probe passes; remove it later through the approved
secret-retirement process.

The server owner lists and permanently revokes installed clients with
`punaro-admin client list` and `punaro-admin client revoke`, using only
content-free lifecycle inventory. Credential rotation remains available through
`punaro-admin credential rotate`; the old credential revoke command delegates
to whole-client revocation. A local identity sidecar or copied credential cannot
restore access.

## 5. Retired v2/v3 attachment evidence

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

The same installer on macOS, Linux, and Windows also builds `punaro-memory`, the native
client for an already enabled M-17 memory API. Supply the fixed HTTPS origin,
an absolute owner-only device credential file, and explicit project/key/ETag
coordinates, or write a protected non-secret profile containing only the
origin, credential-file path, and optional default project; see the
[operator guide](operator-guide.md#native-memory-client). The same binary can
run as a local stdio MCP server with `punaro-memory mcp --profile ...`; this is
local profile-backed MCP, not the later remote OAuth MCP gateway. On Windows,
store both the profile and credential in files protected by the current-user-only
ACL that the installer uses below `%LOCALAPPDATA%\Punaro`; reparse points,
shared ACLs, and replacement races fail closed.

## Agent mailbox behavior

Agents use the local Waypost MCP, not a remote Punaro MCP. Call
`waypost_status` once, then call non-blocking `waypost_recv` to claim mail and
`waypost_ack` with the exact returned delivery ID and lease token after
handling it. For a bounded blocking wait, call
`waypost_status(include_cli_context=true)`, then run only the reported CLI and
state directory with `wait --for BOUND_ADDRESS --timeout 5m --json`; claim the
result through `waypost_recv`. Repeat bounded waits during long-running work.
A complete legacy `mailbox_status` / `mailbox_wait` / `mailbox_recv` /
`mailbox_ack` MCP surface remains supported during rolling migration, but one
claim must never mix tool families. A WebSocket wake
accelerates adapter polling only; it does not itself create a model turn. The durable fetch/ack path
remains correct through sleep, reconnect, or missed wake events. A successful `punaro-adapter send` proves relay acceptance only
(`accepted/queued`); it is not a mailbox acknowledgement or an agent action.
