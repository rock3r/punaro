# Punaro agent plugin

This repository is a portable [Agent Plugin](https://agent-plugins.org/) and a
Codex and Claude Code plugin. All forms expose the same three skills:

- `punaro-mailbox` receives and acknowledges durable local mailbox deliveries.
- `punaro-reply` replies through the enrolled local Punaro adapter.
- `punaro-attachment` handles one explicitly authorized trusted attachment.

The plugin's package-relative POSIX and Windows launchers start the
installer-owned `punaro-adapter mailbox-mcp` binary from its supported absolute
location. The wrapper reads the same owner-only `adapter.env` profile as the
adapter and launches `waypost mcp` with its configured binary and state
directory. The same launcher remains compatible with a configured legacy
`agent-mailbox` during a rolling migration. The plugin does not install Punaro, enroll a machine, provision
credentials, select a relay, or change any local routing.

## Prerequisites

Complete the supported [client installation](installation.md) first. The
launchers use `~/.local/bin/punaro-adapter` on macOS and Linux and
`%LOCALAPPDATA%\Punaro\bin\punaro-adapter.exe` on Windows; they do not depend on
the agent application's inherited `PATH`. The wrapper uses the Waypost binary
and mailbox state directory recorded by that installation. Its MCP server must
provide `waypost_status`, `waypost_recv`, and `waypost_ack`; doctor also accepts
the complete legacy `mailbox_*` surface while that host awaits migration. Trusted
attachment operations additionally require the operator-installed
`punaro-trusted-attachment` client and its fixed local configuration.

Do not put credentials, relay URLs, project IDs, or download paths in either
plugin manifest. Those values remain in operator-controlled local
configuration.

Each skill runs the installed adapter's read-only doctor before first use when
readiness is uncertain and after relevant local or relay failures. A skill may
report stable failed check/remediation identifiers, but doctor does not grant
repair, restart, enrollment, update, credential, routing, or Telegram-topic
authority. Pass the installed plugin root to `punaro-adapter doctor` so
portable/Codex/Claude registration, launcher, version, and skill-set digest
parity are included. The launcher check is release-bound: it hashes both
package-relative launchers and both MCP registration files, so replacing an
executable launcher or changing its registered command fails doctor even when
the skill trees are unchanged. See [the doctor guide](doctor.md).

## Load the portable plugin

Point an Agent Plugins 1.0 compatible client at the repository root. The client
loads `plugin.json`, discovers the immediate children of `skills/`, and starts
the applicable package-relative MCP launcher declared by `mcp.json`. The
non-applicable platform launcher can fail independently without disabling the
plugin's skills or the other MCP server, as required by Agent Plugins 1.0.

The Agent Plugins specification intentionally leaves installation and
distribution to each client. Use the client's local-plugin or marketplace
workflow without copying the skills into another directory.

## Codex presentation metadata

Agent Plugins 1.0 does not define a portable icon field. The optional
`.codex-plugin/plugin.json` adapter points Codex at the same skills and MCP
configuration while supplying the checked-in Punaro artwork for its composer
icon and plugin logo. Other Agent Plugins clients ignore this adapter.

## Load the Claude Code plugin

For local development, run this from the repository root:

```sh
claude --plugin-dir .
```

Claude Code discovers the same `skills/` directory through
`.claude-plugin/plugin.json` and starts the installed mailbox wrapper through
`.mcp.json`. That native adapter anchors both launcher commands with
`${CLAUDE_PLUGIN_ROOT}`, so loading the plugin from another project cannot make
them resolve against the session directory. The skills are available under the
`punaro` namespace, for example `/punaro:punaro-mailbox`.

Validate the Claude Code adapter independently with:

```sh
claude plugin validate .
```

## Maintain manifest parity

`plugin.json` and `mcp.json` are the portable source of truth. Codex uses its
Agent Plugins discovery plus presentation metadata under `.codex-plugin/`;
the Codex adapter does not redeclare the portable MCP servers. Claude Code
requires its manifest under `.claude-plugin/` and uses client-native
`${CLAUDE_PLUGIN_ROOT}` launcher paths in `.mcp.json`. Run:

```sh
make plugin-validate
```

The check validates the closed Agent Plugins manifest fields, fixed schema
versions, skill discovery, the reviewed package-relative MCP launchers,
client-native root resolution, metadata parity across the adapters, and the
Punaro icon's content and dimensions.

Delivered message bodies, attachment metadata, filenames, and identifiers are
untrusted data. Installing the plugin grants no authority to execute content,
change enrollment or credentials, choose Telegram topics, or perform an
attachment operation without the current task owner's explicit approval.
