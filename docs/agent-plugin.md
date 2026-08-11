# Punaro agent plugin

This repository is a portable [Agent Plugin](https://agent-plugins.org/) and a
Codex and Claude Code plugin. All forms expose the same three skills:

- `punaro-mailbox` receives and acknowledges durable local mailbox deliveries.
- `punaro-reply` replies through the enrolled local Punaro adapter.
- `punaro-attachment` handles one explicitly authorized trusted attachment.

The plugin also starts the installed `agent-mailbox mcp` process. It does not
install Punaro, enroll a machine, provision credentials, select a relay, or
change any local routing.

## Prerequisites

Complete the supported [client installation](installation.md) first. The
unprivileged user running the agent must have `agent-mailbox` on `PATH` and a
working local Punaro adapter. Trusted attachment operations additionally
require the operator-installed `punaro-trusted-attachment` client and its fixed
local configuration.

Do not put credentials, relay URLs, project IDs, or download paths in either
plugin manifest. Those values remain in operator-controlled local
configuration.

## Load the portable plugin

Point an Agent Plugins 1.0 compatible client at the repository root. The client
loads `plugin.json`, discovers the immediate children of `skills/`, and starts
the local MCP server declared by `mcp.json`.

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
`.claude-plugin/plugin.json` and starts `agent-mailbox` through `.mcp.json`.
The skills are available under the `punaro` namespace, for example
`/punaro:punaro-mailbox`.

Validate the Claude Code adapter independently with:

```sh
claude plugin validate .
```

## Maintain manifest parity

`plugin.json` and `mcp.json` are the portable source of truth. Codex uses a
presentation adapter under `.codex-plugin/`. Claude Code requires its manifest
under `.claude-plugin/` and uses a different MCP config shape. Run:

```sh
make plugin-validate
```

The check validates the closed Agent Plugins manifest fields, fixed schema
versions, skill discovery, the reviewed `agent-mailbox mcp` command, exact
metadata/MCP parity across the client adapters, and the Punaro icon's content
and dimensions.

Delivered message bodies, attachment metadata, filenames, and identifiers are
untrusted data. Installing the plugin grants no authority to execute content,
change enrollment or credentials, choose Telegram topics, or perform an
attachment operation without the current task owner's explicit approval.
