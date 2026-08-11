#!/usr/bin/env python3
"""Validate Punaro's portable Agent Plugin and Claude Code adapter."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
CLAUDE_SCHEMA = "https://json.schemastore.org/claude-code-plugin-manifest.json"
REQUIRED_SKILLS = {"punaro-mailbox", "punaro-reply", "punaro-attachment"}
SKILL_LAUNCHERS = {
    "punaro-reply": "punaro-adapter",
    "punaro-attachment": "punaro-trusted-attachment",
}
PORTABLE_FIELDS = {
    "$schema",
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "extensions",
}
SHARED_METADATA = {
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
}
PUNARO_ICON = "./assets/punaro.png"
PUNARO_ICON_SHA256 = "5cf8313cbe88e41887db89b0ecd7a668c622416ea83369fc0ec7da4f72b5a353"


class ValidationError(RuntimeError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"missing regular file: {relative_path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError(f"invalid JSON in {relative_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"expected a JSON object in {relative_path}")
    return value


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def validate_portable_manifest() -> dict[str, Any]:
    manifest = load_json("plugin.json")
    unknown = set(manifest) - PORTABLE_FIELDS
    if unknown:
        raise ValidationError(f"plugin.json has unknown fields: {sorted(unknown)}")
    if manifest.get("$schema") != PLUGIN_SCHEMA:
        raise ValidationError("plugin.json targets the wrong Agent Plugins schema")
    name = require_string(manifest.get("name"), "plugin.json name")
    if name != "punaro" or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?", name):
        raise ValidationError("plugin.json name must be the valid stable name 'punaro'")
    if "--" in name or ".." in name:
        raise ValidationError("plugin.json name contains a forbidden repeated separator")
    require_string(manifest.get("version"), "plugin.json version")
    require_string(manifest.get("description"), "plugin.json description")
    require_string(manifest.get("homepage"), "plugin.json homepage")
    require_string(manifest.get("repository"), "plugin.json repository")
    require_string(manifest.get("license"), "plugin.json license")
    author = manifest.get("author")
    if not isinstance(author, dict) or not author or set(author) - {"name", "email", "url"}:
        raise ValidationError("plugin.json author must use only name, email, and url")
    for key, value in author.items():
        require_string(value, f"plugin.json author.{key}")
    keywords = manifest.get("keywords")
    if not isinstance(keywords, list) or not keywords or not all(isinstance(item, str) and item for item in keywords):
        raise ValidationError("plugin.json keywords must be a non-empty string array")
    return manifest


def validate_skills() -> None:
    skills_root = ROOT / "skills"
    discovered = {path.name for path in skills_root.iterdir() if path.is_dir() and not path.is_symlink()}
    missing = REQUIRED_SKILLS - discovered
    if missing:
        raise ValidationError(f"missing required Punaro skills: {sorted(missing)}")
    for skill_name in sorted(discovered):
        skill_path = skills_root / skill_name / "SKILL.md"
        if not skill_path.is_file() or skill_path.is_symlink():
            raise ValidationError(f"skill is missing a regular SKILL.md: {skill_name}")
        text = skill_path.read_text(encoding="utf-8")
        match = re.match(r"\A---\n(.*?)\n---\n", text, flags=re.DOTALL)
        if match is None:
            raise ValidationError(f"skill has invalid frontmatter: {skill_name}")
        frontmatter = match.group(1)
        if not re.search(rf"(?m)^name:\s*{re.escape(skill_name)}\s*$", frontmatter):
            raise ValidationError(f"skill name does not match its directory: {skill_name}")
        if not re.search(r"(?m)^description:\s*\S", frontmatter):
            raise ValidationError(f"skill has no description: {skill_name}")

    for skill_name, command in SKILL_LAUNCHERS.items():
        skill_root = skills_root / skill_name
        text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        for relative_path in (f"scripts/{command}", f"scripts/{command}.cmd"):
            launcher = skill_root / relative_path
            if not launcher.is_file() or launcher.is_symlink():
                raise ValidationError(f"skill launcher must be a regular package file: {skill_name}/{relative_path}")
            if relative_path not in text:
                raise ValidationError(f"skill does not reference its package launcher: {skill_name}/{relative_path}")
        if not os.access(skill_root / "scripts" / command, os.X_OK):
            raise ValidationError(f"POSIX skill launcher must be executable: {skill_name}/{command}")
        posix_launcher = (skill_root / "scripts" / command).read_text(encoding="utf-8")
        if f'.local/bin/{command}' not in posix_launcher or "PATH" in posix_launcher:
            raise ValidationError(f"POSIX skill launcher must use the installer-owned path: {skill_name}/{command}")
        if "set --" in posix_launcher:
            raise ValidationError(f"POSIX skill launcher must preserve forwarded arguments: {skill_name}/{command}")
        windows_launcher = (skill_root / "scripts" / f"{command}.cmd").read_text(encoding="utf-8")
        if f"%LOCALAPPDATA%\\Punaro\\bin\\{command}.exe" not in windows_launcher or "%PATH%" in windows_launcher:
            raise ValidationError(f"Windows skill launcher must use the installer-owned path: {skill_name}/{command}")

    if os.name == "posix":
        with tempfile.TemporaryDirectory(prefix="punaro-skill-launchers-") as fixture:
            home = Path(fixture)
            bin_dir = home / ".local" / "bin"
            bin_dir.mkdir(parents=True)
            for skill_name, command in SKILL_LAUNCHERS.items():
                installed = bin_dir / command
                installed.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n", encoding="utf-8")
                installed.chmod(0o700)
                launcher = skills_root / skill_name / "scripts" / command
                result = subprocess.run(
                    [str(launcher), "pathless-test", "forwarded argument"],
                    check=True,
                    capture_output=True,
                    text=True,
                    env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                )
                if result.stdout != "pathless-test forwarded argument\n":
                    raise ValidationError(f"skill launcher did not forward arguments: {skill_name}/{command}")


def validate_mcp() -> dict[str, Any]:
    config = load_json("mcp.json")
    if set(config) != {"$schema", "mcpServers"} or config.get("$schema") != MCP_SCHEMA:
        raise ValidationError("mcp.json must use the closed Agent Plugins 1.0.0 shape")
    servers = config.get("mcpServers")
    expected = {
        "agent-mailbox": {
            "type": "stdio",
            "command": "./scripts/punaro-plugin-mcp",
        },
        "agent-mailbox-windows": {
            "type": "stdio",
            "command": "./scripts/punaro-plugin-mcp.cmd",
        },
    }
    if servers != expected:
        raise ValidationError("mcp.json mailbox servers drifted from the reviewed package launchers")
    for server in expected.values():
        launcher = ROOT / server["command"].removeprefix("./")
        if not launcher.is_file() or launcher.is_symlink():
            raise ValidationError(f"mailbox launcher must be a regular package file: {launcher.name}")
    if not os.access(ROOT / "scripts/punaro-plugin-mcp", os.X_OK):
        raise ValidationError("POSIX mailbox launcher must be executable")
    return config


def validate_claude_adapter(portable: dict[str, Any], portable_mcp: dict[str, Any]) -> None:
    manifest = load_json(".claude-plugin/plugin.json")
    if manifest.get("$schema") != CLAUDE_SCHEMA:
        raise ValidationError("Claude manifest uses the wrong schema")
    for field in SHARED_METADATA:
        if manifest.get(field) != portable.get(field):
            raise ValidationError(f"Claude manifest metadata drifted: {field}")
    if manifest.get("displayName") != "Punaro":
        raise ValidationError("Claude manifest displayName must be Punaro")

    config = load_json(".mcp.json")
    expected_servers = {
        name: {
            "command": "${CLAUDE_PLUGIN_ROOT}/" + server["command"].removeprefix("./"),
        }
        for name, server in portable_mcp["mcpServers"].items()
    }
    if config != {"mcpServers": expected_servers}:
        raise ValidationError(".mcp.json drifted from the Claude plugin-root launchers")


def validate_codex_adapter(portable: dict[str, Any]) -> None:
    manifest = load_json(".codex-plugin/plugin.json")
    for field in SHARED_METADATA:
        if manifest.get(field) != portable.get(field):
            raise ValidationError(f"Codex manifest metadata drifted: {field}")
    if manifest.get("skills") != "./skills/" or "mcpServers" in manifest:
        raise ValidationError("Codex manifest must use shared skills and default portable MCP discovery")

    interface = manifest.get("interface")
    if not isinstance(interface, dict):
        raise ValidationError("Codex manifest is missing interface metadata")
    if interface.get("composerIcon") != PUNARO_ICON or interface.get("logo") != PUNARO_ICON:
        raise ValidationError("Codex manifest does not use the Punaro icon")

    icon_path = ROOT / PUNARO_ICON.removeprefix("./")
    if not icon_path.is_file() or icon_path.is_symlink():
        raise ValidationError("Punaro icon must be a regular in-package file")
    icon = icon_path.read_bytes()
    if hashlib.sha256(icon).hexdigest() != PUNARO_ICON_SHA256:
        raise ValidationError("Punaro icon differs from the README artwork")
    if icon[:8] != b"\x89PNG\r\n\x1a\n" or len(icon) < 24:
        raise ValidationError("Punaro icon is not a valid PNG header")
    width, height = struct.unpack(">II", icon[16:24])
    if (width, height) != (622, 839):
        raise ValidationError("Punaro icon dimensions differ from the README artwork")


def main() -> None:
    portable = validate_portable_manifest()
    validate_skills()
    portable_mcp = validate_mcp()
    validate_claude_adapter(portable, portable_mcp)
    validate_codex_adapter(portable)
    print("agent_plugin_tests_passed")


if __name__ == "__main__":
    try:
        main()
    except ValidationError as exc:
        raise SystemExit(f"agent plugin validation failed: {exc}") from exc
