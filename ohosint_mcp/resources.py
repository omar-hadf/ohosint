"""Skill manifests exposed as MCP resources.

Each ``skills/*/SKILL.md`` becomes a resource a client can read to understand
the method (why every step stays passive) before invoking the matching tools.
"""

from __future__ import annotations

from pathlib import Path

_SKILLS_ROOT = Path(__file__).resolve().parent.parent / "skills"

_SKILL_DIRS = {
    "silent-recon": "silent-recon",
    "silent-account-finder": "silent-account-finder",
    "tor-proxy": "tor-proxy",
}

_OVERVIEW = """\
# OHOsint skills overview

This server exposes three reviewed skill manifests as resources.

- skills://silent-recon — the general passive OSINT process (name/email/phone/
  username -> identity cluster): normalize, passive lookups, candidate
  generation, handle sweep, dorks, autopsy, pivot loop.
- skills://silent-account-finder — email -> adult-platform (XNXX/XVideos)
  profile locator; 100% GET-based, never triggers recovery flows.
- skills://tor-proxy — route any tool's traffic through Tor without root, with
  the DNS-leak and socksio pitfalls.

Read a skill with `skills://<name>`, then drive the matching tools.
"""


def _skill_text(name: str) -> str:
    dirname = _SKILL_DIRS.get(name)
    if dirname is None:
        return f"unknown skill {name!r}; available: {sorted(_SKILL_DIRS)}"
    path = _SKILLS_ROOT / dirname / "SKILL.md"
    if not path.exists():
        return f"skill manifest not found at {path}"
    return path.read_text(encoding="utf-8")


def register_resources(mcp) -> None:
    """Register skill-manifest resources and a synthesis overview."""

    @mcp.resource("skills://silent-recon")
    def silent_recon() -> str:
        """The general passive OSINT method (silent-recon SKILL.md)."""
        return _skill_text("silent-recon")

    @mcp.resource("skills://silent-account-finder")
    def silent_account_finder() -> str:
        """Email -> adult-platform (XNXX/XVideos) profile locator (SKILL.md)."""
        return _skill_text("silent-account-finder")

    @mcp.resource("skills://tor-proxy")
    def tor_proxy() -> str:
        """Route tools through Tor without root (SKILL.md)."""
        return _skill_text("tor-proxy")

    @mcp.resource("skills://overview")
    def overview() -> str:
        """Index of the available skill resources and what each is for."""
        return _OVERVIEW


def skill_names() -> list:
    return sorted(_SKILL_DIRS)
