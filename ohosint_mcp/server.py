"""OHOsint MCP server entry point.

Builds a FastMCP server that exposes the passive-OSINT engine as tools,
the ``skills/*/SKILL.md`` manifests as resources, and planning/automation
prompts. Runs over stdio by default (Claude Desktop / opencode compatible).
"""

from __future__ import annotations

from fastmcp import FastMCP

from .prompts import register_prompts
from .resources import register_resources
from .tools import register_tools

_INSTRUCTIONS = """\
OHOsint is a passive OSINT engine exposed as MCP tools. It is for lawful,
authorized use only: your own accounts, authorized assessments, or an active
legal case.

Workflow:
1. Call `osint_plan` (or `run_investigation`) with the target to get a detailed
   plan and findings.
2. Read `skills://overview` and the relevant `skills://<name>` resource for the
   method before running anything.
3. Execute the granular tools the plan names, then use `pivot_results` and loop
   until no new identifiers appear.

Hard rules (enforced by the engine): GET-only against public pages and
third-party APIs; never POST to login/recovery/OTP endpoints; no account
creation or credential use; randomized delays; Tor via
`configure(proxy=\"socks5h://127.0.0.1:9050\")`.

Presentation rule: surface only the pertinent results in a structured format
— markdown tables for sweep/breach/candidate hits, a heading per phase or
source, and fenced code blocks for raw JSON or credential lines. Skip empty,
throttled, and noise results; keep status/confidence/error fields only where
they change how a finding should be read.

Reports may contain personal data and breach results may contain leaked
credentials — handle them responsibly and never republish them.
"""


def create_server() -> FastMCP:
    """Build and return the fully-configured FastMCP server."""
    mcp = FastMCP("ohosint", instructions=_INSTRUCTIONS)
    register_tools(mcp)
    register_resources(mcp)
    register_prompts(mcp)
    return mcp


mcp = create_server()


def main() -> None:
    """Run the server over stdio (the default MCP transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
