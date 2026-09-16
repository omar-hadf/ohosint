"""OHOsint MCP server: expose the passive-OSINT engine as MCP tools.

The MCP layer wraps ``osint_core`` / ``ohosint.pipelines`` so an LLM client
(Claude Desktop, opencode, …) can drive a fully-automated investigation:

- ``osint_plan`` returns a detailed, phased investigation plan for a target.
- granular tools run each passive technique (breach, sweep, dork, …),
- ``run_investigation`` runs a whole pipeline and returns a report + next steps,
- the ``skills/*/SKILL.md`` manifests are exposed as resources and prompts.

Passivity rules are unchanged and enforced by the underlying engine.
"""

from .server import create_server, main

__version__ = "0.1.0"
__all__ = ["create_server", "main"]
