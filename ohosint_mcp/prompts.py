"""MCP prompts that guide an LLM through the OSINT workflow.

Prompts are reusable templates: the client fills in the target and the prompt
steers the model toward the correct tool sequence and the passivity rules.
"""

from __future__ import annotations

from typing import Optional


def _plan_prompt(target: str) -> str:
    return (
        f"You are planning a lawful, passive OSINT investigation of {target!r}.\n"
        "1. Call the `osint_plan` tool with this target to get the detailed, "
        "phased plan.\n"
        "2. Read the `skills://overview` resource and any relevant "
        "`skills://<name>` resource to understand the method.\n"
        "3. Present the plan to the user phase by phase, explaining which tool "
        "you will call at each step and why the step never notifies the target.\n"
        "4. Do not execute any tool until the user approves, unless they asked "
        "for full automation.\n"
        "5. Display only the pertinent results in structured form (tables, "
        "headings, code blocks) — skip empty and throttled sources.\n"
        "Remember the hard rules: GET-only, no account creation, no recovery "
        "flows, randomized delays, Tor recommended, lawful purpose required."
    )


def _workflow_prompt(target: str) -> str:
    return (
        f"Run an automated, passive OSINT investigation of {target!r}.\n"
        "1. Call `configure` to route through Tor and set polite delays.\n"
        "2. Call `tor_check` to confirm the exit IP is a Tor relay.\n"
        "3. Call `run_investigation` (depth='fast') to gather initial findings.\n"
        "4. Follow `next_steps` from the result: run the granular tools "
        "(`investigate_email`, `sweep_username`, `breach_search`, `search_dork`, "
        "`autopsy_url`, `pivot_results`, …) as the plan dictates.\n"
        "5. Loop the pivot phase until no new identifiers appear.\n"
        "6. Summarize findings and flag anything that looks like a true negative "
        "vs a throttled source (rotate_tor_circuit before retrying).\n"
        "7. Render the pertinent findings in structured markdown (tables, "
        "headings, code blocks), omitting empty or throttled sources.\n"
        "Stay passive and lawful throughout."
    )


def register_prompts(mcp) -> None:
    """Register the planning and automation prompts."""

    @mcp.prompt()
    def plan_investigation(target: str) -> str:
        """Generate a detailed investigation plan for a target (planning only)."""
        return _plan_prompt(target)

    @mcp.prompt()
    def run_osint_workflow(target: str, target_type: Optional[str] = None) -> str:
        """Guide a fully-automated passive OSINT workflow for a target."""
        base = _workflow_prompt(target)
        if target_type:
            base += f"\nThe target type is {target_type}."
        return base
