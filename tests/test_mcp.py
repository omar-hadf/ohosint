"""Tests for the MCP server layer (planner + tool wiring).

Planner tests are pure (no network). Server-build tests only assert that tools,
resources, and prompts register — they never execute a network call, so they
respect the ``_block_network`` safety rail.
"""

import pytest

from ohosint_mcp.planner import TARGET_TYPES, build_plan, detect_target_type


class TestDetectTargetType:
    @pytest.mark.parametrize(
        "target,expected",
        [
            ("user@example.com", "email"),
            ("jane.doe@example.co.uk", "email"),
            ("+14155550123", "phone"),
            ("415-555-0123", "phone"),
            ("example.com", "domain"),
            ("sub.example.org", "domain"),
            ("Jane Doe", "name"),
            ("jdoe", "username"),
            ("jane_doe94", "username"),
        ],
    )
    def test_detection(self, target, expected):
        assert detect_target_type(target) == expected

    def test_empty_target_raises(self):
        with pytest.raises(ValueError):
            detect_target_type("")


class TestBuildPlan:
    def test_plan_structure(self):
        plan = build_plan("user@example.com")
        assert plan["target"] == "user@example.com"
        assert plan["target_type"] == "email"
        assert plan["hard_rules"]
        assert plan["skills"]
        assert plan["phases"]
        assert plan["phases"][0]["name"].startswith("OPSEC")
        assert plan["plan_text"].startswith("# OSINT plan")

    def test_every_phase_has_steps(self):
        for ttype in TARGET_TYPES:
            target = {
                "email": "a@b.co",
                "phone": "+14155550123",
                "name": "Jane Doe",
                "username": "jdoe",
                "domain": "example.com",
            }[ttype]
            plan = build_plan(target, ttype)
            for phase in plan["phases"]:
                assert phase["steps"], f"{ttype} phase {phase['phase']} empty"

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            build_plan("jdoe", "bogus")

    def test_plan_mentions_real_tool_names(self):
        plan = build_plan("user@example.com")
        text = plan["plan_text"]
        assert "osint_plan" in text or "configure" in text


class TestStdoutCapture:
    def test_run_captures_stdout(self):
        from ohosint_mcp.tools import _run

        def noisy():
            print("progress line")
            return {"ok": True}

        assert _run(noisy) == {"ok": True, "logs": ["progress line"]}

    def test_run_wraps_exceptions(self):
        from ohosint_mcp.tools import _run

        def boom():
            raise RuntimeError("boom")

        out = _run(boom)
        assert out["error"] == "boom"
        assert out["error_type"] == "RuntimeError"


class TestServerBuild:
    @pytest.mark.asyncio
    async def test_registers_tools_resources_prompts(self):
        pytest.importorskip("fastmcp")
        from ohosint_mcp.server import create_server

        mcp = create_server()
        tools = {t.name for t in await mcp.list_tools()}
        resources = {str(r.uri) for r in await mcp.list_resources()}
        prompts = {p.name for p in await mcp.list_prompts()}

        assert "osint_plan" in tools
        assert "run_investigation" in tools
        assert "sweep_username" in tools
        assert "breach_search" in tools
        assert "configure" in tools
        assert "skills://silent-recon" in resources
        assert "skills://overview" in resources
        assert "plan_investigation" in prompts
        assert "run_osint_workflow" in prompts

    @pytest.mark.asyncio
    async def test_generate_candidates_tool_is_offline(self):
        pytest.importorskip("fastmcp")
        from ohosint_mcp.server import create_server

        mcp = create_server()
        result = await mcp.call_tool("generate_candidates", {"seed": "jane.doe94"})
        content = result.structured_content
        assert content["seed"] == "jane.doe94"
        assert any("jane" in c for c in content["candidates"])
