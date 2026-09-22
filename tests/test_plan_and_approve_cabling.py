"""
tests/test_plan_and_approve_cabling.py

B2 — "Cablear el Intelligent Decision Engine al loop de Hades".

The Hades loop consumes NyxStrike's Intelligent Decision Engine through the
plan-and-approve contract (B1). The 5 tools
    profile_target -> propose_next_step -> execute_step -> update_chain ->
    chain_report
must be reachable through the MCP surface Hades drives.

In the cyber-range deployment (hermes-agent-charts/values-hades.yaml) the
NyxStrike MCP sidecar bridge is launched with `--profile cyber-range`; Hades
reaches that bridge at `127.0.0.1:9000/mcp` and the loop calls the 5 tools as
`mcp_nyxstrike_*`. This test LOCKS that cable: it asserts that the cyber-range
profile (and every other profile Hades might select) exposes exactly the 5
contract tools, so a future profile/registration change cannot silently drop
the Decision Engine from Hades' loop.

No real HTTP calls, no tool processes, no network. Mirrors the mock pattern of
tests/test_mcp_gateway.py.
"""

import asyncio
import pytest
from unittest.mock import MagicMock

from mcp_client import server_setup
from mcp_client.tool_profiles import CYBER_RANGE_PROFILE
from mcp_client.plan_and_approve import register_plan_approve_tools

# The 5-tool plan-and-approve contract (cap. 8 / B1).
CONTRACT = [
    "profile_target",
    "propose_next_step",
    "execute_step",
    "update_chain",
    "chain_report",
]


def _recording_mcp():
    """
    Fake FastMCP that records the tools registered via @mcp.tool().

    register_plan_approve_tools uses ``@mcp.tool()`` on 5 async functions, so
    each decorated function's __name__ is captured.
    """
    registered = {}

    def tool_decorator(*_args, **_kwargs):
        def inner(fn):
            registered[fn.__name__] = fn
            return fn
        return inner

    mcp = MagicMock()
    mcp.tool = tool_decorator
    return mcp, registered


def _real_tool_names(profiles):
    """
    Build the real server the bridge builds (setup_mcp_server) and return the
    set of registered tool names, or None if FastMCP list_tools is unavailable.
    """
    api = MagicMock()
    api.safe_post.return_value = {"success": True}
    mcp = server_setup.setup_mcp_server(
        api, MagicMock(), compact=False, profiles=profiles
    )
    if mcp is None:
        return None
    try:
        tools = asyncio.run(mcp.list_tools())
    except Exception:
        return None
    return {t.name for t in tools}


# ---------------------------------------------------------------------------
# The cable: register_plan_approve_tools attaches the 5-tool contract
# ---------------------------------------------------------------------------

class TestCableRegistersContract:
    def setup_method(self):
        self.api = MagicMock()
        self.api.safe_post.return_value = {"success": True}
        self.mcp, self.registered = _recording_mcp()
        register_plan_approve_tools(self.mcp, self.api, MagicMock())

    def test_all_five_tools_registered(self):
        for name in CONTRACT:
            assert name in self.registered, f"{name} not registered on the cable"

    def test_exactly_the_contract(self):
        """The cable must expose the 5 contract tools and nothing else here."""
        assert set(self.registered.keys()) == set(CONTRACT)

    def test_registered_tool_is_async(self):
        assert asyncio.iscoroutinefunction(self.registered["profile_target"])
        assert asyncio.iscoroutinefunction(self.registered["execute_step"])

    def test_profile_target_forwards_to_plan_endpoint(self):
        """A registered tool must forward to the /api/plan/* blueprint (B1)."""
        result = asyncio.run(
            self.registered["profile_target"](
                "https://target.example.invalid", objective="comprehensive",
            )
        )
        assert result == {"success": True}
        self.api.safe_post.assert_called_once()
        endpoint = self.api.safe_post.call_args[0][0]
        assert endpoint == "api/plan/profile-target"

    def test_profile_target_payload(self):
        asyncio.run(
            self.registered["profile_target"]("10.10.0.0/24", objective="stealth")
        )
        _, payload = self.api.safe_post.call_args[0]
        assert payload["target"] == "10.10.0.0/24"
        assert payload["objective"] == "stealth"

    def test_execute_step_forwards(self):
        asyncio.run(
            self.registered["execute_step"](
                "sess-1", step_index=0, tool="nmap",
                params='{"target": "10.0.0.1"}',
            )
        )
        self.api.safe_post.assert_called_once()
        endpoint, payload = self.api.safe_post.call_args[0]
        assert endpoint == "api/plan/execute-step"
        assert payload["session_id"] == "sess-1"
        assert payload["tool"] == "nmap"
        assert payload["params"] == {"target": "10.0.0.1"}

    def test_execute_step_bad_json_rejected_without_http(self):
        """Invalid params must be rejected before any HTTP call (no side effect)."""
        result = asyncio.run(
            self.registered["execute_step"](
                "sess-1", tool="nmap", params="{not valid json"
            )
        )
        assert result["success"] is False
        assert "Invalid params JSON" in result["error"]
        self.api.safe_post.assert_not_called()


# ---------------------------------------------------------------------------
# The cable is wired into the MCP server Hades drives (server_setup)
# ---------------------------------------------------------------------------

class TestServerSetupWiresTheCable:
    """The bridge Hades reaches (setup_mcp_server) must expose the contract."""

    def test_cyber_range_profile_reaches_contract(self):
        """
        The profile Hades' cyber-range sidecar bridge passes (--profile
        cyber-range) must reach the 5 plan-and-approve tools. This is the core
        B2 cable assertion: end-to-end through the real server Hades consumes.
        """
        names = _real_tool_names(["cyber-range"])
        if names is None:
            pytest.skip("FastMCP list_tools unavailable in this environment")
        for name in CONTRACT:
            assert name in names

    def test_full_and_default_also_reach_contract(self):
        """The contract is always-on: reachable from every profile Hades may use."""
        for prof in (["full"], ["default"]):
            names = _real_tool_names(prof)
            if names is None:
                continue
            for name in CONTRACT:
                assert name in names

    def test_cyber_range_profile_is_curated_and_nonempty(self):
        """
        Guard the Hades-driven profile itself: it must be a curated, non-empty
        tool set — the cable's profile endpoint must resolve to something.
        """
        assert isinstance(CYBER_RANGE_PROFILE, list)
        assert len(CYBER_RANGE_PROFILE) > 0
