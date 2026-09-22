# mcp_client/plan_and_approve.py

"""Plan-and-approve MCP tools (Pilar 4, cap. 8).

Registers the 5-tool contract that lets Hades (the LLM supervisor) drive an
audit deterministically, one step at a time:

    profile_target -> propose_next_step -> execute_step -> update_chain -> chain_report

Each tool is a thin async wrapper that forwards to the HTTP blueprint via
``api_client.safe_post`` (the same pattern as mcp_client/gateway.py). The real
contract logic lives in backend/server_core/intelligence/plan_and_approve.py;
these functions only translate between the LLM-facing MCP schema and the HTTP
API, keeping tool schemas clean for small/local LLM context budgets.
"""

from typing import Any, Dict, Optional

import asyncio


def register_plan_approve_tools(mcp, api_client, logger):
    """Register the plan-and-approve tools on an MCP server."""

    @mcp.tool()
    async def profile_target(
        target: str,
        objective: str = "comprehensive",
        planner_mode: str = "",
        session_id: str = "",
    ) -> Dict[str, Any]:
        """Build/refresh the TargetProfile and an AttackChain for a target.

        FIRST call of an audit. Creates a plan-and-approve session that holds
        the profile + a deterministic (not-yet-executed) attack chain, then
        returns it. Re-calling with the same session_id refreshes the plan.

        Args:
            target: Target URL, IP, or domain to analyze.
            objective: Testing objective: "comprehensive", "quick", or "stealth".
            planner_mode: Optional planner override: "advanced" or "legacy" (blank = default).
            session_id: Optional existing session id to refresh (blank = create new).

        Returns:
            The target profile, the planned attack chain, and the session id.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: api_client.safe_post(
                "api/plan/profile-target",
                {
                    "target": target,
                    "objective": objective or "comprehensive",
                    "planner_mode": planner_mode,
                    "session_id": session_id,
                },
            ),
        )

    @mcp.tool()
    async def propose_next_step(
        session_id: str,
        objective: str = "",
        planner_mode: str = "",
        rerank: bool = False,
    ) -> Dict[str, Any]:
        """Propose the NEXT step to execute. NEVER executes anything.

        This is the "plan" half of plan-and-approve: it returns the next
        AttackStep (tool + parameters + score + justification) for the
        supervisor to approve or reject. Nothing runs until execute_step.

        Args:
            session_id: Session id from profile_target.
            objective: Optional objective to (re)plan against.
            planner_mode: Optional planner override: "advanced" or "legacy".
            rerank: If True, re-rank the remaining chain before proposing.

        Returns:
            The next step (or completed=True when the chain is exhausted).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: api_client.safe_post(
                "api/plan/propose-next-step",
                {
                    "session_id": session_id,
                    "objective": objective,
                    "planner_mode": planner_mode,
                    "rerank": bool(rerank),
                },
            ),
        )

    @mcp.tool()
    async def execute_step(
        session_id: str,
        step_index: int = -1,
        tool: str = "",
        params: str = "",
    ) -> Dict[str, Any]:
        """Execute ONE approved step and record its result into the chain.

        The "approve" half of plan-and-approve. Run only a step the supervisor
        has vetted. ``params`` is a JSON string (e.g. '{"target": "10.0.0.1"}')
        that overrides/extends the step's parameters; leave blank to use the
        step's own optimized parameters.

        Args:
            session_id: Session id from profile_target.
            step_index: Index of the chain step to run (default: the current one).
            tool: Optional tool name to locate a specific chain step.
            params: Optional JSON string of parameters to override.

        Returns:
            The execution result and the updated chain status.
        """
        loop = asyncio.get_running_loop()

        def _run():
            import json

            payload: Dict[str, Any] = {"session_id": session_id}
            if step_index is not None and step_index >= 0:
                payload["step_index"] = step_index
            if tool:
                payload["tool"] = tool
            if params:
                try:
                    parsed = json.loads(params) if isinstance(params, str) else params
                    payload["params"] = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, TypeError):
                    return {
                        "success": False,
                        "error": f"Invalid params JSON: {params}",
                        "return_code": 1,
                    }
            return api_client.safe_post("api/plan/execute-step", payload)

        return await loop.run_in_executor(None, _run)

    @mcp.tool()
    async def update_chain(
        session_id: str,
        action: str = "add",
        tool: str = "",
        step_index: int = -1,
        parameters: str = "",
        new_objective: str = "",
    ) -> Dict[str, Any]:
        """Mutate the attack chain: add / remove / skip / reorder a step.

        Lets the supervisor reorient the plan mid-audit. A ``new_objective``
        re-plans the whole chain (preserving executed results).

        Args:
            session_id: Session id from profile_target.
            action: One of "add", "remove", "skip", "reorder".
            tool: Tool name for an "add" step.
            step_index: Target index for the action (destination for "reorder").
            parameters: Optional JSON string of parameters for an "add" step.
            new_objective: Optional new objective to re-plan against.

        Returns:
            The updated chain and its status.
        """
        loop = asyncio.get_running_loop()

        def _run():
            import json

            payload: Dict[str, Any] = {"session_id": session_id, "action": action or "add"}
            if tool:
                payload["tool"] = tool
            if step_index is not None and step_index >= 0:
                payload["step_index"] = step_index
            if parameters:
                try:
                    parsed = json.loads(parameters) if isinstance(parameters, str) else parameters
                    payload["parameters"] = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, TypeError):
                    return {
                        "success": False,
                        "error": f"Invalid parameters JSON: {parameters}",
                        "return_code": 1,
                    }
            if new_objective:
                payload["new_objective"] = new_objective
            return api_client.safe_post("api/plan/update-chain", payload)

        return await loop.run_in_executor(None, _run)

    @mcp.tool()
    async def chain_report(
        session_id: str,
        include_attack: bool = True,
    ) -> Dict[str, Any]:
        """Assemble a structured report of the chain's progress.

        Returns counts (executed / failed / skipped / pending), per-step
        status, and — when ``include_attack`` is True — an ATT&CK tactic tag
        per step derived from the tool catalog (not invented).

        Args:
            session_id: Session id from profile_target.
            include_attack: If True, tag each step with an ATT&CK tactic.

        Returns:
            The audit report.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: api_client.safe_post(
                "api/plan/chain-report",
                {
                    "session_id": session_id,
                    "include_attack": bool(include_attack),
                },
            ),
        )
