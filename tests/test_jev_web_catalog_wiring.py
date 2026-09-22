"""
tests/test_jev_web_catalog_wiring.py

T-14 — Close the T-8 wiring GAP: chain_report resolves a step's tactic/technique
ONLY from the decision-engine tool catalog (build_tool_catalog()). T-8 added the
5 web capabilities to the maps in plan_and_approve.py, but the 3 Jev tools
(web_run_goal / web_extract_surface / web_get_evidence) live in the T-6
toolspec, NOT in build_tool_catalog(). So in production the Jev step would be
tagged None (the M6 benchmark metric's input would be unlabelled).

This test (T-14's explicit item, documented in mapeo-paso-attck.md §10.4) pins
the fix: the 3 Jev tools are present in build_tool_catalog() and their
capabilities resolve to the canonical T-8 tactics/techniques so a web_run_goal
step is grounded (tactic + technique) by chain_report.

No real HTTP / tools / Chrome.
"""

from backend.server_core.intelligence.plan_and_approve import (
    _tactic_for_capabilities,
    _technique_for_capabilities,
)
from backend.server_core.intelligence.tool_catalog import build_tool_catalog


class TestJevWebToolsInCatalog:
    def test_all_three_jev_tools_are_cataloged(self):
        cat = build_tool_catalog()
        for name in ("web_run_goal", "web_extract_surface", "web_get_evidence"):
            assert name in cat, f"{name} missing from build_tool_catalog() — wiring GAP"

    def test_web_run_goal_capabilities_resolve_canonical(self):
        cat = build_tool_catalog()
        caps = cat["web_run_goal"].capabilities
        # The T-8 web capabilities must be present so the Jev step is tagged.
        assert {"web-exploitation", "valid-accounts", "command-injection",
                "xss", "credential-form"} <= caps
        tactic = _tactic_for_capabilities(caps)
        technique = _technique_for_capabilities(caps)
        assert tactic is not None, "web_run_goal step would be untagged (GAP)"
        assert technique is not None, "web_run_goal step would be untagged (GAP)"

    def test_web_run_goal_is_a_web_target_type(self):
        from backend.server_core.target_types import TargetType
        cat = build_tool_catalog()
        assert TargetType.WEB_APPLICATION.value in cat["web_run_goal"].target_types

    def test_evidence_tool_is_recon_not_exploit(self):
        # web_get_evidence only retrieves evidence — it is a discovery surface,
        # never an exploit. Its capabilities must NOT carry exploit caps.
        cat = build_tool_catalog()
        caps = cat["web_get_evidence"].capabilities
        assert "web-exploitation" not in caps
        assert "command-injection" not in caps


class TestJevStepGroundedEndToEnd:
    """A web_run_goal step, executed, is tagged tactic+technique by chain_report."""

    def test_web_run_goal_step_is_tagged(self):
        import sys
        sys.path.insert(0, "/home/ubuntu/repos/clones/nyxstrike")
        from backend.server_core.intelligence.plan_and_approve import (
            PlanAndApproveController,
        )

        class _DE:
            def __init__(self):
                self.tool_catalog = build_tool_catalog()

            def analyze_target(self, target):
                from backend.server_core.target_profile import TargetProfile
                from backend.server_core.target_types import TargetType
                p = TargetProfile(target=target)
                p.target_type = TargetType.WEB_APPLICATION
                p.risk_level = "high"
                p.confidence_score = 0.8
                p.technologies = []
                return p

            def create_attack_chain(self, profile, objective="comprehensive",
                                    planner_mode=None, session_id=None, runtime_context=None):
                from backend.server_core.attack_chain import AttackChain
                from backend.server_core.attack_step import AttackStep
                chain = AttackChain(profile)
                chain.add_step(AttackStep("web_run_goal",
                                          {"url": profile.target, "goal": "login"},
                                          "completar subgoal web", 0.8, 30))
                return chain

        class _SF:
            def __init__(self):
                self.s, self.n = {}, 0

            def create_session(self, target, steps, source="x", objective="",
                               metadata=None, session_id=None, **kw):
                self.n += 1
                sid = session_id or f"s{self.n}"
                self.s[sid] = {"session_id": sid, "target": target, "status": "active",
                               "workflow_steps": list(steps), "run_log": [],
                               "metadata": metadata or {}}
                return self.s[sid]

            def load_session_any(self, sid):
                return (self.s[sid], "active") if sid in self.s else None

            def update_session(self, sid, upd):
                if sid in self.s:
                    self.s[sid].update(upd)
                    return self.s[sid]
                return None

            def append_run_log(self, sid, entry):
                self.s[sid].setdefault("run_log", []).append(entry)

        def fake_exec(tool, params, sid):
            return {"success": True, "status": "DONE", "verified": True,
                    "run_id": "jev-test", "summary": "login ok", "return_code": 0}

        sf = _SF()
        ctrl = PlanAndApproveController(decision_engine=_DE(), session_flow=sf, executor=fake_exec)
        sid = ctrl.profile_target("https://dvwa.example", objective="comprehensive")["session_id"]
        exec_res = ctrl.execute_step(sid, step_index=0)
        assert exec_res["success"] is True, exec_res
        report = ctrl.chain_report(sid, include_attack=True)
        assert report["success"] is True, report
        step = [s for s in report["steps"] if s["tool"] == "web_run_goal"][0]
        assert step["attack_tactic"] is not None, "Jev step untagged — wiring GAP not closed"
        assert step["mitre_technique"] is not None, "Jev step untagged — wiring GAP not closed"
