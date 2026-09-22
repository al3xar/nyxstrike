"""
tests/test_result_categorizer.py

T-19 — Post-execution RESULT CATEGORIZER (colocación "d").

Covers the deterministic level-0 classifier and its integration into
execute_step / chain_report:

  * categorize_result is DETERMINISTIC: same (tool, result) -> same label.
  * The label travels in the execute_step result AND in the chain_report
    step dict.
  * The trimmed stdout is ALWAYS preserved alongside the label (the label
    never hides the signal).
  * An unrecognised capability / output is "unlabeled" (grounded — never
    invented), per the acceptance criteria.
  * The opt-in level-1 model/Jev hook can only OVERRIDE an "unlabeled"
    verdict; it can never fabricate a category that isn't in
    RESULT_CATEGORIES, and a hook failure degrades to "unlabeled" (no crash).

Fixtures are REAL-shaped tool outputs (nmap port lines, hydra credential
success, an empty scan, a timeout, and an unrecognised tool output).
"""

import pytest

from backend.server_core.intelligence.plan_and_approve import (
    PlanAndApproveController,
    categorize_result,
    RESULT_CATEGORIES,
)


# ---------------------------------------------------------------------------
# Fakes (mirror tests/test_plan_and_approve.py so no real tool processes run)
# ---------------------------------------------------------------------------

class _FakeDecisionEngine:
    def __init__(self):
        from backend.server_core.intelligence.tool_catalog import build_tool_catalog
        self.tool_catalog = build_tool_catalog()
        self.tool_effectiveness = {"network_host": {"nmap": 0.9, "hydra": 0.7}}
        self._ranked = ["nmap", "hydra"]
        self._scores = {"nmap": 0.9, "hydra": 0.7}

    def _session_failure_penalties(self, session_id=None):
        return {}

    def select_optimal_tools(self, profile, objective="comprehensive",
                             planner_mode=None, session_id=None):
        return list(self._ranked)

    def _effective_score(self, tool, target_type_value, context_key=None,
                         session_penalties=None):
        return self._scores.get(tool, 0.5)

    def optimize_parameters(self, tool, profile, context):
        return {"target": profile.target, "_optimizations_applied": []}

    def analyze_target(self, target):
        from backend.server_core.target_profile import TargetProfile
        from backend.server_core.target_types import TargetType
        p = TargetProfile(target=target)
        p.target_type = TargetType.NETWORK_HOST
        p.risk_level = "high"
        p.confidence_score = 0.8
        p.technologies = []
        return p

    def create_attack_chain(self, profile, objective="comprehensive",
                            planner_mode=None, session_id=None, runtime_context=None):
        from backend.server_core.attack_chain import AttackChain
        from backend.server_core.attack_step import AttackStep
        chain = AttackChain(profile)
        chain.add_step(AttackStep("nmap", {"target": profile.target},
                                  "port scan", 0.85, 30))
        chain.add_step(AttackStep("hydra", {"target": profile.target},
                                  "brute ssh", 0.6, 60))
        return chain


class _FakeSessionFlow:
    def __init__(self):
        self.sessions = {}
        self._counter = 0

    def create_session(self, target, steps, source="web", objective="",
                       metadata=None, session_id=None, **kw):
        self._counter += 1
        sid = session_id or f"cat_{self._counter}"
        self.sessions[sid] = {
            "session_id": sid,
            "target": target,
            "status": "active",
            "workflow_steps": list(steps),
            "run_log": [],
            "metadata": metadata or {},
        }
        return self.sessions[sid]

    def load_session_any(self, session_id):
        sd = self.sessions.get(session_id)
        return (sd, "active") if sd else None

    def update_session(self, session_id, updates):
        sd = self.sessions.get(session_id)
        if not sd:
            return None
        for k, v in updates.items():
            sd[k] = v
        return sd

    def append_run_log(self, session_id, entry):
        self.sessions[session_id].setdefault("run_log", []).append(entry)


def _make_controller(executor=None, classifier=None):
    """Build a controller whose chain is exactly [nmap, hydra]."""
    sf = _FakeSessionFlow()
    de = _FakeDecisionEngine()
    if executor is None:
        executor = lambda tool, params, sid: {
            "success": True, "stdout": "", "stderr": "", "return_code": 0,
        }
    ctrl = PlanAndApproveController(decision_engine=de, session_flow=sf,
                                    executor=executor)
    if classifier is not None:
        ctrl.result_classifier = classifier
    return ctrl, sf


def _seed(ctrl, target="10.0.0.5"):
    r = ctrl.profile_target(target, objective="comprehensive")
    assert r["success"], r
    return r["session_id"]


# ---------------------------------------------------------------------------
# Deterministic level-0 classifier — real-shaped fixtures
# ---------------------------------------------------------------------------

class TestDeterministicFixtures:
    # -- nmap with open ports ------------------------------------------------
    def test_nmap_open_ports(self):
        stdout = (
            "Nmap scan report for 10.0.0.5\n"
            "Not shown: 998 closed ports\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
        )
        res = {"success": True, "stdout": stdout, "stderr": "", "return_code": 0}
        assert categorize_result("nmap", res) == "open_ports"

    def test_nmap_summary_open_ports(self):
        # Even a bare summary line should read as open_ports.
        res = {"success": True, "stdout": "2 open ports", "stderr": "",
               "return_code": 0}
        assert categorize_result("nmap", res) == "open_ports"

    # -- hydra with a credential ---------------------------------------------
    def test_hydra_credential_found(self):
        stdout = (
            "Hydra v9 - (c) 2022 by van der Laan\n"
            "HYDRA 22/tcp ssh: maxconn 256\n"
            "[22:ssh] host: 10.0.0.5  login: admin  password: P@ssw0rd!\n"
            "Done: 1 ASLv3 password(s) found in 5s.\n"
        )
        res = {"success": True, "stdout": stdout, "stderr": "", "return_code": 0}
        assert categorize_result("hydra", res) == "creds_found"

    def test_credential_line_any_tool(self):
        # A literal user:pass credential line is high-signal creds_found.
        res = {"success": True, "stdout": "admin:Sup3rS3cret", "stderr": "",
               "return_code": 0}
        assert categorize_result("netexec", res) == "creds_found"

    # -- vulnerability confirmation -------------------------------------------
    def test_vuln_confirmed_cve(self):
        stdout = (
            "## Vuln: CVE-2021-44228 (log4shell)\n"
            "    host: 10.0.0.5\n"
            "    [vulnerability] is vulnerable\n"
        )
        res = {"success": True, "stdout": stdout, "stderr": "", "return_code": 0}
        assert categorize_result("nuclei", res) == "vuln_confirmed"

    # -- empty scan ------------------------------------------------------------
    def test_empty_scan(self):
        # A clean run that produced nothing to act on.
        res = {"success": True, "stdout": "", "stderr": "", "return_code": 0}
        assert categorize_result("nmap", res) == "empty"

    # -- timeout / error -------------------------------------------------------
    def test_timeout_is_error(self):
        res = {"success": False, "stdout": "", "stderr": "timed out",
               "return_code": 124, "timed_out": True}
        assert categorize_result("nmap", res) == "error"

    def test_hard_failure_is_error(self):
        res = {"success": False, "stdout": "", "stderr": "", "return_code": 1}
        assert categorize_result("nmap", res) == "error"

    def test_exception_return_code_is_error(self):
        # -1 is the executor's "exception" code.
        res = {"success": False, "stdout": "", "stderr": "boom", "return_code": -1}
        assert categorize_result("nmap", res) == "error"

    # -- blocked (policy / scope) wins over error ------------------------------
    def test_blocked_wins_over_error(self):
        res = {"success": False,
               "stdout": "", "stderr": "host out_of_scope for the allowlist",
               "return_code": 1}
        assert categorize_result("nmap", res) == "blocked"

    # -- unrecognised -> unlabeled (grounded, NEVER invented) ------------------
    def test_unrecognised_output_is_unlabeled(self):
        # A tool whose output matches none of the signals.
        res = {"success": True, "stdout": "hello world, nothing to see",
               "stderr": "", "return_code": 0}
        assert categorize_result("custom_tool_xyz", res) == "unlabeled"

    def test_non_dict_result_is_unlabeled(self):
        assert categorize_result("nmap", "not a dict") == "unlabeled"

    def test_all_labels_are_known_categories(self):
        # Every fixture above returns a member of RESULT_CATEGORIES.
        fixtures = [
            ("nmap", {"success": True, "stdout": "22/tcp open", "stderr": "", "return_code": 0}),
            ("nmap", {"success": True, "stdout": "", "stderr": "", "return_code": 0}),
            ("hydra", {"success": True, "stdout": "admin:secret1", "stderr": "", "return_code": 0}),
            ("nuclei", {"success": True, "stdout": "CVE-1", "stderr": "", "return_code": 0}),
            ("nmap", {"success": False, "return_code": 1, "stdout": "", "stderr": ""}),
            ("nmap", {"success": False, "return_code": 1, "stdout": "", "stderr": "out_of_scope"}),
            ("tool", {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}),
        ]
        for tool, r in fixtures:
            assert categorize_result(tool, r) in RESULT_CATEGORIES


# ---------------------------------------------------------------------------
# Determinism: same input -> same label (acceptance criterion)
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_input_same_label_repeated(self):
        fixtures = [
            ("nmap", {"success": True, "stdout": "22/tcp open\n80/tcp open",
                      "stderr": "", "return_code": 0}),
            ("hydra", {"success": True, "stdout": "admin:secret1",
                       "stderr": "", "return_code": 0}),
            ("nmap", {"success": True, "stdout": "", "stderr": "",
                      "return_code": 0}),
            ("nmap", {"success": False, "stdout": "", "stderr": "",
                      "return_code": 124, "timed_out": True}),
            ("tool", {"success": True, "stdout": "??", "stderr": "",
                      "return_code": 0}),
        ]
        for tool, r in fixtures:
            labels = {categorize_result(tool, r) for _ in range(20)}
            assert len(labels) == 1, f"non-deterministic for {tool}: {labels}"


# ---------------------------------------------------------------------------
# Integration: label travels in execute_step result AND chain_report step
# ---------------------------------------------------------------------------

class TestExecuteStepIntegration:
    def test_label_in_execute_step_result_and_chain_report(self):
        def fake_exec(tool, params, sid):
            if tool == "nmap":
                return {"success": True,
                        "stdout": "22/tcp open\n80/tcp open",
                        "stderr": "", "return_code": 0}
            return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)

        r = ctrl.execute_step(sid, step_index=0)  # nmap
        assert r["success"] is True
        # label present in the top-level result...
        assert r["result_category"] == "open_ports"
        # ...and in the result dict the LLM reads...
        assert r["result"]["result_category"] == "open_ports"
        # ...and the trimmed stdout is STILL there (label must not hide signal)
        assert "22/tcp open" in r["result"]["stdout"]

        # label in the executed_step projection too
        assert r["executed_step"]["result_category"] == "open_ports"

        # chain_report step carries the label + tactic/technique (grounded)
        report = ctrl.chain_report(sid)
        assert report["success"] is True
        step0 = [s for s in report["steps"] if s.get("tool") == "nmap"][0]
        assert step0["result_category"] == "open_ports"
        # trimmed stdout still present in the report step
        assert "22/tcp open" in step0["result"]["stdout"]

    def test_creds_found_via_hydra(self):
        def fake_exec(tool, params, sid):
            return {"success": True,
                    "stdout": "admin:SuperSecret1", "stderr": "",
                    "return_code": 0}
        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)  # nmap step, hydra-style output
        assert r["result_category"] == "creds_found"
        report = ctrl.chain_report(sid)
        step0 = [s for s in report["steps"] if s.get("tool") == "nmap"][0]
        assert step0["result_category"] == "creds_found"

    def test_empty_scan_label(self):
        def fake_exec(tool, params, sid):
            return {"success": True, "stdout": "", "stderr": "", "return_code": 0}
        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)
        assert r["result_category"] == "empty"

    def test_timeout_label(self):
        def fake_exec(tool, params, sid):
            return {"success": False, "stdout": "", "stderr": "timed out",
                    "return_code": 124, "timed_out": True}
        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)
        assert r["result_category"] == "error"

    def test_unrecognised_label(self):
        def fake_exec(tool, params, sid):
            return {"success": True, "stdout": "zzz nothing recognizable",
                    "stderr": "", "return_code": 0}
        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)
        assert r["result_category"] == "unlabeled"
        report = ctrl.chain_report(sid)
        step0 = [s for s in report["steps"] if s.get("tool") == "nmap"][0]
        assert step0["result_category"] == "unlabeled"

    def test_label_is_recorded_in_run_log(self):
        def fake_exec(tool, params, sid):
            return {"success": True, "stdout": "22/tcp open", "stderr": "",
                    "return_code": 0}
        ctrl, sf = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)
        entries = [e for e in sf.sessions[sid]["run_log"]
                   if e.get("tool") == "nmap" and "result_category" in e]
        assert entries, "run_log entry with result_category missing"
        assert entries[-1]["result_category"] == "open_ports"


# ---------------------------------------------------------------------------
# Opt-in level-1 model/Jev fallback — only overrides "unlabeled", never
# fabricates, never crashes.
# ---------------------------------------------------------------------------

class TestModelFallback:
    def test_hook_overrides_unlabeled(self):
        # deterministic pass says "unlabeled"; the model grounds a real label.
        res = {"success": True, "stdout": "mysterious", "stderr": "",
               "return_code": 0}
        assert categorize_result("weird_tool", res,
                                 classifier=lambda t, r: "open_ports") == "open_ports"

    def test_hook_cannot_override_a_grounded_verdict(self):
        # A deterministic "creds_found" is final — the model may not fight it.
        res = {"success": True, "stdout": "admin:secret1", "stderr": "",
               "return_code": 0}
        assert categorize_result("hydra", res,
                                 classifier=lambda t, r: "empty") == "creds_found"

    def test_hook_cannot_fabricate_unknown_category(self):
        # model returns a category that isn't in RESULT_CATEGORIES -> unlabeled
        res = {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}
        assert categorize_result("tool", res,
                                 classifier=lambda t, r: "hacked_the_world") == "unlabeled"

    def test_hook_returns_empty_means_unlabeled(self):
        res = {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}
        assert categorize_result("tool", res,
                                 classifier=lambda t, r: "") == "unlabeled"

    def test_hook_exception_degrades_to_unlabeled(self):
        def boom(t, r):
            raise RuntimeError("model down")
        res = {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}
        assert categorize_result("tool", res, classifier=boom) == "unlabeled"

    def test_hook_case_insensitive(self):
        res = {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}
        assert categorize_result("tool", res,
                                 classifier=lambda t, r: "OPEN_PORTS") == "open_ports"

    def test_no_hook_keeps_deterministic(self):
        # With no hook wired (default), the classifier is purely level-0.
        res = {"success": True, "stdout": "zzz", "stderr": "", "return_code": 0}
        assert categorize_result("tool", res, classifier=None) == "unlabeled"

    def test_wired_hook_overrides_unlabeled_end_to_end(self):
        # End-to-end: a controller with a result_classifier wired overrides an
        # "unlabeled" output through execute_step.
        def fake_exec(tool, params, sid):
            return {"success": True, "stdout": "mystery bytes", "stderr": "",
                    "return_code": 0}
        calls = []

        def fake_classifier(tool, result):
            calls.append(tool)
            return "services_enumerated"

        ctrl, sf = _make_controller(executor=fake_exec, classifier=fake_classifier)
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)
        assert r["result_category"] == "services_enumerated"
        assert calls, "wired classifier hook was not invoked"
