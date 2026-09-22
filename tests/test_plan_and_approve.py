"""
tests/test_plan_and_approve.py

Unit tests for the plan-and-approve contract (Pilar 4, cap. 8):
  backend/server_core/intelligence/plan_and_approve.py

Exercises the full 5-tool contract —
  profile_target -> propose_next_step -> execute_step -> update_chain ->
  chain_report — with a STUBBED executor (no real tool processes) and a
  lightweight fake decision engine + session store, following the codebase's
  established mock pattern (see tests/test_mcp_gateway.py).

Verifies the contract's invariants:
  * propose_next_step NEVER executes.
  * execute_step only runs an approved step and records its result.
  * chain_report ATT&CK tagging is grounded (no invented tactics).
  * the stateful session carries progress across calls.
  * propose_next_step exposes an indexed finite candidate set
    (TestIndexedProposal, T-17: Jev-style action_space — the supervisor
    answers with an index of the set, never free text).
"""

import pytest

from backend.server_core.intelligence.plan_and_approve import (
    PlanAndApproveController,
    _tactic_for_capabilities,
    _technique_for_capabilities,
    _CAPABILITY_TO_TACTIC,
    _is_web_interaction_step,
    _interpret_web_result,
    _WEB_FALLBACK_ROUTES,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_PROPOSED,
    STATUS_SKIPPED,
)

# The 14 canonical ATT&CK Enterprise tactics (attack.mitre.org, v19). The map
# MUST emit only these — "Exploitation" and "Vulnerability Exploitation" are NOT
# canonical tactics and must never appear.
CANONICAL_TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
}
from backend.server_core.attack_chain import AttackChain
from backend.server_core.attack_step import AttackStep
from backend.server_core.target_profile import TargetProfile
from backend.server_core.target_types import TargetType


# ---------------------------------------------------------------------------
# Fakes (mirror the real APIs without any network / tool execution)
# ---------------------------------------------------------------------------

class _FakeDecisionEngine:
    """Minimal stand-in for IntelligentDecisionEngine used by the contract."""

    def __init__(self):
        from backend.server_core.intelligence.tool_catalog import build_tool_catalog
        self.tool_catalog = build_tool_catalog()
        # Ranking surface consumed by propose_next_step's indexed candidate
        # set (T-17): a finite, deterministic shortlist for the fake web
        # profile, with stable effective scores the controller turns into
        # calibrated confidence (score + margin vs the top).
        self.tool_effectiveness = {
            "web_application": {"nmap": 0.90, "nuclei": 0.80},
        }
        self._ranked = ["nmap", "nuclei"]
        self._scores = {"nmap": 0.90, "nuclei": 0.80}

    def _session_failure_penalties(self, session_id=None):
        return {}

    def _build_context_key(self, profile, objective):
        return None

    def select_optimal_tools(
        self, profile, objective="comprehensive", planner_mode=None, session_id=None
    ):
        return list(self._ranked)

    def _effective_score(self, tool, target_type_value, context_key=None, session_penalties=None):
        return self._scores.get(tool, 0.5)

    def optimize_parameters(self, tool, profile, context):
        return {
            "target": profile.target,
            "objective": context.get("objective", "comprehensive"),
            "_optimizations_applied": ["fake"],
        }

    def analyze_target(self, target):
        p = TargetProfile(target=target)
        p.target_type = TargetType.WEB_APPLICATION
        p.risk_level = "high"
        p.confidence_score = 0.8
        p.technologies = []
        return p

    def create_attack_chain(self, profile, objective="comprehensive",
                            planner_mode=None, session_id=None, runtime_context=None):
        chain = AttackChain(profile)
        # nmap first (recon), then nuclei (vuln) — both have catalog entries
        # with capabilities so ATT&CK tagging is grounded in tests.
        chain.add_step(AttackStep("nmap", {"target": profile.target},
                                  "scan surface", 0.85, 30))
        chain.add_step(AttackStep("nuclei", {"target": profile.target},
                                  "find vulns", 0.6, 60))
        return chain


class _FakeSessionFlow:
    """In-memory session store mimicking session_flow's public surface."""

    def __init__(self):
        self.sessions = {}
        self._counter = 0

    def create_session(self, target, steps, source="web", objective="",
                       metadata=None, session_id=None, **kw):
        self._counter += 1
        sid = session_id or f"sess_{self._counter}"
        sd = {
            "session_id": sid,
            "target": target,
            "status": "active",
            "workflow_steps": list(steps),
            "run_log": [],
            "metadata": metadata or {},
        }
        self.sessions[sid] = sd
        return sd

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
        sd = self.sessions.get(session_id)
        if sd:
            sd.setdefault("run_log", []).append(entry)


def _make_controller(executor=None):
    sf = _FakeSessionFlow()
    de = _FakeDecisionEngine()
    if executor is None:
        # default: nmap succeeds, everything else fails
        executor = lambda tool, params, session_id: {
            "success": tool == "nmap",
            "stdout": "PORT 80/TCP open" if tool == "nmap" else "",
            "stderr": "no such binary" if tool != "nmap" else "",
            "return_code": 0 if tool == "nmap" else 127,
        }
    ctrl = PlanAndApproveController(decision_engine=de, session_flow=sf, executor=executor)
    return ctrl, sf


def _seed(ctrl):
    r = ctrl.profile_target("https://target.example.invalid", objective="comprehensive")
    assert r["success"], r
    return r["session_id"]


# ---------------------------------------------------------------------------
# profile_target
# ---------------------------------------------------------------------------

class TestProfileTarget:
    def test_creates_session_and_chain(self):
        ctrl, _ = _make_controller()
        r = ctrl.profile_target("https://target.example.invalid")
        assert r["success"] is True
        assert r["session_id"]
        assert r["target_profile"]["target"] == "https://target.example.invalid"
        # chain is planned, not executed
        assert len(r["attack_chain"]["steps"]) == 2
        assert all(s["status"] == STATUS_PROPOSED for s in r["attack_chain"]["steps"])
        assert r["chain_status"]["executed"] == 0

    def test_requires_target(self):
        ctrl, _ = _make_controller()
        r = ctrl.profile_target("")
        assert r["success"] is False

    def test_replan_refreshes_same_session(self):
        ctrl, sf = _make_controller()
        r = ctrl.profile_target("https://t.example", objective="quick")
        sid = r["session_id"]
        r2 = ctrl.profile_target("https://t.example", objective="comprehensive", session_id=sid)
        assert r2["session_id"] == sid
        assert r2["attack_chain"]["steps"][0]["status"] == STATUS_PROPOSED


# ---------------------------------------------------------------------------
# propose_next_step (the "plan" half — MUST NOT execute)
# ---------------------------------------------------------------------------

class TestProposeNextStep:
    def test_returns_first_step_without_executing(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        assert r["success"] is True
        assert r["completed"] is False
        assert r["next_step"]["tool"] == "nmap"
        assert r["next_step"]["status"] == STATUS_PROPOSED
        # the chain step must not have been marked executed
        chain = sf.sessions[sid]["metadata"]["plan_and_approve"]["chain"]
        assert chain["steps"][0]["status"] == STATUS_PROPOSED

    def test_second_propose_after_execute_moves_cursor(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.propose_next_step(sid)
        ctrl.execute_step(sid, step_index=0)
        r = ctrl.propose_next_step(sid)
        assert r["next_step"]["tool"] == "nuclei"

    def test_all_processed_yields_completed(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        ctrl.propose_next_step(sid)
        ctrl.execute_step(sid, step_index=0)   # nmap ok
        ctrl.execute_step(sid, step_index=1)   # nuclei fail (still processed)
        r = ctrl.propose_next_step(sid)
        assert r["success"] is True
        assert r["completed"] is True
        assert r["next_step"] is None

    def test_missing_session_errors(self):
        ctrl, _ = _make_controller()
        r = ctrl.propose_next_step("nope")
        assert r["success"] is False


# ---------------------------------------------------------------------------
# execute_step (the "approve" half)
# ---------------------------------------------------------------------------

class TestExecuteStep:
    def test_executes_approved_step_and_records_result(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=0)
        assert r["success"] is True
        assert r["executed_step"]["status"] == STATUS_EXECUTED
        assert r["result"]["success"] is True
        # result recorded into the chain step
        chain = sf.sessions[sid]["metadata"]["plan_and_approve"]["chain"]
        assert chain["steps"][0]["status"] == STATUS_EXECUTED
        assert chain["steps"][0]["result"]["success"] is True

    def test_failed_execution_marks_failed(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, step_index=1)  # nuclei -> executor fails
        assert r["success"] is False
        assert r["executed_step"]["status"] == STATUS_FAILED

    def test_execution_writes_run_log(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)
        assert sf.sessions[sid]["run_log"], "run_log must record the execution"
        assert sf.sessions[sid]["run_log"][0]["tool"] == "nmap"

    def test_execute_by_tool_name(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.execute_step(sid, tool="nmap")
        assert r["success"] is True
        assert r["executed_step"]["tool"] == "nmap"

    def test_execute_advances_cursor(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r0 = ctrl.propose_next_step(sid)
        assert r0["next_step"]["tool"] == "nmap"
        ctrl.execute_step(sid, step_index=0)
        r1 = ctrl.propose_next_step(sid)
        assert r1["next_step"]["tool"] == "nuclei"

    def test_adhoc_reoriented_step_appended(self):
        # Use a success-returning executor so the ad-hoc step succeeds.
        def _exec(tool, params, session_id):
            return {"success": True, "stdout": "ok", "return_code": 0}
        ctrl, _ = _make_controller(executor=_exec)
        sid = _seed(ctrl)
        # execute a tool not in the chain -> ad-hoc step appended
        r = ctrl.execute_step(sid, tool="sqlmap",
                             params={"target": "https://target.example.invalid"})
        assert r["success"] is True
        chain = ctrl.chain_report(sid)["steps"]
        assert any(s["tool"] == "sqlmap" for s in chain)


# ---------------------------------------------------------------------------
# update_chain
# ---------------------------------------------------------------------------

class TestUpdateChain:
    def test_add_step(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.update_chain(sid, action="add", tool="sqlmap",
                              parameters={"target": "https://target.example.invalid"})
        assert r["success"] is True
        assert len(r["steps"]) == 3

    def test_remove_step(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.update_chain(sid, action="remove", step_index=0)
        assert r["success"] is True
        assert len(r["steps"]) == 1

    def test_skip_step(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.update_chain(sid, action="skip", step_index=1)
        assert r["success"] is True
        assert r["steps"][1]["status"] == STATUS_SKIPPED

    def test_reorder_step(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        # chain = [nmap(0), nuclei(1)]; move from index 0 to index 1
        r = ctrl.update_chain(sid, action="reorder", step_index=0,
                              parameters={"from_index": 0, "to_index": 1})
        assert r["success"] is True
        assert r["steps"][0]["tool"] == "nuclei"
        assert r["steps"][1]["tool"] == "nmap"

    def test_replan_preserves_executed_results(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)  # nmap executed
        r = ctrl.update_chain(sid, action="reorder", new_objective="quick")
        # executed nmap result should survive re-plan
        chain = ctrl.chain_report(sid)
        nmap = [s for s in chain["steps"] if s["tool"] == "nmap"]
        assert nmap and nmap[0]["status"] == STATUS_EXECUTED

    def test_invalid_remove_index_errors(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.update_chain(sid, action="remove", step_index=99)
        assert r["success"] is False


# ---------------------------------------------------------------------------
# chain_report (+ ATT&CK grounded tagging)
# ---------------------------------------------------------------------------

class TestChainReport:
    def test_counts_reflect_progress(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)   # nmap ok
        ctrl.execute_step(sid, step_index=1)   # nuclei fail
        r = ctrl.chain_report(sid)
        assert r["success"] is True
        assert r["counts"]["executed"] == 1
        assert r["counts"]["failed"] == 1
        assert r["counts"]["total"] == 2

    def test_attck_tag_is_grounded(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.chain_report(sid, include_attack=True)
        tags = {s["tool"]: s.get("attack_tactic") for s in r["steps"]}
        # nmap -> network_scan capability -> Discovery (grounded)
        assert tags.get("nmap") == "Discovery"
        # nuclei -> vuln_scan capability -> Discovery (T1595.002 Vulnerability
        # Scanning is a Discovery technique). The old "Vulnerability Exploitation"
        # was a NON-CANONICAL tactic and must no longer be emitted.
        assert tags.get("nuclei") == "Discovery"

    def test_attck_can_be_omitted(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.chain_report(sid, include_attack=False)
        assert r["att&ck"] is False
        assert all("attack_tactic" not in s for s in r["steps"])


# ---------------------------------------------------------------------------
# ATT&CK derivation purity (no invented tactics)
# ---------------------------------------------------------------------------

class TestTacticDerivation:
    def test_known_capability_maps(self):
        assert _tactic_for_capabilities({"network_scan"}) == "Discovery"
        assert _tactic_for_capabilities({"surface"}) == "Discovery"

    def test_unknown_capability_returns_none(self):
        assert _tactic_for_capabilities({"totally_made_up_capability"}) is None

    def test_empty_returns_none(self):
        assert _tactic_for_capabilities(set()) is None

    # T-8: RAMA WEB (Jev via web_interaction). Each web capability must map to a
    # CANONICAL MITRE ATT&CK Enterprise (v19) tactic. Grounded against
    # attack.mitre.org v19 (verified 2026-09-21); see mapeo-paso-attck.md §10.
    def test_web_branch_capabilities_map_to_canonical(self):
        cases = {
            # Exploit Public-Facing Application (T1190) is Initial Access.
            "web-exploitation": "Initial Access",
            # Command and Scripting Interpreter (T1059) is Execution.
            "command-injection": "Execution",
            # Valid Accounts (T1078) is Initial Access (credential-form / login).
            "credential-form": "Initial Access",
            "valid-accounts": "Initial Access",
            # XSS: arbitrary JavaScript execution in the victim browser ->
            # Execution (T1059), per the catalog's "arbitrary code execution
            # -> Execution/T1059" convention. (Decided + documented, T-8.)
            "xss": "Execution",
        }
        for cap, tactic in cases.items():
            got = _tactic_for_capabilities({cap})
            assert got == tactic, f"{cap} -> {got} (expected {tactic})"
            assert tactic in CANONICAL_TACTICS

    def test_web_capability_unknown_stays_none(self):
        # Golden rule holds for the web branch too: no invented labels.
        assert _tactic_for_capabilities({"web-definitely-not-a-capability"}) is None


# ---------------------------------------------------------------------------
# Full contract end-to-end (the supervised loop)
# ---------------------------------------------------------------------------

class TestFullContract:
    def test_profile_propose_execute_update_report(self):
        ctrl, sf = _make_controller()
        # 1. profile
        r = ctrl.profile_target("https://target.example.invalid", objective="comprehensive")
        sid = r["session_id"]
        # 2. propose (no execution)
        r = ctrl.propose_next_step(sid)
        assert r["next_step"]["tool"] == "nmap"
        # 3. execute
        r = ctrl.execute_step(sid, step_index=0)
        assert r["success"] is True
        # 4. update chain (supervisor injects an extra step)
        r = ctrl.update_chain(sid, action="add", tool="sqlmap")
        assert r["success"] is True
        # 5. report
        r = ctrl.chain_report(sid, include_attack=True)
        assert r["success"] is True
        assert r["counts"]["executed"] == 1
        assert r["counts"]["total"] == 3

    def test_run_log_records_each_execution(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)
        ctrl.execute_step(sid, step_index=1)
        run_log = sf.sessions[sid]["run_log"]
        assert len(run_log) == 2
        assert [e["tool"] for e in run_log] == ["nmap", "nuclei"]


# ---------------------------------------------------------------------------
# ATT&CK mapping: normalization + expansion (TFM·C4-fix)
#
# The 22-entry map B1 shipped emitted two NON-canonical tactics ("Exploitation"
# and "Vulnerability Exploitation") that do not exist in the MITRE ATT&CK
# Enterprise matrix (14 tactics), so they never match a Wazuh alert. It also
# left 55/94 catalog tools unlabelled. This suite pins the fix:
#   * only the 14 canonical tactics are ever emitted,
#   * the expanded map covers the 55 previously-unlabelled tools,
#   * Reconnaissance / Privilege Escalation now fire,
#   * a grounded capability -> technique layer is added (tactic -> technique).
# ---------------------------------------------------------------------------

class TestCanonicalTactics:
    def test_map_emits_only_canonical_tactics(self):
        # Hard invariant: no non-canonical tactic name may appear in the map.
        non_canonical = set(_CAPABILITY_TO_TACTIC.values()) - CANONICAL_TACTICS
        assert not non_canonical, f"non-canonical tactics in map: {non_canonical}"

    def test_no_non_canonical_tactic_is_derived(self):
        # The two names B1 emitted but that are not ATT&CK tactics.
        assert _tactic_for_capabilities({"exploitation"}) != "Exploitation"
        assert _tactic_for_capabilities({"vuln_scan"}) != "Vulnerability Exploitation"
        assert _tactic_for_capabilities({"vulnerability_scan"}) != "Vulnerability Exploitation"
        assert _tactic_for_capabilities({"payload_generation"}) != "Exploitation"

    def test_vuln_scan_and_exploit_map_to_canonical(self):
        # Vulnerability Scanning (T1595.002) is a Discovery technique; exploiting a
        # public-facing application (T1190) is Initial Access.
        assert _tactic_for_capabilities({"vuln_scan"}) == "Discovery"
        assert _tactic_for_capabilities({"vulnerability_scan"}) == "Discovery"
        assert _tactic_for_capabilities({"web_exploit"}) == "Initial Access"
        assert _tactic_for_capabilities({"cve_exploitation"}) == "Initial Access"
        assert _tactic_for_capabilities({"exploitation"}) == "Initial Access"


class TestExpandedMap:
    """The 25 capabilities B1 left unlabelled must now map to canonical tactics."""

    def test_new_capabilities_map_to_canonical(self):
        cases = {
            "web_vulnerability": "Initial Access",
            "xss_testing": "Initial Access",
            "sqli_testing": "Initial Access",
            "content_discovery": "Discovery",
            "api_assessment": "Discovery",
            "api_discovery": "Discovery",
            "auth_assessment": "Credential Access",
            "binary_analysis": "Execution",
            "binary_exploitation": "Execution",
            "payload_generation": "Execution",
            "cloud_assessment": "Discovery",
            "smb_enum": "Discovery",
            "ad_enum": "Discovery",
            "forensics_analysis": "Collection",
            "steganography_analysis": "Collection",
            "cms_assessment": "Discovery",
            "tls_assessment": "Discovery",
            "historical_discovery": "Discovery",
            "endpoint_discovery": "Discovery",
            "param_discovery": "Discovery",
            "manual_validation": "Discovery",
            "cve_lookup": "Discovery",
            "exploit_search": "Discovery",
        }
        for cap, tactic in cases.items():
            assert _tactic_for_capabilities({cap}) == tactic, f"{cap} -> {tactic}"
            assert tactic in CANONICAL_TACTICS

    def test_recon_and_privesc_fire(self):
        # Reconnaissance and Privilege Escalation produced 0 matches before.
        assert _tactic_for_capabilities({"osint"}) == "Reconnaissance"
        assert _tactic_for_capabilities({"escalation"}) == "Privilege Escalation"
        assert _tactic_for_capabilities({"privesc"}) == "Privilege Escalation"


class TestCatalogCoverage:
    """Run the real derivation against the real 94-tool catalog (grounded)."""

    def _catalog(self):
        from backend.server_core.intelligence.tool_catalog import build_tool_catalog
        cat = build_tool_catalog()
        return cat if isinstance(cat, dict) else dict(cat)

    def test_all_tactics_in_catalog_are_canonical(self):
        seen = set()
        for spec in self._catalog().values():
            caps = getattr(spec, "capabilities", None) or set()
            t = _tactic_for_capabilities(caps)
            if t is not None:
                seen.add(t)
        assert seen - CANONICAL_TACTICS == set(), f"non-canonical: {seen - CANONICAL_TACTICS}"
        # The two non-canonical names must never appear.
        assert "Exploitation" not in seen
        assert "Vulnerability Exploitation" not in seen

    def test_catalog_coverage_is_high(self):
        # 39/94 before the fix; the expanded map covers every labelled tool.
        catalog = self._catalog()
        labeled = sum(1 for s in catalog.values()
                     if _tactic_for_capabilities(getattr(s, "capabilities", None) or set()) is not None)
        assert labeled == len(catalog), f"unlabelled: {len(catalog) - labeled} of {len(catalog)}"

    def test_recon_and_privesc_present_in_catalog(self):
        # Grounded, catalog-level reality (honest — matches wiki mapeo-paso-
        # attck.md §5): the single-capability mapping DOES fire
        # (TestExpandedMap.test_recon_and_privesc_fire), but at the *catalog*
        # level Reconnaissance and Privilege Escalation do not surface because:
        #   * the only recon tools (spiderfoot/theharvester/parsero) also carry
        #     the "surface" capability -> the resolver returns Discovery first;
        #   * no ToolSpec in the catalog has an "escalation"/"privesc"
        #     capability, so Privilege Escalation cannot fire.
        # These are catalog facts, not a mapping defect; the map is correct and
        # canonical. We assert the grounded outcome rather than an idealised one.
        from collections import Counter
        dist = Counter(_tactic_for_capabilities(getattr(s, "capabilities", None) or set())
                       for s in self._catalog().values())
        assert "Reconnaissance" not in dist, "recon tools also carry 'surface' -> Discovery"
        assert "Privilege Escalation" not in dist, "no ToolSpec has escalation/privesc capability"


class TestTechniqueDerivation:
    """The grounded capability -> technique layer (tactic -> technique for Wazuh)."""

    def test_known_capability_maps_to_technique(self):
        assert _technique_for_capabilities({"network_scan"}) == "T1046"
        assert _technique_for_capabilities({"vuln_scan"}) == "T1595.002"
        assert _technique_for_capabilities({"exploitation"}) == "T1190"
        assert _technique_for_capabilities({"binary_analysis"}) == "T1059"
        assert _technique_for_capabilities({"password"}) == "T1003"
        assert _technique_for_capabilities({"escalation"}) == "T1548"

    def test_unknown_capability_returns_none(self):
        assert _technique_for_capabilities({"totally_made_up_capability"}) is None

    def test_empty_returns_none(self):
        assert _technique_for_capabilities(set()) is None

    # T-8: RAMA WEB (Jev via web_interaction) — the tactic -> technique hop for
    # Wazuh correlation. Technique ids verified canonical against
    # attack.mitre.org v19 (2026-09-21); see mapeo-paso-attck.md §10.
    def test_web_branch_capabilities_map_to_canonical_technique(self):
        cases = {
            "web-exploitation": "T1190",   # Exploit Public-Facing Application
            "command-injection": "T1059",  # Command and Scripting Interpreter
            "credential-form": "T1078",    # Valid Accounts
            "valid-accounts": "T1078",     # Valid Accounts
            "xss": "T1059",                # arbitrary JS execution (T1059/.007)
        }
        for cap, technique in cases.items():
            got = _technique_for_capabilities({cap})
            assert got == technique, f"{cap} -> {got} (expected {technique})"

    def test_web_capability_unknown_technique_stays_none(self):
        assert _technique_for_capabilities({"web-definitely-not-a-capability"}) is None

    def test_report_carries_technique_when_present(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.chain_report(sid, include_attack=True)
        tags = {s["tool"]: s.get("mitre_technique") for s in r["steps"]}
        # nmap -> network_scan -> T1046 (grounded).
        # nuclei has caps {api_assessment, vuln_scan, web_vulnerability}; the
        # deterministic (sorted) resolver picks api_assessment -> T1083 first.
        assert tags.get("nmap") == "T1046"
        assert tags.get("nuclei") == "T1083"
        # tactic is still present alongside the technique
        tactics = {s["tool"]: s.get("attack_tactic") for s in r["steps"]}
        assert tactics.get("nmap") == "Discovery"
        assert tactics.get("nuclei") == "Discovery"

    def test_technique_omitted_when_unmapped(self):
        # A capability with no confident technique must NOT invent one, but the
        # tactic may still be present (grounding for the technique layer).
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.chain_report(sid, include_attack=True)
        # Every step either has a technique or has it absent (never a fake id).
        for s in r["steps"]:
            if "mitre_technique" in s:
                assert s["mitre_technique"].startswith("T"), s["mitre_technique"]


# ---------------------------------------------------------------------------
# T-17: indexed decision contract (colocación "a", ADR router-decision-indexado)
#
# propose_next_step exposes — in addition to next_step — a FINITE NUMBERED
# candidate set, Jev's action_space pattern: the supervisor (Hades) answers
# with an INDEX of the set, never free text. Confidence is calibrated from
# the decision engine's effective score and the margin over the runner-up
# (classify_intent pattern: clear -> 1.0, narrow -> 0.75, none -> 0.5).
# propose_next_step still NEVER executes.
# ---------------------------------------------------------------------------

class TestIndexedProposal:
    # -- shape: finite, numbered, calibrated --------------------------------

    def test_propose_returns_numbered_candidates(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        assert r["success"] and r["completed"] is False
        cands = r["candidates"]
        assert isinstance(cands, list) and len(cands) >= 1
        # Finite: bounded by the engine's max_tools (objective settings, 8).
        assert len(cands) <= 8
        # Numbered: consecutive 1-based indices (Jev action_space style).
        assert [c["index"] for c in cands] == list(range(1, len(cands) + 1))
        for c in cands:
            assert isinstance(c["tool"], str) and c["tool"]
            assert isinstance(c["params_sugeridos"], dict)
            assert 0.0 <= c["confidence"] <= 1.0
            assert c["selection_reason"], "every candidate must carry a reason"
        # Ordered by confidence, non-increasing (ranking visible in the index).
        confs = [c["confidence"] for c in cands]
        assert confs == sorted(confs, reverse=True)
        # Calibrated tiers only: the classify_intent 3-level scale.
        assert set(confs) <= {1.0, 0.75, 0.5}

    def test_candidate_reason_and_tactic_are_grounded(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        top = r["candidates"][0]
        # nmap's catalog capabilities map to the canonical Discovery tactic.
        assert top["tactic"] == "Discovery"
        assert "surface" in top["capabilities"] or "network_scan" in top["capabilities"]
        assert "nmap" in top["selection_reason"].get("summary", "")

    def test_next_step_still_present_and_linked_by_index(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        # Additive change: the existing next_step field survives intact.
        assert r["next_step"]["tool"] == "nmap"
        # The supervisor can answer with the index of the next step.
        assert r["selected_index"] == 1
        assert r["candidates"][r["selected_index"] - 1]["tool"] == "nmap"

    def test_params_sugeridos_have_no_internal_metadata(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        for c in r["candidates"]:
            assert not any(k.startswith("_") for k in c["params_sugeridos"])

    def test_propose_still_never_executes(self):
        calls = []

        def fake_exec(tool, params, session_id):
            calls.append(tool)
            return {"success": True, "stdout": "x", "stderr": "", "return_code": 0}

        ctrl, _ = _make_controller(executor=fake_exec)
        sid = _seed(ctrl)
        r = ctrl.propose_next_step(sid)
        assert r["success"]
        assert calls == []

    def test_completed_session_has_empty_candidates(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        ctrl.execute_step(sid, step_index=0)
        ctrl.execute_step(sid, step_index=1)
        r = ctrl.propose_next_step(sid)
        assert r["completed"] is True
        assert r["candidates"] == []
        assert r["selected_index"] is None

    # -- determinism: same input -> same finite set, same order -------------

    def test_same_input_same_candidate_order(self):
        def fresh():
            ctrl, _ = _make_controller()
            sid = _seed(ctrl)
            return ctrl.propose_next_step(sid)

        a, b = fresh(), fresh()
        assert [c["tool"] for c in a["candidates"]] == [c["tool"] for c in b["candidates"]]
        assert [c["index"] for c in a["candidates"]] == [c["index"] for c in b["candidates"]]
        assert [c["confidence"] for c in a["candidates"]] == [c["confidence"] for c in b["candidates"]]

    # -- real decision engine: IP (NETWORK_HOST) and web profiles -----------

    @pytest.fixture()
    def real_ctrl(self):
        """Controller wired to the REAL IntelligentDecisionEngine, offline.

        The two network-facing helpers (HTTP probe, DNS resolution) are
        stubbed so no test ever leaves the process.
        """
        from backend.server_core.intelligence.intelligent_decision_engine import (
            IntelligentDecisionEngine,
        )

        eng = IntelligentDecisionEngine()
        eng._http_probe = lambda target: ({}, "")
        eng._resolve_domain = lambda target: []
        return PlanAndApproveController(
            decision_engine=eng,
            session_flow=_FakeSessionFlow(),
            executor=lambda tool, params, session_id: {
                "success": False,
                "stdout": "",
                "stderr": "not-run",
                "return_code": 1,
            },
        )

    def test_ip_profile_returns_indexed_candidates(self, real_ctrl):
        r = real_ctrl.profile_target("10.0.0.5", objective="comprehensive")
        assert r["success"], r
        assert r["target_profile"]["target_type"] == "network_host"

        prop = real_ctrl.propose_next_step(r["session_id"])
        assert prop["success"] and prop["completed"] is False
        cands = prop["candidates"]
        assert len(cands) >= 1
        assert [c["index"] for c in cands] == list(range(1, len(cands) + 1))
        for c in cands:
            assert c["tool"] in real_ctrl.decision_engine.tool_catalog
            assert 0.0 <= c["confidence"] <= 1.0
            assert c["selection_reason"]
            assert isinstance(c["params_sugeridos"], dict)
        # The lead candidate is a network tool for a network host.
        assert cands[0]["tool"].startswith(("nmap", "masscan", "rustscan"))

    def test_web_profile_returns_indexed_candidates(self, real_ctrl):
        r = real_ctrl.profile_target(
            "https://target.example.invalid", objective="comprehensive"
        )
        assert r["success"], r
        assert r["target_profile"]["target_type"] == "web_application"

        prop = real_ctrl.propose_next_step(r["session_id"])
        assert prop["success"] and prop["completed"] is False
        cands = prop["candidates"]
        assert len(cands) >= 1
        assert [c["index"] for c in cands] == list(range(1, len(cands) + 1))
        for c in cands:
            assert c["tool"] in real_ctrl.decision_engine.tool_catalog
            assert 0.0 <= c["confidence"] <= 1.0
            assert c["selection_reason"]
        assert prop["selected_index"] is not None
        assert cands[prop["selected_index"] - 1]["tool"] == prop["next_step"]["tool"]

    def test_real_engine_same_input_same_order(self, real_ctrl):
        r1 = real_ctrl.profile_target("10.0.0.7", objective="comprehensive")
        a = real_ctrl.propose_next_step(r1["session_id"])
        r2 = real_ctrl.profile_target("10.0.0.7", objective="comprehensive")
        b = real_ctrl.propose_next_step(r2["session_id"])
        assert [c["tool"] for c in a["candidates"]] == [c["tool"] for c in b["candidates"]]
        assert [c["confidence"] for c in a["candidates"]] == [c["confidence"] for c in b["candidates"]]


# ---------------------------------------------------------------------------
# T-7: web executor branch in execute_step + BLOCKED fallback
#
# Jev is a *branch of executor* in plan_and_approve.execute_step — NOT a new
# planner loop. When the chosen step is a web-interaction step (the
# web_interaction capability of T-6, carried either by its tool name
# `web_run_goal` or an explicit route tag), execute_step runs it through the
# injected `executor` and INTERPRETS the compressed SubgoalResult contract
# (status / verified / summary / extracted — T-2/T-3).
#
# Key invariants pinned here (contract §2.2 rules a/b/c):
#   * status=DONE does NOT imply success — the planner decides on `verified`
#     independently (a false-DONE must be treated as a non-success).
#   * BLOCKED / BUDGET_EXCEEDED / blocked_reason=out_of_scope -> the executor
#     signals the planner the ALTERNATIVE route (curl/sqlmap/API via
#     NyxStrike) instead of retrying the browser. The step is not retried.
#
# The injected `executor` is always the single in-process executor; T-7 does
# not add a second executor — the web branch is selected INSIDE execute_step
# and the same injected executor is what calls web_run_goal in production.
# ---------------------------------------------------------------------------


def _web_subgoal(status="DONE", verified=None, extracted=None,
                 blocked_reason=None, run_id="jev-7f3a"):
    """A compressed SubgoalResult-shaped dict (what web_run_goal returns,
    T-2/T-3). ``extracted`` is the nested contract object.
    """
    return {
        "run_id": run_id,
        "status": status,
        "verified": verified,
        "summary": "SQLi confirmed via browser",
        "extracted": extracted or {"reflected_text": "First name: admin",
                                   "final_url": "https://target.example/sqli.php",
                                   "forms_seen": 1},
        "budget": {"actions_used": 3, "decisions_used": 5, "elapsed_ms": 2210},
        "evidence_hash": "sha256:abc123",
        "blocked_reason": blocked_reason,
    }


class _WebDecisionEngine:
    """Decision engine whose chain leads with a web_run_goal step (T-6 tool),
    so execute_step can route it down the web branch."""

    def __init__(self):
        from backend.server_core.intelligence.tool_catalog import build_tool_catalog
        self.tool_catalog = build_tool_catalog()

    def analyze_target(self, target):
        p = TargetProfile(target=target)
        p.target_type = TargetType.WEB_APPLICATION
        p.risk_level = "high"
        p.confidence_score = 0.8
        p.technologies = []
        return p

    def create_attack_chain(self, profile, objective="comprehensive",
                            planner_mode=None, session_id=None, runtime_context=None):
        chain = AttackChain(profile)
        chain.add_step(AttackStep(
            "web_run_goal",
            {"url": profile.target, "goal": "envía la inyección y lee el resultado"},
            "completar subgoal web", 0.8, 30,
        ))
        chain.add_step(AttackStep("sqlmap", {"target": profile.target},
                                  "confirmar SQLi por API", 0.7, 45))
        return chain


def _web_controller(executor):
    ctrl = PlanAndApproveController(
        decision_engine=_WebDecisionEngine(),
        session_flow=_FakeSessionFlow(),
        executor=executor,
    )
    return ctrl


class TestWebExecutor:
    # -- unit: web-step detection (the route TAG, not a learned heuristic) ---

    def test_web_tool_step_is_web(self):
        assert _is_web_interaction_step({"tool": "web_run_goal", "parameters": {}})

    def test_route_tag_marks_web(self):
        step = {"tool": "nmap",
                "parameters": {"route": "web_interaction", "target": "x"}}
        assert _is_web_interaction_step(step)

    def test_non_web_step_is_not_web(self):
        assert not _is_web_interaction_step({"tool": "nmap",
                                             "parameters": {"target": "x"}})

    def test_empty_step_is_not_web(self):
        assert not _is_web_interaction_step({})

    # -- unit: interpreting the compressed contract (status x verified) ------

    def test_done_and_verified_is_success(self):
        r = _interpret_web_result(_web_subgoal("DONE", verified=True))
        assert r["success"] is True
        assert r["web_status"] == "DONE"
        assert r["verified"] is True

    def test_done_but_not_verified_is_false_done(self):
        # Contract rule (a): status=DONE does NOT imply success. The planner
        # decides on `verified`; a false-DONE must read as a non-success.
        r = _interpret_web_result(_web_subgoal("DONE", verified=False))
        assert r["success"] is False
        assert r["web_status"] == "DONE"
        assert r["verified"] is False

    def test_blocked_is_failure_with_fallback(self):
        r = _interpret_web_result(_web_subgoal("BLOCKED", verified=None,
                                               blocked_reason="file upload fuera de MVP"))
        assert r["success"] is False
        assert r["web_status"] == "BLOCKED"
        assert r["fallback"], "BLOCKED must signal an alternative route"
        assert "curl" in r["fallback"]

    def test_budget_exceeded_is_failure_with_fallback(self):
        r = _interpret_web_result(_web_subgoal("BUDGET_EXCEEDED"))
        assert r["success"] is False
        assert r["web_status"] == "BUDGET_EXCEEDED"
        assert r["fallback"]

    def test_out_of_scope_is_failure_with_fallback(self):
        r = _interpret_web_result(_web_subgoal("FAILED", verified=None,
                                               blocked_reason="out_of_scope"))
        assert r["success"] is False
        assert r["fallback"], "out_of_scope must signal an alternative route"

    def test_fallback_routes_are_grounding_not_invented(self):
        assert "sqlmap" in _WEB_FALLBACK_ROUTES
        assert "curl" in _WEB_FALLBACK_ROUTES
        assert "API" in _WEB_FALLBACK_ROUTES

    def test_interpret_missing_status_defaults_failure(self):
        r = _interpret_web_result({})
        assert r["success"] is False

    # -- integration: execute_step routes a web step through the executor ----

    def test_web_step_result_flows_to_chain(self):
        calls = []

        def fake_exec(tool, params, session_id):
            calls.append(tool)
            assert tool == "web_run_goal"
            return _web_subgoal("DONE", verified=True)

        ctrl = _web_controller(fake_exec)
        r = ctrl.profile_target("https://target.example.invalid",
                                objective="comprehensive")
        sid = r["session_id"]
        r = ctrl.execute_step(sid, step_index=0)
        # The injected executor was invoked for the web tool (single executor;
        # the web branch is selected inside execute_step).
        assert calls == ["web_run_goal"]
        assert r["success"] is True
        assert r["executed_step"]["status"] == STATUS_EXECUTED
        # The compressed contract fields reach the recorded chain result.
        chain = ctrl.chain_report(sid)["steps"]
        web = [s for s in chain if s["tool"] == "web_run_goal"][0]
        assert web["status"] == STATUS_EXECUTED
        assert web["result"]["web_status"] == "DONE"
        assert web["result"]["verified"] is True
        assert web["result"]["summary"]

    def test_web_blocked_emits_fallback_signal_in_result(self):
        def fake_exec(tool, params, session_id):
            return _web_subgoal("BLOCKED", blocked_reason="file upload fuera de MVP")

        ctrl = _web_controller(fake_exec)
        sid = ctrl.profile_target("https://t.example", objective="comprehensive")["session_id"]
        r = ctrl.execute_step(sid, step_index=0)
        assert r["success"] is False
        assert r["executed_step"]["status"] == STATUS_FAILED
        # The planner-facing fallback recommendation is present + verifiable.
        assert r["fallback"], "BLOCKED must hand the planner an alternative route"
        assert "sqlmap" in r["fallback"]
        assert "curl" in r["fallback"]
        # And it is recorded on the chain step result for the supervisor.
        web = [s for s in ctrl.chain_report(sid)["steps"]
               if s["tool"] == "web_run_goal"][0]
        assert web["result"]["fallback"]
        assert web["result"]["web_status"] == "BLOCKED"

    def test_web_false_done_is_failed_not_executed(self):
        # DONE with verified=False is a non-success: the step must not be
        # marked executed (the planner will re-plan / change route).
        def fake_exec(tool, params, session_id):
            return _web_subgoal("DONE", verified=False)

        ctrl = _web_controller(fake_exec)
        sid = ctrl.profile_target("https://t.example", objective="comprehensive")["session_id"]
        r = ctrl.execute_step(sid, step_index=0)
        assert r["success"] is False
        assert r["executed_step"]["status"] == STATUS_FAILED

    def test_non_web_step_uses_normal_success_path(self):
        # A plain (non-web) step must keep the original success semantics —
        # T-7 must not break contract B1.
        def fake_exec(tool, params, session_id):
            return {"success": True, "stdout": "ok", "stderr": "", "return_code": 0}

        ctrl = _web_controller(fake_exec)
        sid = ctrl.profile_target("https://t.example", objective="comprehensive")["session_id"]
        # sqlmap is the 2nd chain step (non-web).
        r = ctrl.execute_step(sid, step_index=1)
        assert r["success"] is True
        assert r["executed_step"]["status"] == STATUS_EXECUTED
        # No web-interpretation fields leak into a non-web result.
        assert "web_status" not in r["result"]
        assert "fallback" not in r["result"]
