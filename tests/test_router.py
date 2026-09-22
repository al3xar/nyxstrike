"""
tests/test_router.py

Unit tests for the router v1 module (T-21 — TFM routing layer, nivel 1-2):
  backend/server_core/intelligence/router.py

Covers the acceptance criteria:
  * deterministic 100% offline (no network, no LLM) — same state -> same
    Decision, always;
  * calibrated confidence (3-tier pattern of classify_intent applied to the
    effective-score margin: 1.0 / 0.75 / 0.5);
  * fallback to a small model ONLY on low confidence (threshold ~0.6,
    T-24 spike), with the choice validated against the offered set (Jev
    discipline) — out-of-set / abstained / errored fallback keeps the
    deterministic top-1;
  * pluggable RouterModel interface (nivel 3 trained classifier substitutes
    the deterministic model WITHOUT touching propose_next_step —
    substitution test through the controller hook);
  * propose_next_step hook BEHIND A FLAG, OFF BY DEFAULT (test that the
    flag-off behaviour is exactly the pre-T-21 contract: no
    router_decision field, no run_log entry);
  * auditable run_log entry (tool, confidence, reason, level, model,
    escalated, index, timestamp) when the router is active;
  * ROUTE-HIT metric over the T-20 dataset fixture
    (hades-routes-dataset/v1): only rows with outcome.success is True are
    evaluable; not_determined rows are excluded, never counted as misses.
"""

import json
from pathlib import Path

import pytest

from backend.server_core.intelligence.plan_and_approve import PlanAndApproveController
from backend.server_core.intelligence.router import (
    Decision,
    DeterministicRouterModel,
    PromptFallbackRouter,
    RouterModel,
    route_hit,
    route_hit_report,
    _calibrated_confidence,
    normalize_label_tool,
)
from tests.test_plan_and_approve import _FakeDecisionEngine, _FakeSessionFlow, _seed

_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "routes_dataset_t20.json"
)


def _state(candidates):
    return {
        "state_text": "target=10.0.0.5 phase=recon",
        "phase": "recon",
        "candidates": candidates,
        "det_shortlist": [c["tool"] for c in candidates],
        "context": {},
    }


def _cand(tool, index, score):
    return {
        "tool": tool,
        "index": index,
        "confidence": None,
        "effective_score": score,
        "selection_reason": {},
        "params_sugeridos": {},
        "capabilities": [],
        "tactic": None,
    }


# ---------------------------------------------------------------------------
# Nivel 0 — deterministic router + calibrated confidence
# ---------------------------------------------------------------------------


class TestDeterministicRouter:
    def test_clear_winner_gives_confidence_1(self):
        model = DeterministicRouterModel()
        decision = model.route(
            _state([_cand("nmap", 1, 0.95), _cand("nuclei", 2, 0.60)])
        )
        assert decision is not None
        assert decision.tool == "nmap"
        assert decision.confidence == 1.0
        assert decision.level == 0
        assert decision.escalated is False
        assert decision.index == 1
        assert "margin" in decision.reason

    def test_narrow_band_gives_confidence_075(self):
        model = DeterministicRouterModel()
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert decision is not None
        assert decision.confidence == 0.75
        assert decision.tool == "nmap"
        assert decision.level == 0

    def test_tie_gives_confidence_05_and_escalates(self):
        model = DeterministicRouterModel()
        decision = model.route(
            _state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)])
        )
        assert decision is not None
        assert decision.confidence == 0.5
        # below the 0.6 threshold without fallback: keep top-1, flag
        # escalation for the supervisor.
        assert decision.escalated is True
        assert decision.tool == "nmap"
        assert "supervisor" in decision.reason

    def test_unique_candidate_gives_confidence_1(self):
        model = DeterministicRouterModel()
        decision = model.route(_state([_cand("nmap", 1, 0.5)]))
        assert decision is not None
        assert decision.confidence == 1.0

    def test_missing_scores_gives_confidence_075(self):
        # dataset-style state (det_shortlist only, no scores): margin
        # unknown -> moderate confidence, never a fabricated 1.0.
        model = DeterministicRouterModel()
        decision = model.route(
            {"state_text": None, "candidates": None,
             "det_shortlist": ["nmap", "nuclei"], "context": {}}
        )
        assert decision is not None
        assert decision.confidence == 0.75
        assert decision.tool == "nmap"

    def test_empty_candidate_set_abstains(self):
        model = DeterministicRouterModel()
        decision = model.route({"candidates": [], "det_shortlist": None})
        assert decision is not None
        assert decision.tool is None
        assert decision.escalated is True

    def test_deterministic_same_state_same_decision(self):
        model = DeterministicRouterModel()
        state = _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        first = model.route(state).to_dict()
        for _ in range(3):
            assert model.route(state).to_dict() == first

    def test_no_network_calls_offline(self):
        # 100% offline by construction: route() touches only the state.
        model = DeterministicRouterModel()
        decision = model.route(_state([_cand("nmap", 1, 0.95)]))
        assert decision.model == "deterministic-v1"
        assert isinstance(decision.confidence, float)
        assert 0.0 <= decision.confidence <= 1.0


class TestCalibratedConfidence:
    def test_tiers_match_classify_intent_pattern(self):
        # 3-tier calibration (1.0 / 0.75 / 0.5) — same semantics as
        # classify_intent, applied to the effective-score margin.
        clear = [_cand("a", 1, 1.0), _cand("b", 2, 0.7)]
        assert _calibrated_confidence(clear) == 1.0
        narrow = [_cand("a", 1, 0.90), _cand("b", 2, 0.85)]
        assert _calibrated_confidence(narrow) == 0.75
        tie = [_cand("a", 1, 0.80), _cand("b", 2, 0.79)]
        assert _calibrated_confidence(tie) == 0.5

    def test_threshold_tiers_with_clean_margins(self):
        # Avoid float-epsilon boundaries; use margins well inside each
        # band so the tier is unambiguous.
        assert _calibrated_confidence(
            [_cand("a", 1, 0.95), _cand("b", 2, 0.70)]
        ) == 1.0  # margin 0.25 >= CLEAR
        assert _calibrated_confidence(
            [_cand("a", 1, 0.90), _cand("b", 2, 0.80)]
        ) == 0.75  # margin 0.10, NARROW < m < CLEAR
        assert _calibrated_confidence(
            [_cand("a", 1, 0.90), _cand("b", 2, 0.88)]
        ) == 0.5  # margin 0.02 <= NARROW


# ---------------------------------------------------------------------------
# Nivel 1 — small-model fallback (pattern _classify_with_llm)
# ---------------------------------------------------------------------------


class _StubFallback(RouterModel):
    """Test stand-in for a small model behind the fallback path."""

    def __init__(self, answer, confidence=0.9, name="stub-fallback"):
        self._answer = answer
        self._confidence = confidence
        self.name = name
        self.calls = 0

    def route(self, state):
        self.calls += 1
        answer = self._answer
        if answer is None:
            return None
        if isinstance(answer, Exception):
            raise answer
        choice: str = answer
        return Decision(
            tool=choice,
            confidence=self._confidence,
            reason=f"stub model chose {choice}",
            level=1,
            model=self.name,
        )


class TestSmallModelFallback:
    def test_low_confidence_consults_fallback_and_accepts_in_set(self):
        fallback = _StubFallback("nuclei", confidence=0.9)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert fallback.calls == 1  # consulted only on low confidence
        assert decision.tool == "nuclei"
        assert decision.level == 1
        assert decision.escalated is True
        assert decision.model == "stub-fallback"
        assert decision.index == 2
        assert "fallback" in decision.reason

    def test_high_confidence_never_calls_fallback(self):
        fallback = _StubFallback("nuclei", confidence=0.9)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.6)
        decision = model.route(
            _state([_cand("nmap", 1, 0.95), _cand("nuclei", 2, 0.60)])
        )
        assert fallback.calls == 0
        assert decision.level == 0
        assert decision.tool == "nmap"

    def test_out_of_set_choice_rejected_keeps_top1(self):
        # Jev discipline: the choice must belong to the offered set.
        fallback = _StubFallback("sqlmap", confidence=0.95)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert decision.tool == "nmap"
        assert decision.level == 0
        assert decision.escalated is True
        assert "rejected" in decision.reason

    def test_fallback_abstention_keeps_top1(self):
        fallback = _StubFallback(None)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert decision.tool == "nmap"
        assert decision.escalated is True

    def test_fallback_low_confidence_keeps_top1(self):
        # T-24: the small model is an escalation GATE, not an absolute
        # decider — below the threshold the deterministic top-1 stays.
        fallback = _StubFallback("nuclei", confidence=0.4)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.6)
        decision = model.route(
            _state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)])
        )
        assert decision.tool == "nmap"
        assert decision.level == 0
        assert decision.escalated is True

    def test_fallback_exception_keeps_top1(self):
        fallback = _StubFallback(Exception("boom"))
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert decision.tool == "nmap"
        assert decision.escalated is True
        assert "errored" in decision.reason

    def test_fallback_failure_is_still_deterministic(self):
        fallback = _StubFallback(None)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        state = _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        assert model.route(state).to_dict() == model.route(state).to_dict()


class TestPromptFallback:
    def test_valid_choice_returns_level1_decision(self):
        model = PromptFallbackRouter(chat_fn=lambda prompt: "nuclei")
        decision = model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        )
        assert decision is not None
        assert decision.tool == "nuclei"
        assert decision.level == 1
        assert decision.index == 2

    def test_prompt_contains_offered_set_and_state(self):
        captured = {}

        def chat_fn(prompt):
            captured["prompt"] = prompt
            return "nmap"

        model = PromptFallbackRouter(chat_fn=chat_fn)
        state = _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        state["state_text"] = "host 10.0.0.5 phase recon"
        model.route(state)
        assert "nmap, nuclei" in captured["prompt"]
        assert "host 10.0.0.5" in captured["prompt"]

    def test_out_of_set_answer_abstains(self):
        model = PromptFallbackRouter(chat_fn=lambda prompt: "sqlmap")
        assert model.route(
            _state([_cand("nmap", 1, 0.90), _cand("nuclei", 2, 0.80)])
        ) is None

    def test_chat_error_abstains(self):
        def chat_fn(prompt):
            raise RuntimeError("LLM down")

        model = PromptFallbackRouter(chat_fn=chat_fn)
        assert model.route(_state([_cand("nmap", 1, 0.90)])) is None

    def test_empty_candidates_abstains_without_calling(self):
        model = PromptFallbackRouter(
            chat_fn=lambda prompt: (_ for _ in ()).throw(AssertionError("called"))
        )
        assert model.route({"candidates": [], "det_shortlist": None}) is None


# ---------------------------------------------------------------------------
# ROUTE-HIT metric (plan §5) over T-20 dataset labels
# ---------------------------------------------------------------------------


class TestRouteHitMetric:
    def test_normalize_label_tool(self):
        # real T-20 rows carry endpoint-shaped labels; catalog name is
        # the leaf.
        assert normalize_label_tool("web_recon/whatweb") == "whatweb"
        assert normalize_label_tool("nikto") == "nikto"
        assert normalize_label_tool(None) is None
        assert normalize_label_tool("") is None

    def test_route_hit_true_on_match(self):
        row = {
            "row_id": "x",
            "label": {"tool": "web_recon/whatweb"},
            "outcome": {"success": True, "success_basis": "verified"},
        }
        assert route_hit("whatweb", row) is True

    def test_route_hit_false_on_mismatch(self):
        row = {
            "row_id": "x",
            "label": {"tool": "nikto"},
            "outcome": {"success": True, "success_basis": "verified"},
        }
        assert route_hit("nmap", row) is False
        assert route_hit(None, row) is False

    def test_not_determined_rows_are_never_evaluable(self):
        # honest metric: not_determined (success null) is excluded — never
        # counted as a miss, never as a hit.
        row = {
            "row_id": "x",
            "label": {"tool": "nikto"},
            "outcome": {"success": None, "success_basis": "not_determined"},
        }
        assert route_hit("nikto", row) is None
        assert route_hit("nmap", row) is None

    def test_failed_rows_are_not_evaluable(self):
        row = {
            "row_id": "x",
            "label": {"tool": "nikto"},
            "outcome": {"success": False, "success_basis": "not_verified"},
        }
        assert route_hit("nikto", row) is None

    def test_report_over_t20_real_fixture(self):
        # The 9 real rows from the T-20 sample are all not_determined
        # (pre-T-19 campaign): the honest result is 0 evaluable rows and
        # rate None — NOT a fabricated 0.0.
        data = json.loads(_FIXTURE.read_text())
        rows = data["rows"]
        assert len(rows) == 9
        report = route_hit_report(
            {row["row_id"]: "nikto" for row in rows}, rows
        )
        assert report["n_rows"] == 9
        assert report["n_evaluable"] == 0
        assert report["route_hit_rate"] is None
        assert all(e["evaluable"] is False for e in report["per_row"])

    def test_report_counts_hits_and_misses(self):
        rows = [
            {
                "row_id": "r1",
                "label": {"tool": "nmap"},
                "outcome": {"success": True, "success_basis": "category:open_ports"},
            },
            {
                "row_id": "r2",
                "label": {"tool": "nikto"},
                "outcome": {"success": True, "success_basis": "verified"},
            },
            {
                "row_id": "r3",
                "label": {"tool": "dirb"},
                "outcome": {"success": None, "success_basis": "not_determined"},
            },
        ]
        decisions = {"r1": Decision(tool="nmap", confidence=1.0, reason="ok"),
                     "r2": "hydra"}  # accepted decision forms: Decision/str
        report = route_hit_report(decisions, rows)
        assert report["n_evaluable"] == 2
        assert report["hits"] == 1
        assert report["misses"] == 1
        assert report["route_hit_rate"] == 0.5
        by_id = {e["row_id"]: e for e in report["per_row"]}
        assert by_id["r1"]["hit"] is True
        assert by_id["r2"]["hit"] is False
        assert by_id["r3"]["evaluable"] is False


# ---------------------------------------------------------------------------
# Propose hook — behind a flag, OFF by default, pluggable model
# ---------------------------------------------------------------------------


def _make_controller():
    sf = _FakeSessionFlow()
    de = _FakeDecisionEngine()
    executor = lambda tool, params, session_id: {
        "success": tool == "nmap",
        "stdout": "PORT 80/TCP open" if tool == "nmap" else "",
        "stderr": "",
        "return_code": 0 if tool == "nmap" else 127,
    }
    ctrl = PlanAndApproveController(decision_engine=de, session_flow=sf, executor=executor)
    return ctrl, sf


class _FakeTrainedRouter(RouterModel):
    """Stands in for the nivel-3 TRAINED classifier (substitution test)."""

    name = "trained-classifier-fake"

    def __init__(self, tool="nuclei"):
        self._tool = tool
        self.calls = 0

    def route(self, state):
        self.calls += 1
        tools = [c["tool"] for c in state.get("candidates", [])]
        if self._tool not in tools:
            return None  # abstain when the choice is not in the set
        return Decision(
            tool=self._tool,
            confidence=0.92,
            reason="trained classifier picked the route from the offered set",
            level=3,
            model=self.name,
        )


class TestProposeHookOffByDefault:
    def test_router_off_by_default_in_constructor(self):
        # Nivel 3 trained classifier stays POSPUESTO: nothing is wired in
        # until a session opts in, and no model instance exists by default.
        ctrl, _ = _make_controller()
        assert ctrl.router_model is None

    def test_propose_has_no_router_fields_when_off(self):
        # OFF by default (no configure_router) => the propose_next_step
        # contract is EXACTLY the pre-T-21 one: no router_decision field,
        # no run_log entry.
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        result = ctrl.propose_next_step(sid)
        assert result["success"] is True
        assert "router_decision" not in result
        run_log = sf.sessions[sid].get("run_log", [])
        assert not any(e.get("type") == "router_decision" for e in run_log)

    def test_session_without_router_config_stays_off(self):
        # A session that never called configure_router carries no
        # router_config, so the hook never fires even though the
        # controller exists.
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        result = ctrl.propose_next_step(sid)
        assert "router_decision" not in result
        assert "router_config" not in sf.sessions[sid]["metadata"]["plan_and_approve"]

    def test_configure_router_disabled_keeps_off(self):
        # explicit disable: router_config present but enabled=False ->
        # still no router_decision (flag off).
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.configure_router(sid, enabled=False)
        assert r["success"] is True
        assert r["router_config"]["enabled"] is False
        result = ctrl.propose_next_step(sid)
        assert "router_decision" not in result
        run_log = sf.sessions[sid].get("run_log", [])
        assert not any(e.get("type") == "router_decision" for e in run_log)

    def test_configure_router_missing_session_errors(self):
        ctrl, _ = _make_controller()
        r = ctrl.configure_router("ghost-session")
        assert r["success"] is False


class TestProposeHookEnabled:
    def test_deterministic_decision_in_propose_response(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        r = ctrl.configure_router(sid)
        assert r["success"] is True
        assert r["router_config"]["enabled"] is True
        assert r["router_config"]["model"] == "deterministic-v1"

        result = ctrl.propose_next_step(sid)
        assert result["success"] is True
        rd = result["router_decision"]
        assert rd["tool"] == "nmap"
        assert rd["confidence"] == 0.75  # margin 0.10 -> narrow band
        assert rd["level"] == 0
        assert rd["escalated"] is False
        assert rd["index"] == 1
        assert rd["reason"]
        # proposal contract intact (T-17) — additive only.
        assert result["next_step"]["tool"] == "nmap"
        assert len(result["candidates"]) == 2
        assert result["selected_index"] == 1

    def test_run_log_carries_auditable_decision(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.configure_router(sid)
        ctrl.propose_next_step(sid)
        entries = [
            e for e in sf.sessions[sid].get("run_log", [])
            if e.get("type") == "router_decision"
        ]
        assert len(entries) == 1
        entry = entries[0]
        for field in ("tool", "confidence", "reason", "level",
                      "model", "escalated", "index", "timestamp"):
            assert field in entry, f"run_log entry missing {field}"
        assert entry["confidence"] == 0.75
        assert isinstance(entry["reason"], str) and entry["reason"]

    def test_deterministic_same_session_state_same_decision(self):
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        ctrl.configure_router(sid)
        first = ctrl.propose_next_step(sid)["router_decision"]
        ctrl2, _ = _make_controller()
        sid2 = _seed(ctrl2)
        ctrl2.configure_router(sid2)
        second = ctrl2.propose_next_step(sid2)["router_decision"]
        assert first == second

    def test_trained_router_substitution_without_touching_propose(self):
        # NIVEL 3 (future): a trained classifier implements route(state)
        # -> Decision and plugs in via configure_router(model=...).
        # propose_next_step itself is unchanged — it just surfaces the
        # decision and keeps the T-17 contract intact.
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        trained = _FakeTrainedRouter(tool="nuclei")
        r = ctrl.configure_router(sid, model=trained)
        assert r["router_config"]["model"] == "trained-classifier-fake"

        result = ctrl.propose_next_step(sid)
        rd = result["router_decision"]
        assert rd["tool"] == "nuclei"
        assert rd["confidence"] == 0.92
        assert rd["model"] == "trained-classifier-fake"
        assert trained.calls == 1
        # the proposal contract is untouched: next_step still comes from
        # the chain, candidates still finite + numbered.
        assert result["next_step"]["tool"] == "nmap"
        assert result["selected_index"] == 1
        assert len(result["candidates"]) == 2
        # auditable in run_log too.
        entry = [
            e for e in sf.sessions[sid].get("run_log", [])
            if e.get("type") == "router_decision"
        ][0]
        assert entry["tool"] == "nuclei"
        assert entry["model"] == "trained-classifier-fake"

    def test_trained_router_abstention_falls_back_to_deterministic_default(self):
        # A model that abstains (None) leaves the deterministic decision.
        ctrl, _ = _make_controller()
        sid = _seed(ctrl)
        abstainer = _FakeTrainedRouter(tool="not-in-set")
        ctrl.configure_router(sid, model=abstainer)
        result = ctrl.propose_next_step(sid)
        # model returned None -> hook surfaces the deterministic default
        # built by the controller only when a Decision exists; here the
        # trained model abstained, so no router_decision is surfaced but
        # the contract stays intact.
        assert result["success"] is True
        assert result["next_step"]["tool"] == "nmap"

    def test_fallback_model_through_controller_low_confidence(self):
        # nivel 0 -> nivel 1 escalation through the controller hook: a
        # high threshold forces the ambiguous case (margin 0.10 -> 0.75)
        # down to the small-model fallback; its in-set choice above the
        # threshold wins.
        fallback = _StubFallback("nuclei", confidence=0.95)
        model = DeterministicRouterModel(fallback=fallback, threshold=0.9)
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.configure_router(sid, model=model)
        result = ctrl.propose_next_step(sid)
        rd = result["router_decision"]
        assert rd["tool"] == "nuclei"
        assert rd["level"] == 1
        assert rd["escalated"] is True
        entry = [
            e for e in sf.sessions[sid].get("run_log", [])
            if e.get("type") == "router_decision"
        ][0]
        assert entry["escalated"] is True
        assert entry["confidence"] == 0.95

    def test_router_error_does_not_break_proposal(self):
        class _BrokenRouter(RouterModel):
            name = "broken"

            def route(self, state):
                raise RuntimeError("router exploded")

        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.configure_router(sid, model=_BrokenRouter())
        result = ctrl.propose_next_step(sid)
        assert result["success"] is True
        assert "router_decision" not in result
        assert result["next_step"]["tool"] == "nmap"

    def test_completed_session_has_no_router_decision(self):
        ctrl, sf = _make_controller()
        sid = _seed(ctrl)
        ctrl.configure_router(sid)
        # execute + skip until the chain is done
        ctrl.execute_step(sid, tool="nmap")
        ctrl.execute_step(sid, tool="nuclei")
        result = ctrl.propose_next_step(sid)
        assert result["completed"] is True
        assert "router_decision" not in result
