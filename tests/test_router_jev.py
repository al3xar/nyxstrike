"""
tests/test_router_jev.py

Unit tests for the Jev/TypeSafe router fallback (T-21 nivel 1):
  backend/server_core/intelligence/router_jev.py

Fully offline — no TypeSafe SDK, no network. The System One call is injected
via ``judge_fn`` and tool descriptions via ``describe``. Covers:

  * in-set choice with confidence -> level-1 Decision (tool/index/model/reason);
  * out-of-set choice -> abstain (None) (Jev's validate_choice discipline);
  * None choice -> abstain;
  * judge_fn raises -> abstain (a fallback must never break routing);
  * empty candidate set -> abstain;
  * criteria are built from tool descriptions (single source of truth);
  * integration through DeterministicRouterModel: Jev consulted ONLY below
    threshold, accepted when in-set, revalidated against the shortlist.
"""

from typing import Dict, Optional, Tuple

from backend.server_core.intelligence.router import (
    ADVANCE_PHASE,
    Decision,
    DeterministicRouterModel,
    RoutingState,
)
from backend.server_core.intelligence.router_jev import (
    JevRouterModel,
    make_jev_router,
)


def _cand(tool, index, score):
    return {
        "tool": tool,
        "index": index,
        "confidence": None,
        "effective_score": score,
    }


def _state(candidates):
    return {
        "state_text": "target=10.0.0.5 phase=recon",
        "phase": "recon",
        "candidates": candidates,
        "det_shortlist": [c["tool"] for c in candidates],
        "context": {},
    }


class _RecordingJudge:
    """A stand-in for the TypeSafe System One call."""

    def __init__(self, choice: Optional[str], confidence: float = 0.9):
        self._choice = choice
        self._confidence = confidence
        self.calls = 0
        self.last_criteria: Optional[Dict[str, str]] = None
        self.last_state_text: Optional[str] = None

    def __call__(self, state_text: str, criteria: Dict[str, str], state: RoutingState) -> Tuple[Optional[str], float]:
        self.calls += 1
        self.last_criteria = criteria
        self.last_state_text = state_text
        return self._choice, self._confidence


def _describe(tool: str) -> str:
    return f"desc::{tool}"


class TestJevRouterModel:
    def test_in_set_choice_returns_level1_decision(self):
        judge = _RecordingJudge("nuclei", confidence=0.88)
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.8), _cand("nuclei", 2, 0.79)]))
        assert isinstance(decision, Decision)
        assert decision.tool == "nuclei"
        assert decision.confidence == 0.88
        assert decision.level == 1
        assert decision.escalated is True
        assert decision.model == "jev-typesafe-v1"
        assert decision.index == 2
        assert "Jev" in decision.reason

    def test_out_of_set_choice_abstains(self):
        judge = _RecordingJudge("sqlmap")  # not among candidates
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.8), _cand("nuclei", 2, 0.79)]))
        assert decision is None

    def test_none_choice_abstains(self):
        judge = _RecordingJudge(None)
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        assert model.route(_state([_cand("nmap", 1, 0.8)])) is None

    def test_judge_exception_abstains(self):
        def boom(state_text, criteria, state):
            raise RuntimeError("system_one timeout")

        model = JevRouterModel(judge_fn=boom, describe=_describe)
        assert model.route(_state([_cand("nmap", 1, 0.8)])) is None

    def test_empty_candidates_abstains(self):
        judge = _RecordingJudge("nmap")
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        assert model.route(_state([])) is None
        assert judge.calls == 0  # never consulted with no candidates

    def test_criteria_built_from_descriptions(self):
        judge = _RecordingJudge("nmap")
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        model.route(_state([_cand("nmap", 1, 0.8), _cand("nuclei", 2, 0.7)]))
        assert judge.last_criteria == {"nmap": "desc::nmap", "nuclei": "desc::nuclei"}
        assert judge.last_state_text == "target=10.0.0.5 phase=recon"

    def test_default_describe_uses_tool_registry(self):
        # No injected describe: falls back to the tool_registry desc (or the
        # tool name if the tool is unknown). Must not raise.
        judge = _RecordingJudge("definitely_not_a_real_tool_xyz")
        model = JevRouterModel(judge_fn=judge)
        state = _state([_cand("definitely_not_a_real_tool_xyz", 1, 0.8)])
        # unknown tool -> description falls back to the name itself
        model.route(state)
        assert judge.last_criteria == {
            "definitely_not_a_real_tool_xyz": "definitely_not_a_real_tool_xyz"
        }


class TestAdvancePhaseEscape:
    def test_advance_phase_is_offered_in_criteria(self):
        judge = _RecordingJudge("nmap")
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        model.route(_state([_cand("nmap", 1, 0.8)]))
        assert ADVANCE_PHASE in judge.last_criteria
        assert judge.last_criteria[ADVANCE_PHASE]  # has a non-empty description

    def test_jev_picks_advance_phase(self):
        judge = _RecordingJudge(ADVANCE_PHASE, confidence=0.9)
        model = JevRouterModel(judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.8), _cand("nuclei", 2, 0.7)]))
        assert isinstance(decision, Decision)
        assert decision.action == ADVANCE_PHASE
        assert decision.tool is None
        assert decision.index is None
        assert decision.level == 1
        assert decision.escalated is True
        assert decision.confidence == 0.9

    def test_advance_phase_disabled_removes_option_and_abstains(self):
        judge = _RecordingJudge(ADVANCE_PHASE)
        model = JevRouterModel(judge_fn=judge, describe=_describe, allow_advance_phase=False)
        decision = model.route(_state([_cand("nmap", 1, 0.8)]))
        assert ADVANCE_PHASE not in judge.last_criteria
        # If the judge still returns it, it's out of set -> abstain.
        assert decision is None

    def test_gate_accepts_advance_phase_from_fallback(self):
        judge = _RecordingJudge(ADVANCE_PHASE, confidence=0.95)
        # Tie -> deterministic confidence 0.5 < threshold 0.9 -> consult Jev.
        model = make_jev_router(threshold=0.9, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)]))
        assert judge.calls == 1
        assert decision.action == ADVANCE_PHASE
        assert decision.tool is None
        assert decision.level == 1
        assert decision.model == "jev-typesafe-v1"

    def test_gate_rejects_low_confidence_advance_phase(self):
        # advance_phase under the threshold: the deterministic top-1 is kept.
        judge = _RecordingJudge(ADVANCE_PHASE, confidence=0.4)
        model = make_jev_router(threshold=0.6, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)]))
        assert decision.tool == "nmap"
        assert decision.action is None
        assert decision.level == 0


class TestIntegrationWithDeterministicGate:
    def test_jev_consulted_only_below_threshold(self):
        judge = _RecordingJudge("nuclei", confidence=0.9)
        # Clear winner (margin 0.35 >= CLEAR_MARGIN) -> confidence 1.0 -> no fallback.
        model = make_jev_router(threshold=0.6, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.95), _cand("nuclei", 2, 0.60)]))
        assert decision.tool == "nmap"
        assert decision.level == 0
        assert judge.calls == 0

    def test_jev_accepted_when_in_set_and_confident(self):
        judge = _RecordingJudge("nuclei", confidence=0.95)
        # Tie -> deterministic confidence 0.5 < threshold 0.9 -> consult Jev.
        model = make_jev_router(threshold=0.9, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)]))
        assert judge.calls == 1
        assert decision.tool == "nuclei"
        assert decision.level == 1
        assert decision.model == "jev-typesafe-v1"
        assert decision.escalated is True

    def test_jev_abstention_keeps_deterministic_top1(self):
        judge = _RecordingJudge(None)  # abstains
        model = make_jev_router(threshold=0.9, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)]))
        assert judge.calls == 1
        assert decision.tool == "nmap"  # deterministic top-1 kept
        assert decision.level == 0
        assert decision.escalated is True

    def test_jev_low_confidence_keeps_deterministic_top1(self):
        # Jev picks in-set but under the threshold: the gate keeps the top-1.
        judge = _RecordingJudge("nuclei", confidence=0.4)
        model = make_jev_router(threshold=0.6, judge_fn=judge, describe=_describe)
        decision = model.route(_state([_cand("nmap", 1, 0.80), _cand("nuclei", 2, 0.80)]))
        assert decision.tool == "nmap"
        assert decision.level == 0
