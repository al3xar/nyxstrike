"""Router v1 — fast routing model for the TFM routing layer (T-21).

Implements NIVEL 1-2 of the router model fixed by the ADR
(`hades-tfm/wiki/nyxstrike/adr-router-decision-indexado.md`, §4) and the
T-24 spike findings (``hades-tfm/evidences/t24-router-spike/INFORME.md``):

* **Nivel 0 (determinista, this module's default):** reuse the decision
  engine's precision-first ranking (``rank_tools_precision_first`` via
  ``select_optimal_tools`` / ``_index_candidates``) and emit
  ``(ruta, confianza, razón)``. 100% offline, 0 network calls,
  microseconds, fully auditable.
* **Nivel 1 (fallback a modelo pequeño, optional):** when the deterministic
  top-1 has LOW confidence (tie / narrow margin, below the ~0.6 threshold
  measured in T-24), delegate to a pluggable small-model fallback with the
  ``_classify_with_llm`` pattern (``tool_registry.py:2684``): one cheap call,
  constrained to the offered shortlist (Jev discipline — the choice must
  belong to the set; anything else is rejected and the deterministic top-1
  is kept, with the supervisor notified).
* **Nivel 3 (clasificador entrenado): POSPUESTO.** The pluggable
  ``RouterModel.route(state) -> Decision`` interface is designed so a trained
  classifier can replace the deterministic model WITHOUT touching
  ``propose_next_step``; it only activates if the T-22 benchmark justifies
  it (flag OFF by default — T-23).

Design decisions grounded in the T-24 spike (measured, not estimated):
  * determinist as production decider (0.21 ms, $0, 100% explainable);
  * small model only as *escalation gate* on ambiguous cases, threshold
    ~0.6 (Jev's measured median confidence was 0.505 — it does not trust);
  * low confidence => keep deterministic top-1 + escalate flag for the
    supervisor (the model never decides alone below threshold).

Offline route-hit metric (ROUTE-HIT, plan §5 / T-20 dataset
``hades-routes-dataset/v1``): proposed route vs the route that WORKED,
using T-20 labels. Only rows whose ``outcome.success is True`` (grounded
``success_basis`` per T-20 §4) are evaluable — ``not_determined`` rows are
EXCLUDED, never counted as misses (no fabricated labels).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Escalation threshold (T-24: Jev confidence median 0.505 -> threshold ~0.6).
#: Below this, the deterministic top-1 is kept and the supervisor is flagged.
ROUTER_CONFIDENCE_THRESHOLD = 0.6

#: Minimum margin between top-1 and runner-up for a "clear winner" (1.0).
#: Mirrors the 3-level ``classify_intent`` calibration (1.0 / 0.75 / 0.5),
#: now applied to the score margin instead of the keyword-margin scale.
CLEAR_MARGIN = 0.15
NARROW_MARGIN = 0.05


# ---------------------------------------------------------------------------
# Decision — the router's output contract
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    """One routing decision: (ruta, confianza, razón) + audit fields.

    * ``tool``: the chosen route (tool name). ``None`` = no decision
      (empty candidate set — the supervisor must act, never a silent guess).
    * ``confidence``: calibrated in [0, 1] (3-tier pattern of
      ``classify_intent`` applied to the effective-score margin).
    * ``reason``: human/machine-readable rationale — auditable, grounded.
    * ``level``: 0 = deterministic, 1 = small-model fallback, 3 = trained
      classifier (future).
    * ``escalated``: True when the decision was made at/after the fallback
      stage OR when low confidence forced the supervisor to review.
    * ``index``: 1-based position of the chosen tool inside the offered
      candidate set (Jev-style: the supervisor answers with an index).
    """

    tool: Optional[str]
    confidence: float
    reason: str
    level: int = 0
    escalated: bool = False
    model: str = "deterministic-v1"
    index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ``RoutingState`` is a plain dict (JSON-serialisable, session-storeable)
# aligned with the T-20 dataset ``state`` block:
#
#     {
#       "state_text": str | None,     # textual state (T-20 dataset field)
#       "phase": str | None,          # setup | exploitation | impact | ...
#       "candidates": [               # production: _index_candidates output
#           {"tool", "index", "confidence", "effective_score", ...},
#           ...
#       ],
#       "det_shortlist": [str, ...],  # offline/dataset: T-20 context.det_shortlist
#       "context": {...},             # pass-through for custom models
#     }
RoutingState = Dict[str, Any]


# ---------------------------------------------------------------------------
# Pluggable interface (nivel 3 will implement this, see module docstring)
# ---------------------------------------------------------------------------


class RouterModel(ABC):
    """Pluggable routing-model interface.

    A future TRAINED classifier (nivel 3) implements ``route`` and is
    swapped in via ``PlanAndApproveController.router_model`` —
    ``propose_next_step`` only ever calls ``route(state) -> Decision`` and
    never inspects model internals.

    Contract:
      * deterministic on equal input (same state -> same Decision);
      * the chosen tool MUST belong to the offered candidates when one is
        given (Jev's ``validate_choice`` discipline); models may ABSTAIN
        by returning ``None`` — the deterministic top-1 is then kept;
      * confidence in [0, 1], reason grounded (never invented).
    """

    name: str = "abstract"

    @abstractmethod
    def route(self, state: RoutingState) -> Optional[Decision]:
        """Return a Decision for *state*, or None to abstain."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Deterministic router (nivel 0) + small-model fallback (nivel 1)
# ---------------------------------------------------------------------------


def _candidates_from_state(state: RoutingState) -> List[Dict[str, Any]]:
    """Normalise the offered candidate set from the state.

    Production states carry ``candidates`` (``_index_candidates`` output).
    Offline/dataset states carry only ``det_shortlist`` (T-20
    ``state.context.det_shortlist``): synthesised with the low-signal
    tier (0.5) because no score margin is available from the dataset.
    """
    candidates = state.get("candidates")
    if isinstance(candidates, list) and candidates:
        return [c for c in candidates if isinstance(c, dict) and c.get("tool")]
    shortlist = state.get("det_shortlist")
    if isinstance(shortlist, list) and shortlist:
        return [
            {
                "tool": tool,
                "index": i + 1,
                "confidence": 0.5,
                "effective_score": None,
            }
            for i, tool in enumerate(dict.fromkeys(shortlist))
            if tool
        ]
    return []


def _calibrated_confidence(candidates: List[Dict[str, Any]]) -> float:
    """Calibrate top-1 confidence from the margin vs the runner-up.

    3-tier pattern of ``classify_intent`` (1.0 / 0.75 / 0.5) applied to
    the effective-score margin:
      * unique candidate                -> 1.0 (nothing to beat)
      * margin >= CLEAR_MARGIN          -> 1.0 (clear winner)
      * NARROW_MARGIN < margin < CLEAR  -> 0.75 (narrow band)
      * margin <= NARROW_MARGIN         -> 0.5 (tie / ambiguous)
      * no scores available             -> 0.75 (moderate; margin unknown)
    """
    if len(candidates) == 1:
        return 1.0
    top_score = candidates[0].get("effective_score")
    second_score = candidates[1].get("effective_score")
    if not isinstance(top_score, (int, float)) or not isinstance(second_score, (int, float)):
        return 0.75
    margin = float(top_score) - float(second_score)
    if margin >= CLEAR_MARGIN:
        return 1.0
    if margin > NARROW_MARGIN:
        return 0.75
    return 0.5


class DeterministicRouterModel(RouterModel):
    """Nivel 0-1 router: deterministic top-1 + optional small-model fallback.

    100% offline and deterministic unless ``fallback`` (a nivel-1
    ``RouterModel`` with a model behind it) returns a decision. The
    fallback is consulted ONLY when the deterministic confidence is below
    the threshold (T-24: "Jev como gate de escalación, no decisor
    absoluto"), and its choice is validated against the offered set.
    """

    name = "deterministic-v1"

    def __init__(
        self,
        fallback: Optional[RouterModel] = None,
        threshold: float = ROUTER_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.fallback = fallback
        self.threshold = float(threshold)

    def route(self, state: RoutingState) -> Optional[Decision]:
        candidates = _candidates_from_state(state)
        if not candidates:
            return Decision(
                tool=None,
                confidence=0.0,
                reason="empty candidate set; no deterministic route — supervisor must act",
                level=0,
                escalated=True,
                model=self.name,
            )

        top = candidates[0]
        top_tool = top.get("tool")
        confidence = _calibrated_confidence(candidates)
        margin = _margin_text(candidates)
        reason = (
            f"deterministic top-1 '{top_tool}'"
            f"{margin} — confidence {confidence:g} "
            f"({'clear winner' if confidence >= 1 else 'narrow band' if confidence >= 0.75 else 'tie/ambiguous'})"
        )

        if confidence >= self.threshold:
            return Decision(
                tool=top_tool,
                confidence=confidence,
                reason=reason,
                level=0,
                escalated=False,
                model=self.name,
                index=_index_of(candidates, top_tool),
            )

        # Low confidence -> escalation path (nivel 1 fallback, if any).
        if self.fallback is None:
            reason += " — below threshold: kept deterministic top-1, supervisor must review"
            return Decision(
                tool=top_tool,
                confidence=confidence,
                reason=reason,
                level=0,
                escalated=True,
                model=self.name,
                index=_index_of(candidates, top_tool),
            )

        try:
            fb = self.fallback.route(state)
        except Exception as exc:  # noqa: BLE001 — fallback must never break routing
            logger.warning("router fallback %s failed: %s", self.fallback.name, exc)
            fb = None
        if fb is not None and fb.tool in {c.get("tool") for c in candidates} and fb.confidence >= self.threshold:
            return Decision(
                tool=fb.tool,
                confidence=fb.confidence,
                reason=f"fallback '{self.fallback.name}' (low deterministic confidence{margin}): {fb.reason}",
                level=1,
                escalated=True,
                model=self.fallback.name,
                index=_index_of(candidates, fb.tool),
            )
        fb_note = (
            "fallback abstained/rejected"
            if fb is not None
            else "fallback errored"
        )
        reason += f" — below threshold: {fb_note}, kept deterministic top-1, supervisor must review"
        return Decision(
            tool=top_tool,
            confidence=confidence,
            reason=reason,
            level=0,
            escalated=True,
            model=self.name,
            index=_index_of(candidates, top_tool),
        )


def _margin_text(candidates: List[Dict[str, Any]]) -> str:
    if len(candidates) < 2:
        return " (unique candidate)"
    top_score = candidates[0].get("effective_score")
    second_score = candidates[1].get("effective_score")
    if not isinstance(top_score, (int, float)) or not isinstance(second_score, (int, float)):
        return " (margin vs runner-up unknown)"
    return f" (margin {top_score - second_score:.3f} over runner-up)"


def _index_of(candidates: List[Dict[str, Any]], tool: Optional[str]) -> Optional[int]:
    for i, c in enumerate(candidates):
        if c.get("tool") == tool:
            return c.get("index", i + 1)
    return None


# ---------------------------------------------------------------------------
# Nivel 1: small-model fallback (pattern _classify_with_llm, tool_registry.py:2684)
# ---------------------------------------------------------------------------


class PromptFallbackRouter(RouterModel):
    """Small-LLM fallback constrained to the offered shortlist.

    Mirrors the ``_classify_with_llm`` pattern: ONE cheap chat call with a
    constrained prompt ("exactly one tool from this list"), and the answer
    is validated against the set — an out-of-set answer (or any error)
    yields abstention (None) so the deterministic top-1 is kept.
    ``chat_fn(prompt: str) -> str`` is injectable (tests / real LLM client).
    """

    name = "prompt-fallback-v1"

    _PROMPT = (
        "Choose EXACTLY ONE tool from this list, matching the current state.\n"
        "Tools: {tools}\n"
        "State: {state}\n"
        "Tool:"
    )

    def __init__(self, chat_fn: Callable[[str], str], confidence: float = 0.75) -> None:
        self._chat_fn = chat_fn
        self._confidence = float(confidence)

    def route(self, state: RoutingState) -> Optional[Decision]:
        candidates = _candidates_from_state(state)
        if not candidates:
            return None
        allowed = [c["tool"] for c in candidates]
        prompt = self._PROMPT.format(
            tools=", ".join(allowed),
            state=state.get("state_text") or "n/a",
        )
        try:
            raw = self._chat_fn(prompt)
        except Exception as exc:
            logger.warning("PromptFallbackRouter: chat failed: %s", exc)
            return None
        choice = (raw or "").lower().strip()
        choice = choice.split("tool:")[-1].strip() if "tool:" in choice else choice
        if choice not in allowed:
            return None
        return Decision(
            tool=choice,
            confidence=self._confidence,
            reason=f"small-model fallback chose '{choice}' from the offered shortlist",
            level=1,
            escalated=True,
            model=self.name,
            index=_index_of(candidates, choice),
        )


# ---------------------------------------------------------------------------
# ROUTE-HIT metric (plan §5; T-20 dataset labels, hades-routes-dataset/v1)
# ---------------------------------------------------------------------------


def normalize_label_tool(label_tool: Optional[str]) -> Optional[str]:
    """Normalise a T-20 ``label.tool`` (measured) to a catalog tool name.

    Real rows carry endpoints/paths like ``"web_recon/whatweb"``; the
    catalog name is the leaf. Plain names (``"nikto"``) pass through.
    """
    if not label_tool:
        return None
    return label_tool.split("/")[-1].strip()


def route_hit(decision_tool: Optional[str], row: Dict[str, Any]) -> Optional[bool]:
    """ROUTE-HIT for one decision vs one dataset row.

    Returns True/False only for EVALUABLE rows (``outcome.success is
    True`` — the route that WORKED, per T-20 §4 criterion). Rows that are
    ``not_determined`` (success is null) or failed return None: excluded
    from the rate, never counted as misses (no fabricated labels).
    """
    outcome = row.get("outcome") or {}
    if outcome.get("success") is not True:
        return None
    label = normalize_label_tool((row.get("label") or {}).get("tool"))
    if label is None:
        return None
    return bool(decision_tool) and decision_tool == label


def route_hit_report(
    decisions: Dict[str, Any],
    rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Aggregate ROUTE-HIT over decisions matched to T-20 rows by ``row_id``.

    ``decisions`` maps ``row_id -> Decision | {"tool": ...} | str``.
    Honest by construction: only ``outcome.success is True`` rows are
    evaluable; with zero evaluable rows the rate is ``None`` (never 0.0,
    never 1.0).
    """
    per_row: List[Dict[str, Any]] = []
    evaluable = 0
    hits = 0
    for row in rows:
        row_id = row.get("row_id")
        decision = decisions.get(row_id) if row_id is not None else None
        decision_tool = None
        if isinstance(decision, Decision):
            decision_tool = decision.tool
        elif isinstance(decision, dict):
            decision_tool = decision.get("tool")
        elif isinstance(decision, str):
            decision_tool = decision
        verdict = route_hit(decision_tool, row)
        entry = {
            "row_id": row_id,
            "decision_tool": decision_tool,
            "label_tool": normalize_label_tool((row.get("label") or {}).get("tool")),
            "evaluable": verdict is not None,
            "hit": verdict,
        }
        per_row.append(entry)
        if verdict is not None:
            evaluable += 1
            hits += 1 if verdict else 0
    return {
        "metric": "route-hit",
        "n_rows": len(rows),
        "n_evaluable": evaluable,
        "hits": hits,
        "misses": evaluable - hits,
        "route_hit_rate": (hits / evaluable) if evaluable else None,
        "per_row": per_row,
    }
