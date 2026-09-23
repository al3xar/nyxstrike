"""Jev router fallback (T-21 nivel 1) — TypeSafe System One as the escalation gate.

The router v1 (``router.py``) decides deterministically at nivel 0 and only
consults a small model when the deterministic confidence falls below the
threshold (T-24: "Jev como gate de escalación, no decisor absoluto"). The
existing ``PromptFallbackRouter`` does this with a free-text chat call; this
module provides ``JevRouterModel``, a ``RouterModel`` that instead asks
**TypeSafe's System One model (Jev)** a typed ``Choice`` question and consumes
its calibrated confidence.

Design (see the spec:
``docs/superpowers/specs/2026-09-23-tool-selector-typesafe-design.md``):

* The candidate set and its ordering come from upstream
  (``_index_candidates`` → ``effective_score``, which already folds in
  ``tool_registry`` ``effectiveness``). This model does NOT re-mix that prior
  into the prompt: Jev's judgment stays raw and reusable, and the deterministic
  gate in ``DeterministicRouterModel`` owns whether to accept it.
* The ``Choice`` ``criteria`` are built from each tool's ``desc`` in
  ``tool_registry`` — the single source of truth. The ``tool-policy.md`` table
  stays as human documentation, not as logic.
* The choice is validated against the offered shortlist (``choice in allowed``,
  Jev's ``validate_choice`` discipline). Out-of-set ⇒ abstain (``None``).
* The SDK call lives behind an injectable ``judge_fn`` so tests run fully
  offline. The default ``judge_fn`` lazily imports ``typesafe_sdk`` and reads
  the API key from the ``TYPESAFE_API_KEY`` environment variable. A missing
  SDK, a missing key, a timeout or any network error is caught and turned into
  abstention (``None``) — the deterministic top-1 is kept, the pipeline never
  blocks.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.server_core.intelligence.router import (
    ADVANCE_PHASE,
    Decision,
    RouterModel,
    RoutingState,
    DeterministicRouterModel,
    ROUTER_CONFIDENCE_THRESHOLD,
    _candidates_from_state,
    _index_of,
)

logger = logging.getLogger(__name__)

#: A judge takes the textual state, the ``{tool: description}`` criteria and the
#: full routing state, and returns ``(choice, confidence)``. ``choice`` may be
#: ``None`` (or any out-of-set value) to abstain.
JudgeFn = Callable[[str, Dict[str, str], RoutingState], Tuple[Optional[str], float]]

#: A describer maps a tool name to the description shown to the model.
DescribeFn = Callable[[str], str]

_INSTRUCTIONS = (
    "Given the current penetration-testing engagement state and phase, which "
    "tool is the best next step? Choose exactly one option from the offered set — "
    "the tool that yields the most new, useful signal given what has already run, "
    f"or '{ADVANCE_PHASE}' if no offered tool would add useful signal and the "
    "engagement should move on to the next phase."
)

#: Description shown to the model for the non-tool escape option.
_ADVANCE_PHASE_DESC = (
    "None of the offered tools would add useful new signal in this phase — the "
    "phase is exhausted or its goal is already met; advance to the next phase."
)


def _describe_tool(tool: str) -> str:
    """Return the catalog description for *tool*, falling back to its name.

    The description is the single source of truth in ``tool_registry`` (`desc`).
    Imported lazily so this module carries no import-time dependency on the
    registry (and no circular-import risk from the intelligence package).
    """
    try:
        from tool_registry import get_tool  # local, flat top-level module

        defn = get_tool(tool)
        if defn and defn.get("desc"):
            return str(defn["desc"])
    except Exception as exc:  # noqa: BLE001 — describing must never break routing
        logger.debug("router_jev: could not describe %r: %s", tool, exc)
    return tool


def _default_typesafe_judge(
    state_text: str,
    criteria: Dict[str, str],
    state: RoutingState,
) -> Tuple[Optional[str], float]:
    """Ask TypeSafe System One (Jev) a single typed ``Choice`` question.

    Lazily imports ``typesafe_sdk``; the API key is read by the SDK from the
    ``TYPESAFE_API_KEY`` environment variable. Any failure (SDK absent, key
    absent, timeout, network) propagates as an exception — ``JevRouterModel``
    catches it and abstains, so the deterministic top-1 is kept.
    """
    from typesafe_sdk import TypeSafeClient, Choice  # deferred: optional dep

    ctx: Dict[str, Any] = {"engagement_state": state_text}
    phase = state.get("phase")
    if phase:
        ctx["phase"] = phase
    already_run = state.get("context", {}).get("tools_run") if isinstance(state.get("context"), dict) else None
    if already_run:
        ctx["tools_already_run"] = already_run

    with TypeSafeClient() as client:
        response = client.system_one(
            state=ctx,
            questions={
                "tool": Choice(instructions=_INSTRUCTIONS, criteria=dict(criteria)),
            },
        )
    answer = response.choices["tool"]
    return answer.choice, float(answer.confidence)


class JevRouterModel(RouterModel):
    """Nivel-1 router fallback backed by TypeSafe System One (Jev).

    Consulted by ``DeterministicRouterModel`` only when the deterministic
    confidence is below the threshold. Returns a ``Decision`` (level 1,
    escalated) when Jev picks an in-set tool, or ``None`` (abstain) on empty
    candidate set, out-of-set choice, or any error.
    """

    name = "jev-typesafe-v1"

    def __init__(
        self,
        judge_fn: Optional[JudgeFn] = None,
        *,
        describe: Optional[DescribeFn] = None,
        allow_advance_phase: bool = True,
    ) -> None:
        self._judge_fn: JudgeFn = judge_fn or _default_typesafe_judge
        self._describe: DescribeFn = describe or _describe_tool
        #: When True, the Choice offers an ``ADVANCE_PHASE`` escape option so Jev
        #: can signal "no offered tool helps — move on" instead of being forced
        #: to pick a tool (the "none-of-these" of the TypeSafe docs).
        self._allow_advance_phase = bool(allow_advance_phase)

    def route(self, state: RoutingState) -> Optional[Decision]:
        candidates: List[Dict[str, Any]] = _candidates_from_state(state)
        if not candidates:
            return None

        tool_names = [c["tool"] for c in candidates]
        criteria = {tool: self._describe(tool) for tool in tool_names}
        allowed = set(tool_names)
        if self._allow_advance_phase:
            criteria[ADVANCE_PHASE] = _ADVANCE_PHASE_DESC
            allowed.add(ADVANCE_PHASE)
        state_text = state.get("state_text") or "n/a"

        try:
            choice, confidence = self._judge_fn(state_text, criteria, state)
        except Exception as exc:  # noqa: BLE001 — a fallback must never break routing
            logger.warning("JevRouterModel: system_one judge failed: %s", exc)
            return None

        if choice not in allowed:
            # Out-of-set (or None) — Jev's validate_choice discipline: abstain
            # so the deterministic top-1 is kept.
            return None

        if choice == ADVANCE_PHASE:
            # Non-tool action: the router decides "advance", the supervisor/
            # state-machine acts on it. tool/index stay None by contract.
            return Decision(
                tool=None,
                confidence=float(confidence),
                reason="Jev (System One): no offered tool adds useful signal — advance phase",
                level=1,
                escalated=True,
                model=self.name,
                index=None,
                action=ADVANCE_PHASE,
            )

        return Decision(
            tool=choice,
            confidence=float(confidence),
            reason=f"Jev (System One) chose '{choice}' from the offered shortlist",
            level=1,
            escalated=True,
            model=self.name,
            index=_index_of(candidates, choice),
        )


def make_jev_router(
    threshold: float = ROUTER_CONFIDENCE_THRESHOLD,
    *,
    judge_fn: Optional[JudgeFn] = None,
    describe: Optional[DescribeFn] = None,
    allow_advance_phase: bool = True,
) -> DeterministicRouterModel:
    """Deterministic router with the Jev/TypeSafe fallback wired as nivel 1.

    Opt in per session::

        from backend.server_core.intelligence.router_jev import make_jev_router
        controller.configure_router(sid, enabled=True, model=make_jev_router())

    Deterministic nivel 0 still decides in production; Jev is consulted only on
    low-confidence cases and its choice is revalidated against the shortlist.
    """
    return DeterministicRouterModel(
        fallback=JevRouterModel(
            judge_fn=judge_fn,
            describe=describe,
            allow_advance_phase=allow_advance_phase,
        ),
        threshold=threshold,
    )
