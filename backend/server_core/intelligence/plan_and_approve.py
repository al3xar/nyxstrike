"""Plan-and-approve contract controller (Pilar 4, cap. 8).

This is the deterministic intelligence core that binds the Intelligent
Decision Engine + AttackChain into a *stateful* contract Hades (the LLM
supervisor) drives one step at a time:

    profile_target  ->  propose_next_step  ->  execute_step  ->
    update_chain    ->  chain_report

Design goals (see doc/capitulos/08_agente_ia_mcp.tex, sec:plan-and-approve):

* The *plan* lives here in NyxStrike, deterministically; the LLM only
  approves / rejects / reorients each single step.
* ``propose_next_step`` NEVER executes anything — execution only happens on
  an explicit ``execute_step`` call. This is what makes the pattern
  "plan-and-approve" rather than a free-running orchestrator.
* State (profile + chain + runtime cursor) is persisted in a session via
  ``session_flow`` so the contract survives across separate MCP calls.
* ``chain_report`` adds ATT&CK tactic tagging derived *only* from the tool
  catalog's own capabilities — it is grounded, not invented.

The controller is intentionally dependency-injectable (decision_engine,
session_flow module, and a step executor) so the contract can be exercised
by tests with a stubbed executor and no real tool processes.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from backend.server_core.attack_chain import AttackChain
from backend.server_core.attack_step import AttackStep
from backend.server_core.target_profile import TargetProfile

logger = logging.getLogger(__name__)

PA_METADATA_KEY = "plan_and_approve"
PA_SOURCE = "plan_and_approve"

# Upper bound for the indexed candidate set exposed by propose_next_step.
# Mirrors the decision engine's max_tools so the action space stays finite and
# bounded (Jev's "Up to N action candidates" discipline).
MAX_INDEXED_CANDIDATES = 8

# Step lifecycle statuses within a plan-and-approve chain.
STATUS_PROPOSED = "proposed"
STATUS_APPROVED = "approved"
STATUS_EXECUTED = "executed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# ATT&CK tactic derivation — grounded in the tool catalog's own capabilities.
#
# The map is restricted to the 14 CANONICAL tactics of the MITRE ATT&CK
# Enterprise matrix (attack.mitre.org, v19). Two names B1 shipped —
# "Exploitation" and "Vulnerability Exploitation" — are NOT tactics in the
# matrix and never match a Wazuh alert; they are normalised below:
#   * vulnerability scanning  -> Discovery  (T1595.002 Vulnerability Scanning
#                                            is a Discovery technique)
#   * exploiting a public-facing application (web_exploit / exploitation /
#     cve_exploitation)       -> Initial Access (T1190)
#   * binary analysis / binary exploitation / payload generation -> Execution
#     (T1059)
# The 25 capabilities that B1 left unlabelled are added and mapped to the
# nearest canonical tactic. The map is only ever *consulted* by
# ``_tactic_for_capabilities``; capabilities not present stay unlabelled
# (grounded: never invented).
# ---------------------------------------------------------------------------

_CAPABILITY_TO_TACTIC: Dict[str, str] = {
    # --- Discovery (TA0007) ---
    "surface": "Discovery",
    "network_scan": "Discovery",
    "service_enumeration": "Discovery",
    "web_fingerprint": "Discovery",
    "api_discovery": "Discovery",
    "api_assessment": "Discovery",
    "enumeration": "Discovery",
    "content_discovery": "Discovery",
    "endpoint_discovery": "Discovery",
    "historical_discovery": "Discovery",
    "param_discovery": "Discovery",
    "manual_validation": "Discovery",
    "manual": "Discovery",
    "tls_assessment": "Discovery",
    "cms_assessment": "Discovery",
    "cloud_assessment": "Discovery",
    "smb_enum": "Discovery",
    "ad_enum": "Discovery",
    "cve_lookup": "Discovery",
    "exploit_search": "Discovery",
    # Vulnerability Scanning (T1595.002) is a Discovery technique; normalised
    # from the non-canonical "Vulnerability Exploitation".
    "vulnerability_scan": "Discovery",
    "vuln_scan": "Discovery",
    # --- Reconnaissance (TA0043, external) ---
    "recon": "Reconnaissance",
    "osint": "Reconnaissance",
    "subdomain": "Reconnaissance",
    "url_discovery": "Reconnaissance",
    # --- Initial Access (TA0001) ---
    # Exploiting a public-facing application (T1190); normalised from the
    # non-canonical "Exploitation".
    "web_exploit": "Initial Access",
    "exploitation": "Initial Access",
    "cve_exploitation": "Initial Access",
    "web_vulnerability": "Initial Access",
    "xss_testing": "Initial Access",
    "sqli_testing": "Initial Access",
    # RAMA WEB (Jev, T-8): capabilities of the browser-executed steps the
    # decision engine routes through the web_interaction category (T-6).
    # Verified canonical vs MITRE ATT&CK Enterprise v19 (2026-09-21); see
    # hades-tfm/wiki/nyxstrike/mapeo-paso-attck.md §10.
    # web-exploitation: driving the public-facing app via Jev (T1190).
    "web-exploitation": "Initial Access",
    # credential-form / valid-accounts: login with valid accounts (T1078).
    "credential-form": "Initial Access",
    "valid-accounts": "Initial Access",
    # --- Execution (TA0002) ---
    "payload": "Execution",
    "payload_generation": "Execution",
    "binary_analysis": "Execution",
    "binary_exploitation": "Execution",
    # command-injection via the web (DVWA /vulnerabilities/cmdi/): the target
    # runs the injected command -> Command and Scripting Interpreter (T1059).
    "command-injection": "Execution",
    # xss (reflected, via Jev): arbitrary JavaScript execution in the victim
    # browser. No dedicated XSS technique exists in ATT&CK v19; per the
    # catalog convention "arbitrary code execution -> Execution/T1059" we map
    # it to T1059 (sub-technique .007 JavaScript). Decided + documented, T-8.
    "xss": "Execution",
    # --- Credential Access (TA0006) ---
    "password": "Credential Access",
    "credential": "Credential Access",
    "hash": "Credential Access",
    "auth_assessment": "Credential Access",
    # --- Lateral Movement (TA0008) ---
    "post_exploitation": "Lateral Movement",
    "lateral": "Lateral Movement",
    # --- Privilege Escalation (TA0004) ---
    "escalation": "Privilege Escalation",
    "privesc": "Privilege Escalation",
    # --- Collection (TA0009) ---
    "forensics_analysis": "Collection",
    "forensics": "Collection",
    "steganography_analysis": "Collection",
    "steganography": "Collection",
}


# Capability -> MITRE ATT&CK technique id. Only mappings with a confident,
# verified technique (attack.mitre.org v19, cross-checked in
# hades-tfm wiki/nyxstrike/mapeo-paso-attck.md) are included. This is the
# "tactic -> technique" hop that lets an attack step correlate with a Wazuh
# alert *by technique* (Wazuh emits techniques, not just tactics). Grounded:
# capabilities absent here stay unlabelled at the technique level and must
# never be invented.
_CAPABILITY_TO_TECHNIQUE: Dict[str, str] = {
    # Network / software discovery
    "network_scan": "T1046",
    "service_enumeration": "T1046",
    "surface": "T1046",
    "web_fingerprint": "T1518",
    # File / directory / endpoint discovery
    "content_discovery": "T1083",
    "api_discovery": "T1083",
    "api_assessment": "T1083",
    "endpoint_discovery": "T1083",
    "param_discovery": "T1083",
    # Vulnerability scanning / exploitation
    "vulnerability_scan": "T1595.002",
    "vuln_scan": "T1595.002",
    "exploitation": "T1190",
    "web_exploit": "T1190",
    "cve_exploitation": "T1190",
    # RAMA WEB (Jev, T-8) — tactic -> technique hop for Wazuh correlation.
    # Verified canonical vs MITRE ATT&CK Enterprise v19 (2026-09-21); see
    # hades-tfm/wiki/nyxstrike/mapeo-paso-attck.md §10.
    "web-exploitation": "T1190",   # Exploit Public-Facing Application
    "credential-form": "T1078",    # Valid Accounts
    "valid-accounts": "T1078",     # Valid Accounts
    # Command and scripting interpreter (binaries / payloads)
    "binary_analysis": "T1059",
    "binary_exploitation": "T1059",
    "payload": "T1059",
    "payload_generation": "T1059",
    # T-8 web branch (see mapeo-paso-attck.md §10):
    "command-injection": "T1059",   # Command and Scripting Interpreter
    "xss": "T1059",                 # arbitrary JS execution (T1059.007 JavaScript)
    # Credential access
    "password": "T1003",
    "credential": "T1003",
    "hash": "T1003",
    "auth_assessment": "T1003",
    # Lateral movement / C2
    "post_exploitation": "T1021",
    # Privilege escalation
    "escalation": "T1548",
    "privesc": "T1548",
    # Account / SMB discovery (Windows AD)
    "ad_enum": "T1087",
    "smb_enum": "T1087",
    # Collection (forensics / steganography)
    "forensics_analysis": "T1005",
    "forensics": "T1005",
    "steganography_analysis": "T1005",
    "steganography": "T1005",
}


def _tactic_for_capabilities(capabilities: set) -> Optional[str]:
    """Map a set of tool capabilities to a single ATT&CK tactic.

    Grounded: only the catalog's own capability strings are used. If none of
    the capabilities map to a known tactic we return None rather than
    inventing one. Resolution order: (1) exact capability match, (2) a known
    key appearing as a substring of the capability name, (3) None.

    The map is restricted to the 14 canonical ATT&CK Enterprise tactics;
    ``_CAPABILITY_TO_TACTIC`` never contains a non-canonical value.
    """
    if not capabilities:
        return None
    # Deterministic: iterate capabilities in a stable order so a multi-capability
    # tool resolves to the same tactic regardless of set-iteration order (a
    # non-deterministic mapping would make a Wazuh correlation flaky).
    keys = sorted(str(cap).lower() for cap in capabilities)
    for key in keys:
        if key in _CAPABILITY_TO_TACTIC:
            return _CAPABILITY_TO_TACTIC[key]
    # A capability whose name contains a known keyword still maps.
    for key in keys:
        for known, tactic in _CAPABILITY_TO_TACTIC.items():
            if known in key:
                return tactic
    return None


def _technique_for_capabilities(capabilities: set) -> Optional[str]:
    """Map a set of tool capabilities to a single MITRE ATT&CK technique id.

    Grounded exactly like ``_tactic_for_capabilities``: capabilities absent
    from ``_CAPABILITY_TO_TECHNIQUE`` (and not a substring of a known key)
    return None instead of an invented technique id. Resolution order:
    (1) exact capability match, (2) known key as a substring of the capability
    name, (3) None.
    """
    if not capabilities:
        return None
    # Deterministic (see ``_tactic_for_capabilities``): stable order so a
    # multi-capability tool resolves to the same technique id every time.
    keys = sorted(str(cap).lower() for cap in capabilities)
    for key in keys:
        if key in _CAPABILITY_TO_TECHNIQUE:
            return _CAPABILITY_TO_TECHNIQUE[key]
    for key in keys:
        for known, technique in _CAPABILITY_TO_TECHNIQUE.items():
            if known in key:
                return technique
    return None


def _catalog_capabilities(decision_engine, tool: str) -> set:
    """Return the catalog capabilities for *tool*, empty if unknown."""
    try:
        spec = decision_engine.tool_catalog.get(tool)
    except Exception:
        return set()
    if spec is None:
        return set()
    caps = getattr(spec, "capabilities", None)
    return set(caps) if isinstance(caps, set) else set()


# ---------------------------------------------------------------------------
# Web-executor branch (T-7): Jev as a *branch of executor* in execute_step
# (plan-and-approve). NOT a new planner loop: the single injected executor is
# what calls web_run_goal in production; execute_step just selects the web
# branch when the chosen step is a web-interaction step and INTERPRETS the
# compressed SubgoalResult contract (status / verified / summary / extracted —
# T-2/T-3) instead of the plain stdout/stderr/return_code envelope.
#
# The route selection is a *capability TAG*, not a learned heuristic (design §1.4): a
# step is a web step when its tool is web_run_goal (T-6 category) or it carries
# an explicit web_interaction route tag. No over-engineered browser-vs-API
# routing model.
# ---------------------------------------------------------------------------

# Tool names that map to the web_interaction category (T-6 toolspec).
WEB_TOOL_NAMES = {"web_run_goal", "web_extract_surface"}
WEB_ROUTE_TAG = "web_interaction"

# Fallback routes handed to the planner when the browser cannot / must not
# continue (BLOCKED / BUDGET_EXCEEDED / out_of_scope). Grounded in existing
# NyxStrike capabilities (T-6 §1.2); never an invented route. Bare names so the
# set is a clean, membership-testable catalog of the alternative routes.
_WEB_FALLBACK_ROUTES = (
    "curl",
    "sqlmap",
    "API",
)

# Compressed-contract fields worth preserving through _trim_result so the
# planner reads status/verified (not just the HTTP-level success envelope).
_WEB_RESULT_FIELDS = (
    "web_status", "verified", "summary", "fallback",
    "run_id", "extracted", "budget", "blocked_reason",
)


def _web_fallback_message(reason) -> str:
    routes = " / ".join(_WEB_FALLBACK_ROUTES)
    why = reason or "run web bloqueado"
    return (
        f"Ruta alternativa (el navegador no pudo o no debe continuar): "
        f"{routes}. Motivo: {why}. No reintentar el navegador; "
        f"el planner decide la otra vía."
    )


def _is_web_interaction_step(step: Any) -> bool:
    """Return True if *step* is a web-interaction step (the T-6 route TAG).

    Grounded in the step's own tool name (web_run_goal) or an explicit
    ``web_interaction`` route tag in its parameters — NOT a learned heuristic
    (design §1.4). Deterministic and cheap so execute_step can branch on it.
    """
    if not isinstance(step, dict):
        return False
    tool = str(step.get("tool", "") or "").lower()
    if tool in WEB_TOOL_NAMES:
        return True
    params = step.get("parameters")
    if isinstance(params, dict):
        if str(params.get("route", "") or "").lower() == WEB_ROUTE_TAG:
            return True
        caps = params.get("capabilities")
        if isinstance(caps, (list, set, tuple)):
            return any(str(c).lower() == WEB_ROUTE_TAG for c in caps)
    return False


def _interpret_web_result(exec_result: Any) -> Dict[str, Any]:
    """Interpret the compressed SubgoalResult contract (T-2/T-3) that
    web_run_goal returns, independent of the HTTP-level success envelope.

    Contract §2.2 rules:
      (a) status=DONE does NOT imply success — the planner decides on
          ``verified`` independently; a DONE with verified != True is a
          "false DONE" and reads as a non-success.
      (b) BLOCKED / BUDGET_EXCEEDED / blocked_reason=out_of_scope -> the
          alternative route (curl/sqlmap/API) is signalled to the planner
          instead of retrying the browser.

    Returns a dict with: success (bool), web_status (str), verified
    (bool|None), summary (str), fallback (str|None).
    """
    if not isinstance(exec_result, dict):
        return {
            "success": False,
            "web_status": "FAILED",
            "verified": None,
            "summary": "",
            "fallback": _web_fallback_message("respuesta no válida del executor web"),
        }

    status = str(exec_result.get("status", "") or "").upper()
    verified = exec_result.get("verified")
    blocked_reason = exec_result.get("blocked_reason")

    needs_fallback = (
        status in ("BLOCKED", "BUDGET_EXCEEDED")
        or (isinstance(blocked_reason, str) and "out_of_scope" in blocked_reason.lower())
    )

    # Rule (a): success requires a DONE that the independent verifier
    # confirmed. A DONE with verified False/None (false-DONE) is a non-success.
    success = bool(status == "DONE" and verified is True)

    fallback = _web_fallback_message(blocked_reason or status) if needs_fallback else None

    return {
        "success": success,
        "web_status": status or "FAILED",
        "verified": verified,
        "summary": exec_result.get("summary", "") or "",
        "fallback": fallback,
        "run_id": exec_result.get("run_id") or None,
        "extracted": exec_result.get("extracted"),
        "budget": exec_result.get("budget"),
        "blocked_reason": blocked_reason or None,
    }


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class PlanAndApproveController:
    """Stateful driver of the plan-and-approve contract.

    Parameters
    ----------
    decision_engine:
        A decision engine exposing ``analyze_target`` / ``create_attack_chain``
        / ``tool_catalog`` (defaults to the shared singleton).
    session_flow:
        The ``session_flow`` module (or any object exposing create_session /
        load_session_any / update_session / append_run_log / append_event).
        Injected for testability.
    executor:
        ``executor(tool, params, session_id) -> dict`` that runs a single
        approved step. Defaults to the in-process registered-endpoint
        dispatcher. Injected/stubbed in tests so no real tool processes run.
    """

    def __init__(
        self,
        decision_engine: Optional[Any] = None,
        session_flow: Optional[Any] = None,
        executor: Optional[Callable[[str, Dict[str, Any], Optional[str]], Dict[str, Any]]] = None,
    ) -> None:
        if decision_engine is None:
            from backend.server_core.singletons import decision_engine as _de
            decision_engine = _de
        self.decision_engine = decision_engine

        if session_flow is None:
            import backend.server_core.session_flow as _sf
            session_flow = _sf
        self.session_flow = session_flow

        self.executor = executor or _default_step_executor()

    # -- persistence helpers -------------------------------------------------

    def _load(self, session_id: str) -> Optional[Dict[str, Any]]:
        loaded = self.session_flow.load_session_any(session_id)
        if not loaded:
            return None
        session_dict, _state = loaded
        return session_dict

    def _get_pa(self, session_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Return the plan-and-approve metadata block, creating it if absent."""
        meta = session_dict.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
            session_dict["metadata"] = meta
        pa = meta.get(PA_METADATA_KEY)
        if not isinstance(pa, dict):
            pa = {}
            meta[PA_METADATA_KEY] = pa
        return pa

    def _persist(self, session_dict: Dict[str, Any]) -> None:
        sid = session_dict.get("session_id")
        if not sid:
            return
        try:
            self.session_flow.update_session(sid, {"metadata": session_dict.get("metadata", {})})
        except Exception:
            logger.exception("plan_and_approve: failed to persist metadata for %s", sid)

    # -- contract: profile_target -------------------------------------------

    def profile_target(
        self,
        target: str,
        objective: str = "comprehensive",
        planner_mode: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build/refresh the TargetProfile for *target* and seed a chain.

        Returns the profile + a freshly built (but not yet executed)
        AttackChain, persisted into a plan-and-approve session. Re-calling
        with the same ``session_id`` refreshes the profile + chain.
        """
        start = time.time()
        if not target:
            return {"success": False, "error": "target is required", "return_code": 1}

        try:
            profile = self.decision_engine.analyze_target(target)
            chain = self.decision_engine.create_attack_chain(
                profile,
                objective,
                planner_mode=planner_mode,
                session_id=session_id,
            )
        except Exception as exc:
            logger.exception("plan_and_approve.profile_target failed")
            return {
                "success": False,
                "error": f"profile_target failed: {exc}",
                "return_code": 1,
                "timestamp": datetime.now().isoformat(),
            }

        profile_dict = profile.to_dict()
        chain_dict = _annotate_chain(chain.to_dict())

        # Create or refresh the session.
        if session_id:
            existing = self._load(session_id)
            if existing is None:
                # requested id does not exist -> fall back to a new session
                session_id = None

        if session_id is None:
            session_id = self.session_flow.create_session(
                target=target,
                steps=chain_dict.get("steps", []),
                source=PA_SOURCE,
                objective=objective,
                metadata={PA_METADATA_KEY: {
                    "profile": profile_dict,
                    "chain": chain_dict,
                    "objective": objective,
                    "planner_mode": planner_mode or "",
                    "current_step_index": 0,
                }},
            )["session_id"]
        else:
            existing = self._load(session_id) or {}
            pa = self._get_pa(existing)
            pa["profile"] = profile_dict
            pa["chain"] = chain_dict
            pa["objective"] = objective
            pa["planner_mode"] = planner_mode or ""
            pa["current_step_index"] = 0
            # reset runtime status fields on re-plan
            for s in chain_dict.get("steps", []):
                s["status"] = STATUS_PROPOSED
                s["result"] = None
            existing["metadata"] = {PA_METADATA_KEY: pa}
            self._persist(existing)

        result = {
            "success": True,
            "session_id": session_id,
            "target": target,
            "objective": objective,
            "planner_mode": planner_mode or "",
            "target_profile": profile_dict,
            "attack_chain": chain_dict,
            "chain_status": _chain_status(chain_dict),
            "timestamp": datetime.now().isoformat(),
        }
        return result

    # -- contract: propose_next_step ---------------------------------------

    def propose_next_step(
        self,
        session_id: str,
        objective: Optional[str] = None,
        planner_mode: Optional[str] = None,
        rerank: bool = False,
    ) -> Dict[str, Any]:
        """Return the next step to execute. NEVER executes anything.

        If ``rerank`` is True (e.g. the supervisor reorients), the remaining
        steps are re-ranked by the decision engine before proposing.

        T-17 (colocación "a"): the response also exposes a FINITE NUMBERED
        candidate set (``candidates``) — the decision engine's precision-first
        ranking as a Jev-style action space — plus ``selected_index``, the
        1-based index of ``next_step`` within it. The supervisor (Hades)
        answers with an index of the set, never free text. This is an
        additive change: the existing ``next_step`` contract is untouched and
        nothing is ever executed here.
        """
        session = self._load(session_id)
        if session is None:
            return {"success": False, "error": f"session {session_id} not found", "return_code": 1}

        pa = self._get_pa(session)
        chain = pa.get("chain")
        if not isinstance(chain, dict) or not chain.get("steps"):
            return {
                "success": False,
                "error": "no chain in session; call profile_target first",
                "return_code": 1,
            }

        if rerank and self._can_rerank(pa):
            chain = self._rerank(session, pa, objective, planner_mode)
            session["metadata"] = {PA_METADATA_KEY: pa}
            self._persist(session)

        # Walk to the next step that is not already executed/failed/skipped.
        steps = chain["steps"]
        nxt = None
        idx = pa.get("current_step_index", 0)
        for i in range(idx, len(steps)):
            if steps[i].get("status", STATUS_PROPOSED) in (STATUS_EXECUTED, STATUS_FAILED, STATUS_SKIPPED):
                continue
            nxt = steps[i]
            pa["current_step_index"] = i
            break

        # Indexed candidate set (finite, deterministic) for the supervisor.
        candidates = _index_candidates(
            pa.get("profile", {}),
            session.get("target", ""),
            pa.get("objective") or objective or "comprehensive",
            session_id,
            self.decision_engine,
        )
        selected_index = None
        if nxt is not None and candidates:
            for c in candidates:
                if c["tool"] == nxt.get("tool"):
                    selected_index = c["index"]
                    break

        if nxt is None:
            pa["current_step_index"] = len(steps)
            self._persist(session)
            return {
                "success": True,
                "session_id": session_id,
                "completed": True,
                "next_step": None,
                "candidates": [],
                "selected_index": None,
                "message": "all chain steps processed",
                "chain_status": _chain_status(chain),
                "timestamp": datetime.now().isoformat(),
            }

        nxt["status"] = STATUS_PROPOSED
        self._persist(session)

        return {
            "success": True,
            "session_id": session_id,
            "completed": False,
            "next_step": _step_public(nxt),
            "candidates": candidates,
            "selected_index": selected_index,
            "chain_status": _chain_status(chain),
            "timestamp": datetime.now().isoformat(),
        }

    def _can_rerank(self, pa: Dict[str, Any]) -> bool:
        profile = pa.get("profile")
        if not isinstance(profile, dict):
            return False
        return bool(pa.get("objective"))

    def _rerank(
        self,
        session: Dict[str, Any],
        pa: Dict[str, Any],
        objective: Optional[str],
        planner_mode: Optional[str],
    ) -> Dict[str, Any]:
        """Rebuild the chain (preserving executed results) from the profile."""
        profile_dict = pa.get("profile", {})
        profile = _profile_from_dict(profile_dict)
        if profile is None:
            return pa.get("chain", {})
        objective = objective or pa.get("objective") or "comprehensive"
        try:
            new_chain = self.decision_engine.create_attack_chain(
                profile,
                objective,
                planner_mode=planner_mode,
            )
        except Exception:
            logger.warning("plan_and_approve.rerank: chain rebuild failed; keeping old chain")
            return pa.get("chain", {})

        # Preserve executed/failed/skipped results on the matching tool steps.
        old_by_tool: Dict[str, Dict[str, Any]] = {}
        for s in pa.get("chain", {}).get("steps", []):
            if s.get("status") in (STATUS_EXECUTED, STATUS_FAILED, STATUS_SKIPPED):
                old_by_tool.setdefault(s.get("tool"), s)

        new_chain_dict = _annotate_chain(new_chain.to_dict())
        for s in new_chain_dict["steps"]:
            prev = old_by_tool.get(s.get("tool"))
            if prev and prev.get("status") in (STATUS_EXECUTED, STATUS_FAILED, STATUS_SKIPPED):
                s["status"] = prev["status"]
                s["result"] = prev.get("result")
        return new_chain_dict

    # -- contract: execute_step --------------------------------------------

    def execute_step(
        self,
        session_id: str,
        step_index: Optional[int] = None,
        tool: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute ONE approved step and record the result into the chain.

        ``step_index`` selects the step; if omitted, ``tool`` (with optional
        ``params``) is used to find the matching step. If neither matches an
        existing chain step, the (tool, params) pair is executed ad-hoc and
        appended as a new step so reoriented plans survive.
        """
        session = self._load(session_id)
        if session is None:
            return {"success": False, "error": f"session {session_id} not found", "return_code": 1}

        pa = self._get_pa(session)
        chain = pa.get("chain")
        if not isinstance(chain, dict):
            return {"success": False, "error": "no chain in session", "return_code": 1}
        steps = chain.get("steps", [])

        target = session.get("target", "")
        if not params and not tool:
            # no explicit override; we must pick a concrete step below
            pass

        # Resolve which step we are executing.
        chosen: Optional[Dict[str, Any]] = None
        if step_index is not None:
            if 0 <= step_index < len(steps):
                chosen = steps[step_index]
        elif tool:
            for s in steps:
                if s.get("tool") == tool:
                    chosen = s
                    break
            if chosen is None:
                # ad-hoc step (reorientation) -> build + append a new one
                chosen = _adhoc_step(tool, params or {"target": target}, target)
                steps.append(chosen)

        if chosen is None:
            # fall back to the current cursor step
            idx = pa.get("current_step_index", 0)
            if 0 <= idx < len(steps):
                chosen = steps[idx]

        if chosen is None:
            return {
                "success": False,
                "error": "no step to execute (chain empty or index out of range)",
                "return_code": 1,
                "timestamp": datetime.now().isoformat(),
            }

        # Merge any caller-provided params over the step's own params.
        run_params = dict(chosen.get("parameters") or {})
        if params:
            run_params.update(params)
        run_params.setdefault("target", target)
        run_params["session_id"] = session_id

        # Execute via the injected executor (stubbed in tests).
        try:
            exec_result = self.executor(tool or chosen.get("tool", ""), run_params, session_id)
        except Exception as exc:
            logger.exception("plan_and_approve.execute_step: executor raised")
            exec_result = {
                "success": False,
                "error": f"execution failed: {exc}",
                "stdout": "",
                "stderr": str(exc),
                "return_code": 1,
            }
        if not isinstance(exec_result, dict):
            exec_result = {"success": False, "stdout": "", "stderr": str(exec_result)}

        # T-7: web-executor branch (Jev / web_interaction route TAG).
        # When the chosen step is a web-interaction step, interpret the
        # compressed SubgoalResult contract (status/verified/summary/
        # extracted - T-2/T-3) instead of the plain stdout/stderr/
        # return_code envelope. A branch of executor, NOT a new planner
        # loop: the single injected executor is what calls web_run_goal
        # in production; here we only interpret its result and apply the
        # fallback policy (BLOCKED / BUDGET_EXCEEDED / out_of_scope ->
        # signal the alternative route to the planner, never retry the
        # browser).
        web_interp = (
            _interpret_web_result(exec_result)
            if _is_web_interaction_step(chosen)
            else None
        )
        succeeded = (
            bool(web_interp["success"])
            if web_interp is not None
            else bool(exec_result.get("success", False))
        )
        chosen["status"] = STATUS_EXECUTED if succeeded else STATUS_FAILED
        chosen["result"] = _trim_result(exec_result, web_interp)

        # Record the run log for the evidence chain (grounded, hashable).
        _append_run_log(self.session_flow, session_id, {
            "tool": chosen.get("tool", ""),
            "params": run_params,
            "success": succeeded,
            "stdout": exec_result.get("stdout", ""),
            "stderr": exec_result.get("stderr", ""),
            "return_code": exec_result.get("return_code", 0),
            "timestamp": datetime.now().isoformat(),
        })

        # Auto-advance the cursor past the executed step.
        cursor = pa.get("current_step_index", 0)
        cursor = min(cursor, len(steps) - 1) if steps else cursor
        pa["current_step_index"] = min(cursor + 1, len(steps))

        self._persist(session)

        result = _trim_result(exec_result, web_interp)
        return {
            "success": succeeded,
            "session_id": session_id,
            "executed_step": _step_public(chosen),
            "result": result,
            **({"fallback": result["fallback"]} if "fallback" in result else {}),
            "chain_status": _chain_status(chain),
            "timestamp": datetime.now().isoformat(),
        }

    # -- contract: update_chain --------------------------------------------

    def update_chain(
        self,
        session_id: str,
        action: str = "add",
        step: Optional[Dict[str, Any]] = None,
        step_index: Optional[int] = None,
        tool: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        new_objective: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mutate the chain: add / remove / reorder / skip a step.

        Supported actions:
            add    — append (or insert at ``step_index``) a new step.
            remove — drop the step at ``step_index``.
            skip   — mark the step at ``step_index`` as skipped.
            reorder— move the step at ``from_index`` to ``step_index``.
        A ``new_objective`` re-plans the whole chain (preserving executed
        results) — this is how the supervisor reorients.
        """
        session = self._load(session_id)
        if session is None:
            return {"success": False, "error": f"session {session_id} not found", "return_code": 1}

        pa = self._get_pa(session)
        chain = pa.get("chain")
        if not isinstance(chain, dict):
            return {"success": False, "error": "no chain in session", "return_code": 1}
        steps = chain.get("steps", [])

        # Re-plan branch.
        if new_objective:
            pa["objective"] = new_objective
            rebuilt = self._rerank(session, pa, new_objective, None)
            if isinstance(rebuilt, dict):
                chain = rebuilt
                pa["chain"] = chain
                steps = chain.get("steps", [])

        action = (action or "add").lower()
        if action in ("add", "append", "insert"):
            new_step = _new_step(step, tool, parameters, session.get("target", ""))
            if new_step is None:
                return {
                    "success": False,
                    "error": "update_chain add: need 'step' or 'tool'",
                    "return_code": 1,
                }
            if step_index is not None and 0 <= step_index < len(steps):
                steps.insert(step_index, new_step)
            else:
                steps.append(new_step)
        elif action in ("remove", "delete"):
            if step_index is None or not (0 <= step_index < len(steps)):
                return {"success": False, "error": "update_chain remove: invalid step_index", "return_code": 1}
            steps.pop(step_index)
        elif action in ("skip", "mark"):
            if step_index is None or not (0 <= step_index < len(steps)):
                return {"success": False, "error": "update_chain skip: invalid step_index", "return_code": 1}
            steps[step_index]["status"] = STATUS_SKIPPED
            steps[step_index]["result"] = None
        elif action in ("reorder", "move"):
            from_idx = step_index if isinstance(step_index, int) else 0
            to_idx = step_index if isinstance(step_index, int) else 0
            if isinstance(parameters, dict):
                if "from_index" in parameters:
                    from_idx = int(parameters.get("from_index", from_idx))
                if "to_index" in parameters:
                    to_idx = int(parameters.get("to_index", to_idx))
            if not (0 <= from_idx < len(steps)):
                return {"success": False, "error": "update_chain reorder: invalid from index", "return_code": 1}
            if not (0 <= to_idx < len(steps)):
                return {"success": False, "error": "update_chain reorder: invalid to index", "return_code": 1}
            moved = steps.pop(from_idx)
            steps.insert(to_idx, moved)
        else:
            return {"success": False, "error": f"unknown update_chain action: {action}", "return_code": 1}

        # Renumber current index defensively.
        pa["current_step_index"] = max(0, min(pa.get("current_step_index", 0), len(steps)))
        self._persist(session)

        return {
            "success": True,
            "session_id": session_id,
            "action": action,
            "chain_status": _chain_status(chain),
            "steps": [_step_public(s) for s in steps],
            "timestamp": datetime.now().isoformat(),
        }

    # -- contract: chain_report --------------------------------------------

    def chain_report(
        self,
        session_id: str,
        include_attack: bool = True,
    ) -> Dict[str, Any]:
        """Assemble a structured report of the chain's progress.

        When ``include_attack`` is True, each executed/failed step is tagged
        with an ATT&CK tactic derived from the tool catalog's capabilities
        (grounded; missing capabilities => tactic omitted, never invented).
        """
        session = self._load(session_id)
        if session is None:
            return {"success": False, "error": f"session {session_id} not found", "return_code": 1}

        pa = self._get_pa(session)
        chain = pa.get("chain")
        profile = pa.get("profile")
        if not isinstance(chain, dict):
            return {"success": False, "error": "no chain in session", "return_code": 1}

        executed = [s for s in chain.get("steps", []) if s.get("status") == STATUS_EXECUTED]
        failed = [s for s in chain.get("steps", []) if s.get("status") == STATUS_FAILED]
        skipped = [s for s in chain.get("steps", []) if s.get("status") == STATUS_SKIPPED]
        pending = [
            s for s in chain.get("steps", [])
            if s.get("status") in (STATUS_PROPOSED, STATUS_APPROVED, None)
        ]

        report_steps: List[Dict[str, Any]] = []
        for s in chain.get("steps", []):
            pub = _step_public(s)
            if include_attack:
                caps = _catalog_capabilities(self.decision_engine, s.get("tool", ""))
                tactic = _tactic_for_capabilities(caps)
                if tactic:
                    pub["attack_tactic"] = tactic
                # tactic -> technique hop (grounded; absent when unmapped).
                technique = _technique_for_capabilities(caps)
                if technique:
                    pub["mitre_technique"] = technique
            report_steps.append(pub)

        progress = _chain_status(chain)
        report = {
            "success": True,
            "session_id": session_id,
            "target": session.get("target", ""),
            "objective": pa.get("objective", ""),
            "target_profile": profile,
            "progress": progress,
            "counts": {
                "total": len(chain.get("steps", [])),
                "executed": len(executed),
                "failed": len(failed),
                "skipped": len(skipped),
                "pending": len(pending),
            },
            "steps": report_steps,
            "att&ck": True if include_attack else False,
            "timestamp": datetime.now().isoformat(),
        }
        return report


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------

def default_controller(**kwargs) -> PlanAndApproveController:
    """Factory used by the HTTP + MCP layers."""
    return PlanAndApproveController(**kwargs)


def _default_step_executor() -> Callable[[str, Dict[str, Any], Optional[str]], Dict[str, Any]]:
    """In-process dispatcher mirroring the decision-engine smart-scan path."""

    def _executor(tool: str, params: Dict[str, Any], session_id: Optional[str]) -> Dict[str, Any]:
        from flask import current_app, LocalProxy

        app = current_app._get_current_object() if isinstance(current_app, LocalProxy) else current_app
        from backend.server_api.ops.vulnerability_intelligence import (
            execute_tool_via_registered_endpoint,
        )

        result = execute_tool_via_registered_endpoint(app, tool, params)
        if not isinstance(result, dict):
            return {"success": False, "stdout": "", "stderr": str(result), "return_code": 1}
        return result

    return _executor


def _annotate_chain(chain_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add runtime fields (status, result) to each step of a chain dict."""
    out = dict(chain_dict)
    steps = []
    for s in chain_dict.get("steps", []):
        s2 = dict(s)
        s2.setdefault("status", STATUS_PROPOSED)
        s2["result"] = None
        steps.append(s2)
    out["steps"] = steps
    return out


def _index_candidates(
    profile_dict: Dict[str, Any],
    target: str,
    objective: str,
    session_id: Optional[str],
    decision_engine: Any,
) -> List[Dict[str, Any]]:
    """Build the finite indexed candidate set exposed by propose_next_step.

    This is the "colocación (a)" of the TFM routing layer (ADR
    ``adr-router-decision-indexado``): the decision engine's precision-first
    ranking becomes a Jev-style ``action_space`` — a finite, numbered set the
    supervisor (Hades) answers with an INDEX, never free text.

    Every candidate carries: ``index`` (1-based), ``tool``,
    ``params_sugeridos`` (via the engine's ``optimize_parameters``, internal
    ``_*`` metadata stripped), ``confidence`` (calibrated from the engine's
    effective score and the margin against the top-ranked candidate — the
    ``classify_intent`` 3-level pattern applied to the winner: clear winner
    -> 1.0, narrow band around the top -> 0.75, tie / far from the top ->
    0.5), ``selection_reason`` (``explain_selection_reason``),
    ``capabilities`` and ``tactic`` (grounded in the catalog, never invented).

    The set is finite (bounded by ``MAX_INDEXED_CANDIDATES``), ordered by
    confidence (effective_score descending, stable on ties so the engine's
    ranking order breaks them), and deterministic: same input -> same tools,
    same order, same confidences.
    """
    if not profile_dict or not hasattr(decision_engine, "select_optimal_tools"):
        return []
    objective = objective or "comprehensive"
    try:
        profile = _profile_from_dict(profile_dict)
        if profile is None:
            return []
        session_penalties = (
            decision_engine._session_failure_penalties(session_id)
            if hasattr(decision_engine, "_session_failure_penalties")
            else {}
        )
        context_key = (
            decision_engine._build_context_key(profile, objective)
            if hasattr(decision_engine, "_build_context_key")
            else None
        )
        ranked: List[str] = list(dict.fromkeys(
            decision_engine.select_optimal_tools(
                profile, objective, session_id=session_id
            ) or []
        ))
        if not ranked:
            return []
        scores = {
            tool: decision_engine._effective_score(
                tool, profile.target_type.value, context_key, session_penalties
            )
            for tool in ranked
        }
        # Order the action space by confidence (effective_score descending).
        # ``list.sort`` is stable, so exact ties keep the engine's ranking
        # order — same input therefore always yields the same set and order.
        ranked.sort(key=lambda tool: scores[tool], reverse=True)
        ranked = ranked[:MAX_INDEXED_CANDIDATES]
        top_score = scores[ranked[0]]
        catalog = getattr(decision_engine, "tool_catalog", {}) or {}
        from backend.server_core.intelligence.tool_catalog import (
            objective_alias,
            required_capabilities,
        )
        from backend.server_core.intelligence.tool_scoring import (
            explain_selection_reason,
        )

        norm_obj = objective_alias(objective)
        required_caps = required_capabilities(profile.target_type.value, norm_obj)
        selected_caps: set = set()
        out: List[Dict[str, Any]] = []
        for i, tool in enumerate(ranked):
            score = scores[tool]
            # classify_intent calibration applied to the margin against the
            # top-ranked candidate: the winner is a clear choice (1.0); a
            # candidate within the narrow band of the top (ties included —
            # a tie with the leader is a strong alternative, not a
            # low-signal guess) is 0.75; anything further from the top is
            # low-signal (0.5). Because scores are sorted descending, the
            # 0.75 band is contiguous, so confidences are monotone
            # non-increasing by construction.
            if i == 0:
                confidence = 1.0
            else:
                margin = top_score - score
                confidence = 0.75 if margin <= 0.05 else 0.5
            spec = catalog.get(tool)
            caps = set(spec.capabilities) if spec else set()
            reason = explain_selection_reason(
                tool=tool,
                profile=profile,
                objective=norm_obj,
                catalog=catalog,
                required=required_caps,
                effective_score=score,
                selected_capabilities=selected_caps,
            )
            params = (
                decision_engine.optimize_parameters(
                    tool, profile, {"objective": objective, "target_type": profile.target_type.value}
                )
                if hasattr(decision_engine, "optimize_parameters")
                else {}
            )
            if not isinstance(params, dict):
                params = {}
            params = {
                k: v for k, v in params.items() if not (isinstance(k, str) and k.startswith("_"))
            }
            out.append(
                {
                    "index": i + 1,
                    "tool": tool,
                    "params_sugeridos": params,
                    "confidence": confidence,
                    "effective_score": score,
                    "selection_reason": reason,
                    "capabilities": sorted(caps),
                    "tactic": _tactic_for_capabilities(caps),
                }
            )
            selected_caps.update(caps)
        return out
    except Exception:
        logger.exception("plan_and_approve.index_candidates failed; returning empty set")
        return []


def _step_public(step: Dict[str, Any]) -> Dict[str, Any]:
    """Public projection of a step for proposal/report."""
    return {
        "tool": step.get("tool"),
        "parameters": step.get("parameters", {}),
        "expected_outcome": step.get("expected_outcome", ""),
        "success_probability": step.get("success_probability", 0.0),
        "execution_time_estimate": step.get("execution_time_estimate", 0),
        "selection_reason": step.get("selection_reason", {}),
        "status": step.get("status", STATUS_PROPOSED),
        "result": _trim_result(step.get("result")) if step.get("result") else None,
    }


def _new_step(
    step: Optional[Dict[str, Any]],
    tool: Optional[str],
    parameters: Optional[Dict[str, Any]],
    target: str,
) -> Optional[Dict[str, Any]]:
    """Build a chain step from a full dict or (tool, params)."""
    if isinstance(step, dict) and step:
        s = dict(step)
        s.setdefault("tool", tool or "unknown")
        s.setdefault("parameters", parameters or {})
        s.setdefault("expected_outcome", "")
        s.setdefault("success_probability", 0.5)
        s.setdefault("execution_time_estimate", 60)
        s.setdefault("selection_reason", {})
        s["status"] = STATUS_PROPOSED
        s["result"] = None
        return s
    if tool:
        return {
            "tool": tool,
            "parameters": parameters or {},
            "expected_outcome": "",
            "success_probability": 0.5,
            "execution_time_estimate": 60,
            "selection_reason": {"reason": "supervisor-injected step"},
            "status": STATUS_PROPOSED,
            "result": None,
        }
    return None


def _adhoc_step(tool: str, params: Dict[str, Any], target: str) -> Dict[str, Any]:
    return {
        "tool": tool,
        "parameters": params,
        "expected_outcome": "",
        "success_probability": 0.5,
        "execution_time_estimate": 60,
        "selection_reason": {"reason": "reoriented ad-hoc step"},
        "status": STATUS_EXECUTED,
        "result": None,
    }


def _chain_status(chain: Dict[str, Any]) -> Dict[str, Any]:
    steps = chain.get("steps", [])
    total = len(steps)
    executed = sum(1 for s in steps if s.get("status") == STATUS_EXECUTED)
    failed = sum(1 for s in steps if s.get("status") == STATUS_FAILED)
    skipped = sum(1 for s in steps if s.get("status") == STATUS_SKIPPED)
    processed = executed + failed + skipped
    done = processed == total and total > 0
    return {
        "total": total,
        "executed": executed,
        "failed": failed,
        "skipped": skipped,
        "processed": processed,
        "completed": done,
    }


def _trim_result(result: Dict[str, Any], web_interp: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Trim an execution result to a storable projection.

    When *web_interp* is provided (the T-7 web-executor branch), the
    compressed-contract fields (web_status / verified / summary /
    extracted / budget / run_id / blocked_reason / fallback) are
    preserved through the projection so the planner reads them back off
    the chain step, not just the HTTP-level success envelope. The full
    payload still lives in the session run_log.
    """
    if not isinstance(result, dict):
        return {"success": False, "stdout": "", "stderr": str(result), "return_code": 1}
    out = {}
    for key in ("success", "return_code", "timed_out", "partial_results", "execution_time", "timestamp"):
        if key in result:
            out[key] = result[key]
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    # Keep bounded; the full stdout lives in the session run_log.
    if isinstance(stdout, str):
        out["stdout"] = stdout[:8000]
    if isinstance(stderr, str):
        out["stderr"] = stderr[:4000]
    for key in ("error", "command"):
        if key in result:
            out[key] = result[key]
    # T-7: preserve the compressed-contract web fields through the projection.
    # Either they arrive via *web_interp* (execution-time interpretation) or the
    # input is already a web-trimmed projection being re-projected (e.g.
    # _step_public) — carry whichever source is present so status/verified/
    # summary/extracted/budget/fallback survive to the chain step the planner
    # reads. A plain (non-web) envelope has none of these keys.
    web_source = web_interp if web_interp is not None else (
        result if any(k in result for k in _WEB_RESULT_FIELDS) else None
    )
    if web_source:
        for key in _WEB_RESULT_FIELDS:
            if key in web_source and web_source[key] is not None:
                out[key] = web_source[key]
        if web_source.get("fallback"):
            out["fallback"] = web_source["fallback"]
    return out


def _profile_from_dict(profile_dict: Dict[str, Any]) -> Optional[TargetProfile]:
    """Reconstruct a TargetProfile from a serialised profile dict."""
    from backend.server_core.target_types import TargetType, TechnologyStack

    try:
        profile = TargetProfile(target=profile_dict.get("target"))
        ttype = profile_dict.get("target_type")
        try:
            profile.target_type = TargetType(ttype) if ttype else TargetType.UNKNOWN
        except ValueError:
            profile.target_type = TargetType.UNKNOWN
        profile.ip_addresses = profile_dict.get("ip_addresses", []) or []
        profile.technologies = [
            TechnologyStack(t) if isinstance(t, str) else t
            for t in profile_dict.get("technologies", [])
        ]
        profile.cms_type = profile_dict.get("cms_type")
        profile.cloud_provider = profile_dict.get("cloud_provider")
        profile.attack_surface_score = float(profile_dict.get("attack_surface_score", 0.0))
        profile.risk_level = profile_dict.get("risk_level", "unknown")
        profile.confidence_score = float(profile_dict.get("confidence_score", 0.0))
        return profile
    except Exception:
        logger.warning("plan_and_approve: failed to rebuild profile from dict")
        return None


def _append_run_log(session_flow: Any, session_id: str, entry: Dict[str, Any]) -> None:
    try:
        session_flow.append_run_log(session_id, entry)
    except Exception:
        logger.debug("plan_and_approve: append_run_log failed for %s", session_id, exc_info=True)
