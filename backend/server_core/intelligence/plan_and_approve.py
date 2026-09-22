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

import ipaddress
import logging
import re
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
# Post-execution result categorizer (colocación "d" — ADR router-decision
# indexado §3(d)).
#
# Every executed step yields an envelope of the form
#   {stdout, stderr, return_code, success, timed_out, partial_results, ...}
# (see enhanced_command_executor / _trim_result). Before that result goes back
# to the LLM supervisor (Hades) we attach ONE actionable label so the planner
# reads the *already categorised* fact (cheaper context, cheaper decision):
#
#   open_ports / services_enumerated / creds_found / vuln_confirmed /
#   empty / error / blocked / unlabeled
#
# Grounding rules (the whole point of "d"):
#   * DETERMINISTIC over the trimmed stdout/stderr/return_code — same input,
#     same label, no model in the loop (level 0 of the hybrid cascade).
#   * NEVER invent a label: an unrecognized capability/output is "unlabeled".
#   * The label is ADDED to — never substituted for — the trimmed stdout, so
#     the LLM always still sees the raw signal (the label must not hide it).
#   * It feeds chain_report (tactic/technique hop) and the Wazuh correlation
#     surface (T-11) via the same step dict.
#
# Design decision (Al3xar 2026-09-22 comment on this card): the *optional*
# level-1 fallback is a single Jev call, kept light, fused with the T-17
# decision call when possible — it is NOT a local model. Crucially the ADR
# (T-16) keeps Jev OFF the production dependency path (closed API + recon
# egress to a third party), and the acceptance criteria here require a
# deterministic, same-input-same-label guarantee on fixtures. So the shipped
# core is the deterministic level-0 classifier (below); the model/Jev fallback
# is an OPT-IN, injectable hook on the controller that only ever *overrides*
# an "unlabeled" verdict with a label the model itself grounds — it can never
# fabricate one, and it is a no-op unless explicitly wired. That preserves the
# deterministic contract while leaving the door open for the T-17/T-24 fusion.
# ---------------------------------------------------------------------------

RESULT_CATEGORIES: tuple = (
    "open_ports",
    "services_enumerated",
    "creds_found",
    "vuln_confirmed",
    "empty",
    "error",
    "blocked",
    "unlabeled",
)

# Phrases that mark a HARD stop in the output itself (the run was refused or
# halted, not a plain tool failure). Checked before success/error so a
# "blocked by policy" run is labelled "blocked", not "error".
_BLOCKED_MARKERS: tuple = (
    "out_of_scope",
    "out of scope",
    "budget_exceeded",
    "budget exceeded",
    "scope violation",
    "forbidden by policy",
    "blocked by policy",
    "not in scope",
    "exceeds budget",
)

# Credential-success signals. Kept high-specificity so a generic "password"
# word in help text does not fire: an account must be paired with a success
# phrase, OR a full credential line (user:pass) must be present.
_CRED_SUCCESS_MARKERS: tuple = (
    "successfully",
    "login successful",
    "password for",
    "password is",
    "valid credentials",
    "accepted",
)
_CRED_LINE_RE = re.compile(r"\b[\w.@+-]+:([\w!@#$%^&*-]{3,})\b")

# Vulnerability-confirmation signals: a CVE id, or a tool naming a confirmed
# finding. "vulnerable" alone is too broad; we require a finding keyword.
_VULN_MARKERS: tuple = (
    "vulnerabilit",   # vulnerability / vulnerabilities (es + en)
    "cve-",
    "exploit",
    "injection",
    "xss",
    "sqlmap",
    "found a",
    "detected",
    "is vulnerable",
)

# Service-enumeration signals (beyond the open-port line): a service/version
# probe result.
_SERVICE_MARKERS: tuple = (
    "service",
    "version",
    "software",
    "fingerprint",
    "running on",
    "open port",
    "port scan",
)

# Open-port line: nmap / rustscan / masscan "PORT <n>/<proto> ... open".
_OPEN_PORT_RE = re.compile(r"\b\d{1,5}/(tcp|udp|sctp)\b.*\bopen\b", re.IGNORECASE)
# An explicit "N open ports" summary line.
_OPEN_PORTS_SUMMARY_RE = re.compile(r"\bopen ports?\b", re.IGNORECASE)


def _looks_blocked(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _BLOCKED_MARKERS)


def _looks_like_error(result: Dict[str, Any]) -> bool:
    """Hard-failure detection, grounded in the executor's own envelope."""
    if result.get("success") is False:
        return True
    try:
        rc = int(result.get("return_code", 0) or 0)
    except (TypeError, ValueError):
        rc = 0
    if rc < 0:
        return True  # -1 is the executor's "exception" code, not "non-zero"
    if result.get("timed_out"):
        return True
    return False


def _is_substantive(stdout: str, stderr: str) -> bool:
    """True when there is real output to categorise (not a bare banner)."""
    out = (stdout or "").strip()
    err = (stderr or "").strip()
    if out or err:
        return True
    return False


def _classify_deterministic(tool: str, result: Dict[str, Any]) -> str:
    """Deterministic level-0 categorizer. Same (tool, result) -> same label."""
    tool_l = (tool or "").lower()
    stdout = str(result.get("stdout", "") or "")
    stderr = str(result.get("stderr", "") or "")
    text = f"{stdout}\n{stderr}"
    low = text.lower()

    # 1) Hard stop / policy block wins over everything (a blocked run is not
    #    a tool error, and the planner must see it as "blocked").
    if _looks_blocked(text) or _looks_blocked(str(result.get("error", "") or "")):
        return "blocked"

    # 2) Credentials (highest value signal): a credential-brute tool that
    #    reports a login, or any full user:pass credential line.
    is_cracker = tool_l in (
        "hydra", "medusa", "mkcert", "crowbar", "ncrack", "john", "hashcat",
    ) or "hydra" in tool_l or "crack" in tool_l or "brute" in tool_l
    if is_cracker and any(m in low for m in _CRED_SUCCESS_MARKERS):
        return "creds_found"
    if _CRED_LINE_RE.search(stdout):
        # A literal credential line anywhere -> creds_found (grounded).
        return "creds_found"

    # 3) Vulnerability confirmation: a CVE id or a named finding.
    if any(m in low for m in _VULN_MARKERS):
        return "vuln_confirmed"

    # 4) Open ports: a PORT n/proto open line, or an "open ports" summary.
    if _OPEN_PORT_RE.search(stdout) or _OPEN_PORTS_SUMMARY_RE.search(low):
        return "open_ports"

    # 5) Service enumeration: service/version fingerprint output.
    if any(m in low for m in _SERVICE_MARKERS):
        return "services_enumerated"

    # 6) Failure / error / timeout (no positive signal above).
    if _looks_like_error(result) or _looks_blocked(stderr):
        return "error"

    # 7) Empty: a clean run that produced nothing to act on.
    if not _is_substantive(stdout, stderr):
        return "empty"

    # 8) Nothing recognised -> honest "unlabeled" (grounded; never invented).
    return "unlabeled"


def _classify_with_model(tool: str, result: Dict[str, Any], classifier) -> str:
    """Opt-in level-1 model/Jev fallback.

    ``classifier(tool, trimmed_result_dict) -> str`` is expected to return one
    of RESULT_CATEGORIES (case-insensitive) or "" / None when it cannot decide.
    The returned label is only accepted if it is a KNOWN category and it is
    not "unlabeled" (the model may override an "unlabeled" guess but never
    fabricate a category that isn't in RESULT_CATEGORIES; anything else falls
    back to "unlabeled"). No exception may escape — a model failure degrades
    to "unlabeled", never to a crash.
    """
    if classifier is None:
        return "unlabeled"
    try:
        label = classifier(tool, result)
    except Exception as exc:  # noqa: BLE001 - model hook must never raise
        logger.warning("result categorizer model hook failed for %r: %s", tool, exc)
        return "unlabeled"
    if not isinstance(label, str):
        return "unlabeled"
    label = label.strip().lower()
    if label in RESULT_CATEGORIES and label != "unlabeled":
        return label
    return "unlabeled"


def categorize_result(
    tool: str,
    result: Dict[str, Any],
    classifier: Optional[Callable[[str, Dict[str, Any]], str]] = None,
) -> str:
    """Label an executed step's result with ONE actionable category.

    Deterministic level-0 first. If the deterministic pass returns "unlabeled"
    AND a ``classifier`` (model / Jev hook) is supplied, a single model call may
    override it (level-1). A non-"unlabeled" deterministic verdict is final —
    the model is never allowed to fight a grounded decision.

    Returns a member of RESULT_CATEGORIES. Never raises.
    """
    if not isinstance(result, dict):
        return "unlabeled"
    label = _classify_deterministic(tool, result)
    if label != "unlabeled" or classifier is None:
        return label
    return _classify_with_model(tool, result, classifier)


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

        # T-19: optional level-1 result-classifier hook (model / Jev call,
        # light — at most one categorisation per result, fusible with the
        # T-17 decision call). Default None => the deterministic level-0
        # categorizer alone decides (100% offline, deterministic). The hook
        # may only override an "unlabeled" verdict; it can never fabricate a
        # category (see categorize_result / _classify_with_model).
        self.result_classifier = None

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

    # -- T-18: pre-execution gate configuration ----------------------------

    def configure_gate(
        self,
        session_id: str,
        scope_hosts: Optional[List[str]] = None,
        max_executions: Optional[int] = None,
        max_seconds: Optional[float] = None,
        proposed_tools: Optional[List[str]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """Enable the pre-execution gate for *session_id* (per-session config).

        Grounded in the ADR (colocación "b"): the gate validates every
        tool-call against (1) the proposed set / catalog, (2) the host scope
        allowlist, (3) duplicate-suppression, and (4) the campaign budget.
        ``proposed_tools`` extends the gate's accepted id set beyond the
        current chain candidates (e.g. tools not in the static catalog, such
        as the web ``web_run_goal`` or a custom ``hydra``). The gate is OFF
        by default; this call opts a session in.
        """
        session = self._load(session_id)
        if session is None:
            return {"success": False, "error": f"session {session_id} not found", "return_code": 1}
        pa = self._get_pa(session)
        pa["gate_config"] = {
            "enabled": bool(enabled),
            "scope_hosts": list(scope_hosts) if scope_hosts else [],
            "max_executions": max_executions,
            "max_seconds": max_seconds,
            "proposed_tools": list(proposed_tools) if proposed_tools else [],
        }
        self._persist(session)
        return {
            "success": True,
            "session_id": session_id,
            "gate_config": pa["gate_config"],
            "timestamp": datetime.now().isoformat(),
        }

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
        gate_chain_snapshot: Optional[List[Dict[str, Any]]] = None
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
                # Capture the gate snapshot BEFORE the append: the membership
                # check must validate against the chain the supervisor was
                # actually offered (its last known state), not against a step
                # invented by this very call (see T-18 gate below).
                gate_chain_snapshot = [dict(s) for s in steps if isinstance(s, dict)]
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

        # T-18 (colocación "b"): pre-execution GATE. Applies the Jev
        # discipline to EVERY tool-call before the executor is reached:
        # membership (choice in proposed set / catalog), host scope allowlist,
        # duplicate suppression, and campaign budget. A rejection is returned
        # to the planner WITHOUT executing and leaves an AUDITABLE run_log
        # entry. Off by default (ADR §T-23).
        gate_config = pa.get("gate_config")
        if isinstance(gate_config, dict) and gate_config.get("enabled"):
            step_tool = tool or chosen.get("tool", "")
            gate = self._run_gate(
                session,
                pa,
                step_index,
                step_tool,
                run_params,
                chain_snapshot=gate_chain_snapshot,
            )
            if gate is not None:
                return gate

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

        # T-19 (colocación "d"): post-execution RESULT CATEGORIZER. Attach ONE
        # actionable label (open_ports / services_enumerated / creds_found /
        # vuln_confirmed / empty / error / blocked / unlabeled) so the LLM
        # supervisor reads the already-categorised fact. Deterministic level-0
        # over the trimmed signal; the opt-in model/Jev hook may only override
        # an "unlabeled" verdict. The label is ADDED to, never substituted
        # for, the trimmed stdout — raw signal is never hidden.
        cat_input = exec_result
        if web_interp is not None:
            # The web branch speaks the compressed SubgoalResult contract
            # (summary/blocked_reason, not stdout/stderr); feed those texts to
            # the same deterministic pass so BLOCKED/BUDGET/out_of_scope read
            # as "blocked" and a finding named in the summary reads as such.
            cat_input = {
                "success": bool(web_interp.get("success")),
                "stdout": str(web_interp.get("summary") or ""),
                "stderr": str(web_interp.get("blocked_reason") or ""),
                "return_code": 0,
                "timed_out": False,
            }
        result_category = categorize_result(
            tool or chosen.get("tool", ""),
            cat_input,
            classifier=self.result_classifier,
        )
        chosen["result_category"] = result_category
        # Attach the label to the stored result projection as well, so every
        # reader of the step (chain_report / Wazuh correlation T-11) sees the
        # category next to the trimmed stdout.
        stored_result = chosen.get("result")
        if isinstance(stored_result, dict):
            stored_result["result_category"] = result_category

        # Record the run log for the evidence chain (grounded, hashable).
        _append_run_log(self.session_flow, session_id, {
            "tool": chosen.get("tool", ""),
            "params": run_params,
            "success": succeeded,
            "stdout": exec_result.get("stdout", ""),
            "stderr": exec_result.get("stderr", ""),
            "return_code": exec_result.get("return_code", 0),
            "result_category": result_category,
            "timestamp": _now_iso(),
        })

        # Auto-advance the cursor past the executed step.
        cursor = pa.get("current_step_index", 0)
        cursor = min(cursor, len(steps) - 1) if steps else cursor
        pa["current_step_index"] = min(cursor + 1, len(steps))

        self._persist(session)

        result = _trim_result(exec_result, web_interp)
        # T-19: the label travels in the result dict the LLM reads (kept
        # alongside the trimmed stdout — it annotates, never replaces).
        result["result_category"] = result_category
        return {
            "success": succeeded,
            "session_id": session_id,
            # T-19: the actionable category of this run's result travels with
            # the response so the LLM supervisor decides off the label + the
            # trimmed stdout (label alone is never a substitute for the signal).
            "result_category": result_category,
            "executed_step": _step_public(chosen),
            "result": result,
            **({"fallback": result["fallback"]} if "fallback" in result else {}),
            "chain_status": _chain_status(chain),
            "timestamp": datetime.now().isoformat(),
        }

    # -- T-18: pre-execution gate (colocación "b") --------------------------

    def _run_gate(
        self,
        session: Dict[str, Any],
        pa: Dict[str, Any],
        step_index: Optional[int],
        tool: str,
        run_params: Dict[str, Any],
        chain_snapshot: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Enforce the pre-execution GATE (ADR router-decision §3(b)).

        Applies the Jev decision discipline to EVERY tool-call before the
        executor is reached. Returns a planner-facing rejection (BLOCKED) when
        the call is denied, or ``None`` when the call may proceed. Check order
        mirrors the gate's contract:

        1. **membership** — the chosen tool must belong to the proposed set
           (chain candidates + ``proposed_tools`` opt-in, T-17) or the valid
           catalog; analog of Jev's ``validate_choice`` (``choice in ids``).
        2. **scope** — the host must be inside the session allowlist
           (``scope_hosts``); generalises T-5's web-only allowlist to every
           tool. A host the session itself was profiled against is
           implicitly in scope (anchor).
        3. **duplicate suppression / phase order** — a tool whose most recent
           recorded run FAILED is dampened by
           ``_session_failure_penalties`` (factor 0.2); the gate turns that
           dampening into a hard rejection when the supervisor repeats it
           unchanged (dampening, not blind exclusion).
        4. **budget** — the campaign execution / wall-time cap, cut with an
           explicit ``budget_exceeded``.

        Every rejection leaves an AUDITABLE ``gate_rejection`` run_log entry
        (candidates offered, the choice, the verdict and its reason) — plan
        §6 / T-22 "elecciones rechazadas por el gate".
        """
        cfg = pa.get("gate_config") or {}
        scope_hosts = cfg.get("scope_hosts") or []
        proposed = set(cfg.get("proposed_tools") or [])
        candidates = list(
            _gate_candidate_tools(session, chain_snapshot=chain_snapshot)
        )
        accepted = set(candidates) | proposed
        session_id = session.get("session_id")
        # (1) membership — the tool must belong to the proposed set / catalog.
        in_catalog = _gate_in_catalog(self.decision_engine, tool)

        def _deny(verdict: str, reason: str) -> Dict[str, Any]:
            entry = {
                "event": _GATE_EVENT_REJECTION,
                "tool": tool,
                "choice": {"tool": tool, "params": dict(run_params or {})},
                "verdict": verdict,
                "reason": reason,
                "candidates_offered": candidates,
                "in_catalog": in_catalog,
                "executed": False,
                "blocked": True,
                "timestamp": _now_iso(),
            }
            _append_run_log(self.session_flow, session_id, entry)
            return _gate_block_response(
                session_id, step_index, candidates, tool, run_params, verdict, reason
            )

        if tool not in accepted and not in_catalog:
            return _deny("not_in_proposed_set", "choice not in the proposed set nor in the valid catalog")

        # (2) scope — host allowlist (generalised T-5), session target anchors.
        session_host = _gate_session_host(session)
        host = None
        for key in _GATE_HOST_PARAM_KEYS:
            if key in run_params and isinstance(run_params.get(key), str):
                host = _gate_host(run_params.get(key))
                if host:
                    break
        in_scope = _gate_host_in_scope(host, scope_hosts)
        if in_scope and session_host and host and host != session_host:
            # The session was profiled against a specific target: treat that
            # target as an implicit in-scope anchor so legitimate steps aimed
            # at the session's own host pass even with a narrow allowlist.
            in_scope = _gate_host_in_scope(host, [session_host])
        if not in_scope:
            return _deny("host_out_of_scope", f"host '{host}' is out_of_scope for the session allowlist")

        # (3) duplicate suppression / phase order — dampened failed repeats.
        last_outcome = _gate_last_outcome(session)
        if last_outcome.get(tool) is False:
            return _deny(
                "duplicate_failure",
                "tool failed on its most recent run (dampened via _session_failure_penalties, factor 0.2) and was repeated unchanged",
            )

        # (4) budget — campaign execution / wall-time cap.
        if _gate_budget_status(session, cfg.get("max_executions"), cfg.get("max_seconds")):
            return _deny("budget_exceeded", "campaign budget (executions / wall time) exceeded")

        return None

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
# T-18 — pre-execution GATE (colocación "b").
#
# Applies the Jev decision discipline to EVERY tool-call (not only web):
#   (1) membership — the chosen tool must belong to the proposed set (T-17
#       indexed candidates) or the valid catalog (analog of Jev's
#       validate_choice "choice in ids"); today run_tool does NOT enforce
#       this, so a free-text choice would execute unchecked;
#   (2) scope — a per-session host allowlist applied to ANY tool (generalises
#       T-5's web-only allowlist);
#   (3) duplicate suppression / phase order — a tool whose most recent run
#       failed in this session is dampened by _session_failure_penalties
#       (factor 0.2); the gate turns that into a hard rejection when the
#       supervisor repeats it unchanged (dampening, not blind exclusion);
#   (4) budget — a campaign cap on executions / wall time, cut with an
#       explicit BUDGET_EXCEEDED.
#
# Every rejection leaves an AUDITABLE run_log entry (candidates offered,
# choice, verdict, reason) per plan §6 / T-22 "elecciones rechazadas por el
# gate".
#
# The gate is OFF by default (ADR §T-23: router/gate activable por flag, OFF
# por defecto). It is enabled per session via ``configure_gate`` so the
# existing plan-and-approve contract is untouched until it is opted in.
# ---------------------------------------------------------------------------

# Keys whose values carry a host/domain to scope-check. Grounded in the
# parameter names the catalog + MCP gateway actually use ("target" is the
# canonical one; "url"/"host"/"hostname" are the common web/ssh variants).
_GATE_HOST_PARAM_KEYS = ("target", "url", "host", "hostname", "ip")

_GATE_EVENT_REJECTION = "gate_rejection"
_GATE_EVENT_ALLOW = "gate_allow"


def _gate_host(value: Any) -> Optional[str]:
    """Extract a scope-checkable host (domain / bare IP) from a param value.

    Grounded: strips a scheme, the ``user@`` prefix, a path, a port and IPv6
    bracketing. Returns None when the value is not a host-like string.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.startswith(("http://", "https://")):
        s = s.split("://", 1)[1]
    # drop a user@ prefix and any path/query (host:port comes first).
    s = s.split("@", 1)[-1]
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    # IPv6: keep the bracketed host only.
    if s.startswith("["):
        end = s.find("]")
        return s[1:end] if end > 1 else None
    # bare host:port -> host.
    s = s.split(":", 1)[0]
    s = s.strip()
    return s or None


def _gate_ip_key(host: Optional[str]) -> Optional[str]:
    """Map *host* to a comparable key: the exact host string, or the normalised
    IP string when *host* is a literal IP (so allowlist "10.0.0.1" matches
    "10.0.0.1:443" style values)."""
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def _gate_candidate_tools(
    session_dict: Dict[str, Any],
    chain_snapshot: Optional[List[Dict[str, Any]]] = None,
) -> List[str]:
    """Tools offered to the supervisor in the LAST propose_next_step call.

    Sourced from the plan-and-approve chain's pending steps (the concrete
    candidate set, in order) — the gate's "id set" analog of Jev's action
    space. When *chain_snapshot* is given (a copy of the steps taken before
    the current call appended an ad-hoc reorientation step), it is used
    instead of the live chain: the membership check must validate against
    what the supervisor was actually offered, not against a step that the
    very call being validated invented.
    """
    steps: List[Dict[str, Any]]
    if chain_snapshot is not None:
        steps = [s for s in chain_snapshot if isinstance(s, dict)]
    else:
        meta = session_dict.get("metadata") or {}
        pa = meta.get(PA_METADATA_KEY) or {}
        chain = pa.get("chain") or {}
        steps = chain.get("steps", [])
    tools: List[str] = []
    for s in steps:
        if not isinstance(s, dict):
            continue
        tool = s.get("tool")
        if tool and tool not in tools:
            tools.append(tool)
    return tools


def _gate_in_catalog(decision_engine: Any, tool: str) -> bool:
    """True when *tool* is a member of the valid tool catalog."""
    if not tool:
        return False
    catalog = getattr(decision_engine, "tool_catalog", None) or {}
    return tool in catalog


def _gate_last_outcome(session_dict: Dict[str, Any]) -> Dict[str, bool]:
    """Last recorded outcome per tool in the session run_log.

    Reuses the same "last entry wins" semantics as
    IntelligentDecisionEngine._session_failure_penalties (so a tool that failed
    and later succeeded on retry is no longer penalized).
    """
    run_log = session_dict.get("run_log") or []
    last: Dict[str, bool] = {}
    for entry in run_log:
        if not isinstance(entry, dict):
            continue
        tool = entry.get("tool")
        # Execution entries only — gate events carry no "tool" success flag.
        if not tool or "success" not in entry:
            continue
        last[tool] = bool(entry.get("success", False))
    return last


def _gate_session_host(session_dict: Dict[str, Any]) -> Optional[str]:
    """The session's primary target host (for the implicit in-scope anchor)."""
    target = session_dict.get("target")
    return _gate_host(target)


def _gate_host_in_scope(host: Optional[str], scope_hosts: List[str]) -> bool:
    """True when *host* is inside the allowlist *scope_hosts*.

    An empty/None allowlist means "no scope restriction" (gate off for the
    scope dimension) -> True. When the allowlist is set, the host must match
    an entry exactly, as an IP-normalised key, or be a subdomain of an entry.
    """
    if not scope_hosts:
        return True
    if not host:
        return True
    host_lc = host.lower().strip(".")
    for entry in scope_hosts:
        e = str(entry).lower().strip().strip(".")
        if not e:
            continue
        if host_lc == e:
            return True
        # subdomain: host ends with ".<entry>"
        if host_lc.endswith("." + e):
            return True
        # IP normalisation match (allowlist IP vs param host:port/IP).
        if _gate_ip_key(host_lc) == _gate_ip_key(e):
            return True
    return False


def _gate_budget_status(
    session_dict: Dict[str, Any],
    max_executions: Optional[int],
    max_seconds: Optional[float],
) -> Optional[str]:
    """Return 'budget_exceeded' when the campaign cap is reached, else None."""
    if max_executions is not None:
        n_exec = sum(
            1 for e in (session_dict.get("run_log") or [])
            if isinstance(e, dict) and e.get("event") not in (_GATE_EVENT_REJECTION, _GATE_EVENT_ALLOW)
        )
        if n_exec >= max_executions:
            return "budget_exceeded"
    if max_seconds is not None:
        run_log = session_dict.get("run_log") or []
        start = None
        for e in run_log:
            if isinstance(e, dict) and "timestamp" in e and e.get("event") not in (_GATE_EVENT_REJECTION, _GATE_EVENT_ALLOW):
                start = e.get("timestamp")
                break
        if start is not None:
            try:
                elapsed = time.time() - datetime.fromisoformat(start).timestamp()
            except (ValueError, TypeError):
                elapsed = 0.0
            if elapsed >= max_seconds:
                return "budget_exceeded"
    return None


def _gate_block_response(
    session_id: str,
    step_index: Optional[int],
    candidates: List[str],
    tool: str,
    run_params: Dict[str, Any],
    verdict: str,
    reason: str,
) -> Dict[str, Any]:
    """Build the planner-facing rejection response (executor NOT called)."""
    return {
        "success": False,
        "status": "BLOCKED",
        "session_id": session_id,
        "step_index": step_index,
        "gate": {"verdict": verdict, "reason": reason,
                 "candidates": candidates},
        "executed_step": {
            "tool": tool,
            "status": "proposed",
            "reason": f"gate rejected: {verdict} ({reason})",
        },
        "timestamp": datetime.now().isoformat(),
    }


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
        # T-19: post-execution actionable category (absent until the step ran).
        # chain_report's step dict carries it for the planner + Wazuh
        # correlation (T-11); grounded — only set from the categorizer.
        **({"result_category": step["result_category"]}
           if step.get("result_category") else {}),
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
    # T-19: carry the actionable result category through the projection so it
    # reaches both the planner's response result and the chain step re-read via
    # _step_public (idempotent: re-projecting an already-trimmed result keeps
    # the label).
    if "result_category" in result and result["result_category"]:
        out["result_category"] = result["result_category"]
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


def _now_iso() -> str:
    """Clock-driven ISO timestamp for run_log entries.

    Built from ``time.time()`` (not ``datetime.now()``) so an entry's
    timestamp stays consistent with the elapsed-time arithmetic in
    ``_gate_budget_status`` when tests patch the module's ``time`` clock
    (the T-18 time-budget cut is deterministic that way).
    """
    return datetime.fromtimestamp(time.time()).isoformat()
