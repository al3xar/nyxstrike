"""
web_interaction — Jev as an HTTP-backed toolspec category of NyxStrike.

ADR (hades-tfm/wiki/nyxstrike/adr-jev-web-interaction-toolspec.md) fija: Jev NO
es un MCP standalone, sino una CATEGORÍA de toolspec de NyxStrike, HTTP-backed
contra el env ``JEV_URL`` (el servicio Jev de T-1, ``jev_ultrafast.service``),
con el mismo patrón que ``web_crawl`` / ``web_probe`` / ``web_scan`` /
``web_fuzz``.

Las 3 tools (nombres alineados con el espacio ``web_*`` para no colisionar en
el MCP; el sidecar ``nyxstrike-mcp`` les aplica el prefijo ``mcp_nyxstrike_*``):

  * ``web_run_goal``        POST /api/tools/web_run_goal        -> Jev POST /run_goal
  * ``web_extract_surface`` POST /api/tools/web_extract_surface -> Jev POST /extract_surface
  * ``web_get_evidence``    GET  /api/tools/web_get_evidence    -> Jev GET  /get_evidence/{run_id}

Cada handler proxya al servicio Jev y devuelve SIEMPRE ``stdout`` / ``stderr``
/ ``return_code`` (además de los campos útiles). Es ese trío el que el hook
``record_tool_run`` (``nyxstrike_server.py``) detecta y encadena en la cadena de
evidencias tamper-evident + ``tool_stats`` / ``session_flow`` (ADR §3, ver T-9).

Nota de red: los tests monkey-pachean ``_requests`` y fijan ``JEV_URL``; este
módulo nunca llama a una API pagada (regla del repo).
"""

import json
import logging
import os

import requests

from backend.server_core.tool_spec import ParamSpec, ToolSpec, ToolValidationError

logger = logging.getLogger(__name__)

# Module-level handle so tests can swap the real `requests` for a fake. The
# handlers always route through ``_requests`` — never a bare ``requests.``.
_requests = requests


def _jev_base_url() -> str:
    """Base URL of the Jev service (env JEV_URL, e.g. http://jev.nyx.svc:8765)."""
    return (os.environ.get("JEV_URL", "") or "").rstrip("/")


# --- response shaping -------------------------------------------------------

def _success(payload: dict, summary: str, run_id: str = "") -> dict:
    """A successful proxy response in the evidence shape.

    ``stdout`` carries the machine-readable Jev payload (compact JSON) plus a
    human-readable summary line; ``stderr`` is empty; ``return_code`` is 0.
    """
    stdout_lines = []
    if run_id:
        stdout_lines.append(f"run_id={run_id}")
    stdout_lines.append(f"summary: {summary}")
    stdout_lines.append(f"payload={json.dumps(payload, ensure_ascii=False, sort_keys=True)}")
    return {
        "success": True,
        "stdout": "\n".join(stdout_lines),
        "stderr": "",
        "return_code": 0,
        **{k: v for k, v in payload.items() if k not in ("success",)},
    }


def _failure(status: int, detail: str, partial: dict | None = None) -> dict:
    """A failure/HTTP-error response in the evidence shape (non-zero return_code)."""
    body = dict(partial or {})
    body.update({
        "success": False,
        "stdout": "",
        "stderr": f"JEV HTTP {status}: {detail}".strip(),
        "return_code": 1,
    })
    return body


def _network_failure(exc: Exception) -> dict:
    body = {
        "success": False,
        "stdout": "",
        "stderr": f"Jev service unreachable (JEV_URL): {exc}",
        "return_code": 1,
    }
    return body


# --- handlers ---------------------------------------------------------------

def _run_goal_handler(p: dict) -> dict:
    """POST Jev /run_goal — execute a full subgoal (loop until DONE/BLOCKED/budget)."""
    url = (p.get("url") or "").strip()
    goal = (p.get("goal") or "").strip()
    session_id = (p.get("session_id") or "").strip()
    if not url:
        raise ToolValidationError("url parameter is required")
    if not goal:
        raise ToolValidationError("goal parameter is required")
    if not session_id:
        raise ToolValidationError("session_id parameter is required")

    base = _jev_base_url()
    if not base:
        return {
            "success": False,
            "stdout": "",
            "stderr": "JEV_URL is not set — cannot reach the Jev service",
            "return_code": 1,
        }

    body = {
        "url": url,
        "goal": goal,
        "session_id": session_id,
    }
    # Budget knobs are clamped/passed through by the Jev wrapper (T-5); forward
    # them verbatim so the service can enforce its hard limits.
    for key in ("max_actions", "max_decisions", "reuse_session", "screenshots",
                "scope_allowlist", "verify"):
        if key in p and p[key] not in (None, ""):
            body[key] = p[key]

    try:
        resp = _requests.post(f"{base}/run_goal", json=body, timeout=None)
    except requests.exceptions.RequestException as exc:
        return _network_failure(exc)

    payload = resp.json()
    if resp.status_code >= 400:
        return _failure(resp.status_code, payload.get("detail", str(payload)), partial=payload)

    run_id = payload.get("run_id", "")
    status = payload.get("status", "")
    summary = f"run_goal {status or 'done'} for {goal} on {url} (session {session_id})"
    if payload.get("error"):
        summary += f" — error: {payload['error']}"
    return _success(payload, summary, run_id=run_id)


def _extract_surface_handler(p: dict) -> dict:
    """POST Jev /extract_surface — one indexed snapshot, no loop (cheap recon)."""
    url = (p.get("url") or "").strip()
    session_id = (p.get("session_id") or "").strip()
    if not url:
        raise ToolValidationError("url parameter is required")
    if not session_id:
        raise ToolValidationError("session_id parameter is required")

    base = _jev_base_url()
    if not base:
        return {
            "success": False,
            "stdout": "",
            "stderr": "JEV_URL is not set — cannot reach the Jev service",
            "return_code": 1,
        }

    body = {"url": url, "session_id": session_id, "reuse_session": bool(p.get("reuse_session", True))}

    try:
        resp = _requests.post(f"{base}/extract_surface", json=body, timeout=None)
    except requests.exceptions.RequestException as exc:
        return _network_failure(exc)

    payload = resp.json()
    if resp.status_code >= 400:
        return _failure(resp.status_code, payload.get("detail", str(payload)), partial=payload)

    elements = payload.get("elements") or []
    summary = (
        f"extract_surface for {url}: "
        f"{len(elements)} indexed elements on {payload.get('title') or 'page'}"
    )
    return _success(payload, summary)


def _get_evidence_handler(p: dict) -> dict:
    """GET Jev /get_evidence/{run_id} — full trace + snapshot + evidence chain."""
    run_id = (p.get("run_id") or "").strip()
    if not run_id:
        raise ToolValidationError("run_id parameter is required")

    base = _jev_base_url()
    if not base:
        return {
            "success": False,
            "stdout": "",
            "stderr": "JEV_URL is not set — cannot reach the Jev service",
            "return_code": 1,
        }

    try:
        resp = _requests.get(f"{base}/get_evidence/{run_id}", timeout=None)
    except requests.exceptions.RequestException as exc:
        return _network_failure(exc)

    payload = resp.json()
    if resp.status_code >= 400:
        return _failure(resp.status_code, payload.get("detail", str(payload)), partial=payload)

    history = payload.get("history") or []
    summary = (
        f"evidence for run {run_id}: status={payload.get('status', '')}, "
        f"{len(history)} recorded actions"
    )
    return _success(payload, summary, run_id=run_id)


# --- specs ------------------------------------------------------------------

SPECS = [
    ToolSpec(
        name="web_run_goal",
        mcp_tool_name="web_run_goal",
        endpoint="/api/tools/web_run_goal",
        category="web_interaction",
        method="POST",
        description=(
            "Drive Jev (fast browser executor) to complete a web subgoal end-to-end: "
            "open the URL and run the action loop until DONE / BLOCKED / budget. "
            "Returns the compressed subgoal result (run_id + status + extracted data). "
            "Trace/screenshots are fetched separately via web_get_evidence."
        ),
        params=[
            ParamSpec("url", str, required=True, help_text="Starting URL of the web application"),
            ParamSpec("goal", str, required=True, help_text="Natural-language subgoal to accomplish on the page"),
            ParamSpec("session_id", str, required=True, help_text="NyxStrike session id to correlate the run into (evidence chain + session_flow)"),
            ParamSpec("max_actions", int, default=40, help_text="Hard cap on browser actions for this run (Jev budget)"),
            ParamSpec("max_decisions", int, default=80, help_text="Hard cap on model decision calls for this run (Jev budget)"),
            ParamSpec("reuse_session", bool, default=True, help_text="Reuse an existing Jev browser session/context for this session_id"),
            ParamSpec("scope_allowlist", list, default=[], help_text="Hosts/URLs allowed; out-of-scope navigation is rejected (empty = no allowlist)"),
            ParamSpec("verify", str, default="", help_text="Optional verification condition; filled into the subgoal contract by the verifier (T-3)"),
            ParamSpec("screenshots", bool, default=False, help_text="Capture screenshots inside the loop (off by default — structured state only)"),
        ],
        handler=_run_goal_handler,
        use_cache=False,
    ),
    ToolSpec(
        name="web_extract_surface",
        mcp_tool_name="web_extract_surface",
        endpoint="/api/tools/web_extract_surface",
        category="web_interaction",
        method="POST",
        description=(
            "Cheap web recon: capture ONE indexed DOM/ARIA snapshot of the URL "
            "(no action loop, 1 TypeSafe request) to enumerate the interactive surface."
        ),
        params=[
            ParamSpec("url", str, required=True, help_text="URL to snapshot"),
            ParamSpec("session_id", str, required=True, help_text="NyxStrike session id to correlate into"),
            ParamSpec("reuse_session", bool, default=True, help_text="Reuse an existing Jev browser session/context"),
        ],
        handler=_extract_surface_handler,
        use_cache=False,
    ),
    ToolSpec(
        name="web_get_evidence",
        mcp_tool_name="web_get_evidence",
        endpoint="/api/tools/web_get_evidence",
        category="web_interaction",
        method="GET",
        description=(
            "Retrieve the full evidence for a Jev run by run_id: action trace, final "
            "snapshot, and the tamper-evident evidence-chain hash (sha256)."
        ),
        params=[
            ParamSpec("run_id", str, required=True, help_text="Jev run id (from web_run_goal)"),
        ],
        handler=_get_evidence_handler,
        use_cache=False,
    ),
]
