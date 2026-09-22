"""Plan-and-approve HTTP endpoints (Pilar 4, cap. 8).

Thin Flask blueprint that exposes the 5-tool plan-and-approve contract over
HTTP. Each endpoint delegates to :class:`PlanAndApproveController`, which is the
single source of truth for the contract (tests exercise that directly).

Routes (all POST, JSON in / JSON out):
    /api/plan/profile-target
    /api/plan/propose-next-step
    /api/plan/execute-step
    /api/plan/update-chain
    /api/plan/chain-report
"""

import json
import logging
import time
from datetime import datetime
from typing import Optional

from flask import Blueprint, request, jsonify

from backend.server_core.intelligence.plan_and_approve import (
    PA_SOURCE,
    PlanAndApproveController,
)

logger = logging.getLogger(__name__)

api_plan_approve_bp = Blueprint("api_plan_approve", __name__)


# A module-level controller instance is created lazily so the Flask app can be
# imported without pulling the decision-engine singleton at import time.
_controller: Optional[PlanAndApproveController] = None


def _get_controller() -> PlanAndApproveController:
    global _controller
    if _controller is None:
        _controller = PlanAndApproveController()
    return _controller


def _set_controller_for_test(ctrl: PlanAndApproveController) -> None:
    """Used by tests to inject a stubbed controller."""
    global _controller
    _controller = ctrl


def _read_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    return data


def _wrap(payload: dict, stdout_payload: dict, start_time: float) -> dict:
    return {
        "success": bool(payload.get("success", False)),
        **payload,
        "stdout": json.dumps(stdout_payload, indent=2),
        "stderr": "",
        "return_code": 0 if payload.get("success", False) else 1,
        "timed_out": False,
        "partial_results": False,
        "execution_time": time.time() - start_time,
        "timestamp": datetime.now().isoformat(),
    }


@api_plan_approve_bp.route("/api/plan/profile-target", methods=["POST"])
def profile_target():
    data = _read_body()
    start = time.time()
    try:
        result = _get_controller().profile_target(
            target=data.get("target", ""),
            objective=data.get("objective", "comprehensive"),
            planner_mode=data.get("planner_mode"),
            session_id=data.get("session_id"),
        )
        return jsonify(_wrap(result, result, start))
    except Exception as exc:
        logger.exception("plan-and-approve profile-target failed")
        return jsonify({
            "success": False,
            "error": f"profile_target failed: {exc}",
            "stdout": "",
            "return_code": 1,
            "timestamp": datetime.now().isoformat(),
        }), 500


@api_plan_approve_bp.route("/api/plan/propose-next-step", methods=["POST"])
def propose_next_step():
    data = _read_body()
    start = time.time()
    try:
        result = _get_controller().propose_next_step(
            session_id=data.get("session_id", ""),
            objective=data.get("objective"),
            planner_mode=data.get("planner_mode"),
            rerank=bool(data.get("rerank", False)),
        )
        return jsonify(_wrap(result, result, start))
    except Exception as exc:
        logger.exception("plan-and-approve propose-next-step failed")
        return jsonify({
            "success": False,
            "error": f"propose_next_step failed: {exc}",
            "return_code": 1,
            "timestamp": datetime.now().isoformat(),
        }), 500


@api_plan_approve_bp.route("/api/plan/execute-step", methods=["POST"])
def execute_step():
    data = _read_body()
    start = time.time()
    try:
        result = _get_controller().execute_step(
            session_id=data.get("session_id", ""),
            step_index=data.get("step_index"),
            tool=data.get("tool"),
            params=data.get("params"),
        )
        return jsonify(_wrap(result, result, start))
    except Exception as exc:
        logger.exception("plan-and-approve execute-step failed")
        return jsonify({
            "success": False,
            "error": f"execute_step failed: {exc}",
            "return_code": 1,
            "timestamp": datetime.now().isoformat(),
        }), 500


@api_plan_approve_bp.route("/api/plan/update-chain", methods=["POST"])
def update_chain():
    data = _read_body()
    start = time.time()
    try:
        result = _get_controller().update_chain(
            session_id=data.get("session_id", ""),
            action=data.get("action", "add"),
            step=data.get("step"),
            step_index=data.get("step_index"),
            tool=data.get("tool"),
            parameters=data.get("parameters"),
            new_objective=data.get("new_objective"),
        )
        return jsonify(_wrap(result, result, start))
    except Exception as exc:
        logger.exception("plan-and-approve update-chain failed")
        return jsonify({
            "success": False,
            "error": f"update_chain failed: {exc}",
            "return_code": 1,
            "timestamp": datetime.now().isoformat(),
        }), 500


@api_plan_approve_bp.route("/api/plan/chain-report", methods=["POST"])
def chain_report():
    data = _read_body()
    start = time.time()
    try:
        result = _get_controller().chain_report(
            session_id=data.get("session_id", ""),
            include_attack=bool(data.get("include_attack", True)),
        )
        return jsonify(_wrap(result, result, start))
    except Exception as exc:
        logger.exception("plan-and-approve chain-report failed")
        return jsonify({
            "success": False,
            "error": f"chain_report failed: {exc}",
            "return_code": 1,
            "timestamp": datetime.now().isoformat(),
        }), 500
