"""
tests/test_web_interaction_registry.py

T-6 · Categoría `web_interaction` de NyxStrike (Jev como rama HTTP-backed).

Jev NO es un MCP standalone: es una CATEGORÍA de toolspec de NyxStrike,
HTTP-backed contra el env ``JEV_URL`` (servicio Jev de T-1), con el mismo
patrón que ``web_crawl`` / ``web_probe`` / ``web_scan`` / ``web_fuzz``.

Los 3 tools de la categoría:
  * ``web_run_goal``        -> POST /api/tools/web_run_goal
  * ``web_extract_surface`` -> POST /api/tools/web_extract_surface
  * ``web_get_evidence``    -> GET  /api/tools/web_get_evidence

Los endpoints proxyean al servicio Jev y devuelven ``stdout`` / ``stderr`` /
``return_code`` para que el hook ``record_tool_run`` (nyxstrike_server.py) los
capture en la cadena de evidencias tamper-evident (ver ADR y T-9).

Tests offline: NO hay red real. El módulo ``requests`` usado por
``web_interaction`` se monkey-patchea y ``JEV_URL`` se fija a un valor dummy.
"""

import importlib
import os
import sys

import pytest
from unittest.mock import MagicMock

# Ensure the backend package is importable exactly as the runtime sees it.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

SPEC_MODULE = "backend.server_core.tool_specs.web_interaction"


def _specs():
    module = importlib.import_module(SPEC_MODULE)
    return module.SPECS


# ---------------------------------------------------------------------------
# 1) The category exists and exposes exactly the 3 ToolSpecs with the right shape
# ---------------------------------------------------------------------------
class TestToolSpecShape:
    def test_module_exposes_three_specs(self):
        specs = _specs()
        assert len(specs) == 3, f"expected 3 SPECS, got {len(specs)}"

    def test_all_three_names_present(self):
        names = {s.name for s in _specs()}
        assert names == {"web_run_goal", "web_extract_surface", "web_get_evidence"}

    def test_category_field_is_web_interaction(self):
        for spec in _specs():
            assert spec.category == "web_interaction", spec.name

    def test_mcp_tool_names_follow_nyxstrike_web_convention(self):
        """The resulting MCP tool names must be ``mcp_nyxstrike_web_*``-style
        (the ``mcp_nyxstrike_`` prefix is applied by the ``nyxstrike`` toolset
        binding in the charts; here we lock the bare tool names)."""
        names = {s.mcp_tool_name for s in _specs()}
        assert names == {
            "web_run_goal",
            "web_extract_surface",
            "web_get_evidence",
        }
        for name in names:
            assert name.startswith("web_"), name

    def test_endpoints_map_to_api_tools_web(self):
        by_name = {s.name: s for s in _specs()}
        assert by_name["web_run_goal"].endpoint == "/api/tools/web_run_goal"
        assert by_name["web_extract_surface"].endpoint == "/api/tools/web_extract_surface"
        assert by_name["web_get_evidence"].endpoint == "/api/tools/web_get_evidence"

    def test_methods_run_goal_and_extract_are_post_evidence_is_get(self):
        by_name = {s.name: s for s in _specs()}
        assert by_name["web_run_goal"].method == "POST"
        assert by_name["web_extract_surface"].method == "POST"
        assert by_name["web_get_evidence"].method == "GET"

    def test_every_spec_has_a_handler(self):
        """These are HTTP-backed (proxy to Jev), not shell-command tools: each
        spec must carry a handler and no build_command."""
        for spec in _specs():
            assert spec.handler is not None, spec.name
            assert spec.build_command is None, spec.name

    def test_run_goal_param_contract(self):
        by_name = {s.name: s for s in _specs()}
        params = {p.name: p for p in by_name["web_run_goal"].params}
        # Required inputs
        for required in ("url", "goal", "session_id"):
            assert required in params, required
            assert params[required].required is True
        # Optional knobs with the ADR/task defaults
        assert params["max_actions"].type is int
        assert params["max_actions"].default == 40
        assert params["max_decisions"].type is int
        assert params["max_decisions"].default == 80
        assert params["reuse_session"].type is bool
        assert params["reuse_session"].default is True
        assert params["screenshots"].type is bool
        assert params["screenshots"].default is False

    def test_extract_surface_param_contract(self):
        by_name = {s.name: s for s in _specs()}
        params = {p.name: p for p in by_name["web_extract_surface"].params}
        assert params["url"].required is True
        assert params["session_id"].required is True
        assert params["reuse_session"].type is bool
        assert params["reuse_session"].default is True

    def test_get_evidence_param_contract(self):
        by_name = {s.name: s for s in _specs()}
        params = {p.name: p for p in by_name["web_get_evidence"].params}
        assert params["run_id"].required is True


# ---------------------------------------------------------------------------
# 2) Category is registered in the MCP tool profiles
# ---------------------------------------------------------------------------
class TestToolProfilesRegistration:
    def test_web_interaction_is_a_tool_profile(self):
        from mcp_client.tool_profiles import TOOL_PROFILES
        assert "web_interaction" in TOOL_PROFILES

    def test_web_interaction_is_in_cyber_range_profile(self):
        """Hades drives the cyber-range profile; the web branch must be there."""
        from mcp_client.tool_profiles import CYBER_RANGE_PROFILE
        assert "web_interaction" in CYBER_RANGE_PROFILE

    def test_profile_registers_web_interaction_category(self, monkeypatch):
        """The profile entry must route through register_toolspec_category with
        the ``web_interaction`` category (identical to every other web_*
        profile). The lambda resolves the global name at call time, so we swap
        it in the tool_profiles namespace and confirm the category it emits."""
        from mcp_client import tool_profiles
        calls = []

        def fake_reg(mcp, client, logger, category):
            calls.append(category)

        monkeypatch.setattr(tool_profiles, "register_toolspec_category", fake_reg)
        tool_profiles.TOOL_PROFILES["web_interaction"][0](
            MagicMock(), MagicMock(), MagicMock()
        )
        assert calls == ["web_interaction"], calls


# ---------------------------------------------------------------------------
# 3) The handlers proxy to Jev and return stdout/stderr/return_code
# ---------------------------------------------------------------------------
def _fake_response(status_code=200, payload=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = ""
    if payload is not None:
        r.json.return_value = payload
    else:
        r.json.side_effect = ValueError("no json")
    return r


def _patch_requests(monkeypatch, response):
    import backend.server_core.tool_specs.web_interaction as wi
    fake = MagicMock()
    fake.post.return_value = response
    fake.get.return_value = response
    monkeypatch.setattr(wi, "_requests", fake)
    return fake


class TestHandlersReturnEvidenceShape:
    def setup_method(self):
        self.params = {
            "url": "https://range.invalid/login",
            "goal": "obtain the flag",
            "session_id": "hades-sess-1",
            "max_actions": 40,
            "max_decisions": 80,
            "reuse_session": True,
            "scope_allowlist": [],
            "verify": "",
            "screenshots": False,
        }

    def test_jev_url_unset_is_clean_error_not_network(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.delenv("JEV_URL", raising=False)
        fake = MagicMock()
        monkeypatch.setattr(wi, "_requests", fake)
        out = wi.SPECS[0].handler(dict(self.params))
        assert out["return_code"] == 1
        assert out["success"] is False
        assert "JEV_URL" in out["stderr"]
        # No network call attempted.
        fake.post.assert_not_called()
        fake.get.assert_not_called()

    def test_run_goal_success_returns_stdout_stderr_return_code(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        payload = {
            "run_id": "jev-abc123",
            "status": "done",
            "session_id": "hades-sess-1",
            "elapsed_ms": 7100,
            "error": None,
        }
        fake = _patch_requests(monkeypatch, _fake_response(200, payload))
        out = wi.SPECS[0].handler(dict(self.params))
        for key in ("stdout", "stderr", "return_code", "success"):
            assert key in out, key
        assert out["return_code"] == 0
        assert out["success"] is True
        assert out["stderr"] == ""
        # stdout must carry the Jev run id so the evidence chain is linkable.
        assert "jev-abc123" in out["stdout"]
        # It must have POSTed to Jev's /run_goal.
        fake.post.assert_called_once()
        called_url = fake.post.call_args[0][0]
        assert called_url.endswith("/run_goal"), called_url
        # The forwarded body carries url/goal/session_id.
        body = fake.post.call_args[1].get("json")
        assert body["url"] == self.params["url"]
        assert body["goal"] == self.params["goal"]
        assert body["session_id"] == self.params["session_id"]

    def test_run_goal_http_error_maps_to_nonzero_return_code(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        fake = _patch_requests(monkeypatch, _fake_response(503, {"detail": "Browser unavailable"}))
        out = wi.SPECS[0].handler(dict(self.params))
        assert out["return_code"] == 1
        assert out["success"] is False
        assert "stderr" in out and "503" in out["stderr"]

    def test_run_goal_network_error_is_caught(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        import requests as real_requests
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        fake = MagicMock()
        fake.post.side_effect = real_requests.exceptions.ConnectionError("boom")
        monkeypatch.setattr(wi, "_requests", fake)
        out = wi.SPECS[0].handler(dict(self.params))
        assert out["return_code"] == 1
        assert out["success"] is False
        assert out["stdout"] == ""
        assert "unreachable" in out["stderr"].lower() or "boom" in out["stderr"]

    def test_extract_surface_success(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        payload = {
            "run_id": None,
            "session_id": "hades-sess-1",
            "status": "ready",
            "url": "https://range.invalid/login",
            "title": "Login",
            "text": "Please sign in",
            "elements": [{"id": 1, "role": "textbox"}, {"id": 2, "role": "button"}],
        }
        fake = _patch_requests(monkeypatch, _fake_response(200, payload))
        spec = {s.name: s for s in wi.SPECS}["web_extract_surface"]
        out = spec.handler({"url": "https://range.invalid/login", "session_id": "hades-sess-1", "reuse_session": True})
        assert out["return_code"] == 0
        assert out["success"] is True
        assert "stdout" in out and "stderr" in out and "return_code" in out
        # Bounded stdout mentions the surface title and element count.
        assert "Login" in out["stdout"]
        fake.post.assert_called_once()
        assert fake.post.call_args[0][0].endswith("/extract_surface")

    def test_get_evidence_success(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        payload = {
            "run_id": "jev-abc123",
            "session_id": "hades-sess-1",
            "url": "https://range.invalid/login",
            "goal": "obtain the flag",
            "status": "done",
            "error": None,
            "elapsed_ms": 7100,
            "history": [{"op": "CLICK", "target": 7}],
            "snapshot": {"url": "https://range.invalid/flag", "title": "Flag"},
            "created_at": 1234567890.0,
        }
        fake = _patch_requests(monkeypatch, _fake_response(200, payload))
        spec = {s.name: s for s in wi.SPECS}["web_get_evidence"]
        out = spec.handler({"run_id": "jev-abc123"})
        assert out["return_code"] == 0
        assert out["success"] is True
        assert "stdout" in out and "stderr" in out and "return_code" in out
        assert "jev-abc123" in out["stdout"]
        # It must have GET the run by id.
        fake.get.assert_called_once()
        assert "jev-abc123" in fake.get.call_args[0][0]

    def test_get_evidence_unknown_run_is_404(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        fake = _patch_requests(monkeypatch, _fake_response(404, {"detail": "Unknown run_id"}))
        spec = {s.name: s for s in wi.SPECS}["web_get_evidence"]
        out = spec.handler({"run_id": "jev-missing"})
        assert out["return_code"] == 1
        assert out["success"] is False
        assert "stderr" in out and "404" in out["stderr"]


# ---------------------------------------------------------------------------
# 4) The Flask endpoints exist and are wired through the toolspec autoload
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    from nyxstrike_server import app
    app.config["TESTING"] = True
    app.config["NYXSTRIKE_API_TOKEN"] = None
    with app.test_client() as c:
        yield c


class TestFlaskEndpoints:
    """Import the real Flask app and assert the three routes are registered and
    proxy to Jev, returning the evidence shape. execute_command is mocked by
    conftest; the Jev ``requests`` calls are monkey-patched per test."""

    def test_routes_are_registered(self, client):
        # A POST with an empty body must NOT be a 404 (route exists). The handler
        # may legitimately 400 (missing required param) — that still proves the
        # route is registered.
        for path in ("/api/tools/web_run_goal", "/api/tools/web_extract_surface"):
            resp = client.post(path, json={})
            assert resp.status_code != 404, f"{path} unregistered"
        resp = client.get("/api/tools/web_get_evidence")
        assert resp.status_code != 404, "/api/tools/web_get_evidence unregistered"

    def test_run_goal_endpoint_proxies_and_returns_evidence_shape(self, client, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        fake = MagicMock()
        fake.post.return_value = _fake_response(200, {
            "run_id": "jev-x", "status": "done", "session_id": "s",
            "elapsed_ms": 1, "error": None,
        })
        monkeypatch.setattr(wi, "_requests", fake)
        resp = client.post(
            "/api/tools/web_run_goal",
            json={"url": "https://r.invalid/", "goal": "g", "session_id": "s"},
        )
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        for key in ("stdout", "stderr", "return_code", "success"):
            assert key in data, key
        assert data["success"] is True
        assert data["return_code"] == 0
        assert "jev-x" in data["stdout"]

    def test_get_evidence_endpoint_missing_run_id_400(self, client):
        resp = client.get("/api/tools/web_get_evidence")
        # No run_id query param -> the blueprint's required-param check returns 400.
        assert resp.status_code == 400
        assert "run_id" in resp.get_json()["error"]


# ---------------------------------------------------------------------------
# Jev API-token auth (public endpoint gates every request behind a Bearer token)
# ---------------------------------------------------------------------------
class TestJevAuthHeader:
    """The public Jev endpoint requires ``Authorization: Bearer <token>``.

    When ``JEV_API_TOKEN`` is set every handler must forward it; unset (an
    in-cluster Jev with no auth, or the offline tests) must send NO Authorization
    header so local/dummy setups keep working unchanged.
    """

    params = {
        "url": "https://range.invalid/login",
        "goal": "obtain the flag",
        "session_id": "hades-sess-1",
    }

    def _spec(self, wi, name):
        return next(s for s in wi.SPECS if s.name == name)

    def test_run_goal_forwards_bearer_token_when_set(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        monkeypatch.setenv("JEV_API_TOKEN", "s3cr3t-token")
        fake = _patch_requests(monkeypatch, _fake_response(200, {
            "run_id": "jev-abc", "status": "done", "session_id": "hades-sess-1",
            "elapsed_ms": 1, "error": None,
        }))
        self._spec(wi, "web_run_goal").handler(dict(self.params))
        headers = fake.post.call_args[1].get("headers") or {}
        assert headers.get("Authorization") == "Bearer s3cr3t-token"

    def test_extract_surface_forwards_bearer_token_when_set(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        monkeypatch.setenv("JEV_API_TOKEN", "s3cr3t-token")
        fake = _patch_requests(monkeypatch, _fake_response(200, {"elements": [], "title": "t"}))
        self._spec(wi, "web_extract_surface").handler(
            {"url": self.params["url"], "session_id": self.params["session_id"]}
        )
        headers = fake.post.call_args[1].get("headers") or {}
        assert headers.get("Authorization") == "Bearer s3cr3t-token"

    def test_get_evidence_forwards_bearer_token_when_set(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        monkeypatch.setenv("JEV_API_TOKEN", "s3cr3t-token")
        fake = _patch_requests(monkeypatch, _fake_response(200, {"history": [], "screenshots": []}))
        self._spec(wi, "web_get_evidence").handler({"run_id": "jev-abc"})
        headers = fake.get.call_args[1].get("headers") or {}
        assert headers.get("Authorization") == "Bearer s3cr3t-token"

    def test_no_authorization_header_when_token_unset(self, monkeypatch):
        import backend.server_core.tool_specs.web_interaction as wi
        monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
        monkeypatch.delenv("JEV_API_TOKEN", raising=False)
        fake = _patch_requests(monkeypatch, _fake_response(200, {
            "run_id": "jev-abc", "status": "done", "session_id": "hades-sess-1",
            "elapsed_ms": 1, "error": None,
        }))
        self._spec(wi, "web_run_goal").handler(dict(self.params))
        headers = fake.post.call_args[1].get("headers") or {}
        assert "Authorization" not in headers
