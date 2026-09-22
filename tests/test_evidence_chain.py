"""
tests/test_evidence_chain.py

Unit tests for the tamper-evident hash chain (server_core.evidence_chain),
plus the RunHistoryStore wiring that produces it (record() chaining + hash round-trip
through _load()), plus T-9: a Jev web run (``web_run_goal`` toolspec) landing in the
same chain, and ``web_get_evidence`` exposing that entry's hash/prev_hash + trace +
screenshots.

The web-run sections use the real Flask app (conftest patches every subprocess path)
with the Jev service ``requests`` calls monkey-patched and a scratch RunHistoryStore —
no network, no paid APIs.
"""

import json
import os
import sys

import pytest
from unittest.mock import MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import backend.server_core.singletons as singletons  # noqa: E402
import backend.server_core.tool_specs.web_interaction as web_interaction  # noqa: E402
import nyxstrike_server  # noqa: E402
from backend.server_core.evidence_chain import (  # noqa: E402
    GENESIS_HASH,
    chain_entry,
    compute_hash,
    find_run_by_hash,
    verify_chain,
)
from backend.server_core.run_history_store import RunHistoryStore  # noqa: E402


def _make_raw_entry(i: int) -> dict:
    return {
        "tool": f"tool-{i}",
        "endpoint": f"/api/tools/tool-{i}",
        "params": {"target": f"host-{i}"},
        "session_id": "sess_abc",
        "stdout": f"output {i}",
        "stderr": "",
        "return_code": 0,
        "timestamp": f"2026-07-28T00:00:{i:02d}",
    }


def _build_chain(n: int, start_prev_hash: str = GENESIS_HASH) -> list:
    entries = []
    prev_hash = start_prev_hash
    for i in range(n):
        entry = chain_entry(_make_raw_entry(i), prev_hash)
        entries.append(entry)
        prev_hash = entry["hash"]
    return entries


# ---------------------------------------------------------------------------
# chain_entry / compute_hash
# ---------------------------------------------------------------------------

class TestChainEntry:
    def test_chain_entry_adds_hash_and_prev_hash(self):
        entry = chain_entry(_make_raw_entry(0), GENESIS_HASH)
        assert entry["prev_hash"] == GENESIS_HASH
        assert isinstance(entry["hash"], str)
        assert len(entry["hash"]) == 64

    def test_chain_entry_is_pure(self):
        raw = _make_raw_entry(0)
        chain_entry(raw, GENESIS_HASH)
        assert "hash" not in raw and "prev_hash" not in raw

    def test_same_content_same_prev_hash_is_deterministic(self):
        a = chain_entry(_make_raw_entry(0), GENESIS_HASH)
        b = chain_entry(_make_raw_entry(0), GENESIS_HASH)
        assert a["hash"] == b["hash"]

    def test_different_prev_hash_changes_hash(self):
        a = chain_entry(_make_raw_entry(0), GENESIS_HASH)
        b = chain_entry(_make_raw_entry(0), "1" * 64)
        assert a["hash"] != b["hash"]


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------

class TestVerifyChain:
    def test_valid_chain(self):
        entries = _build_chain(5)
        result = verify_chain(entries)
        assert result == {
            "valid": True,
            "total_runs": 5,
            "verified_runs": 5,
            "broken_at_index": None,
            "tip_hash": entries[-1]["hash"],
        }

    def test_empty_chain(self):
        result = verify_chain([])
        assert result["valid"] is True
        assert result["total_runs"] == 0
        assert result["verified_runs"] == 0
        assert result["tip_hash"] is None

    def test_tampered_content_breaks_at_that_index(self):
        entries = _build_chain(5)
        entries[2] = {**entries[2], "stdout": "tampered!"}
        result = verify_chain(entries)
        assert result["valid"] is False
        assert result["broken_at_index"] == 2
        assert result["verified_runs"] == 2

    def test_missing_hash_is_a_break_not_a_crash(self):
        entries = _build_chain(3)
        del entries[1]["hash"]
        result = verify_chain(entries)
        assert result["valid"] is False
        assert result["broken_at_index"] == 1

    def test_no_genesis_assumption_for_subwindow(self):
        """A chain that doesn't start at GENESIS_HASH (e.g. a session that began
        mid-way through global run history) still verifies correctly."""
        entries = _build_chain(4, start_prev_hash="deadbeef" * 8)
        result = verify_chain(entries)
        assert result["valid"] is True
        assert result["verified_runs"] == 4


# ---------------------------------------------------------------------------
# find_run_by_hash
# ---------------------------------------------------------------------------

class TestFindRunByHash:
    def test_finds_known_hash(self):
        entries = _build_chain(4)
        target = entries[2]
        found = find_run_by_hash(entries, target["hash"])
        assert found is target

    def test_case_insensitive(self):
        entries = _build_chain(1)
        found = find_run_by_hash(entries, entries[0]["hash"].upper())
        assert found is entries[0]

    def test_unknown_hash_returns_none(self):
        entries = _build_chain(3)
        assert find_run_by_hash(entries, "0" * 64) is None

    def test_empty_query_returns_none(self):
        entries = _build_chain(3)
        assert find_run_by_hash(entries, "") is None


# ---------------------------------------------------------------------------
# RunHistoryStore wiring
# ---------------------------------------------------------------------------

class TestRunHistoryStoreChaining:
    def test_record_returns_chained_entry_with_genesis_prev_hash(self, tmp_path):
        store = RunHistoryStore(data_dir=str(tmp_path))
        chained = store.record(tool="nmap", endpoint="/api/tools/nmap", params={}, result={"stdout": "ok"})
        assert chained["prev_hash"] == GENESIS_HASH
        assert compute_hash(chained, GENESIS_HASH) == chained["hash"]

    def test_successive_records_chain_together(self, tmp_path):
        store = RunHistoryStore(data_dir=str(tmp_path))
        first = store.record(tool="nmap", endpoint="/e1", params={}, result={"stdout": "a"})
        second = store.record(tool="whois", endpoint="/e2", params={}, result={"stdout": "b"})
        assert second["prev_hash"] == first["hash"]
        # get_all() is newest-first
        assert verify_chain(list(reversed(store.get_all())))["valid"] is True

    def test_chains_onto_genesis_after_legacy_unhashed_entry(self, tmp_path):
        """A store loaded with pre-existing data recorded before this feature shipped
        (hash="" from the _load() fallback) must chain the next record() onto
        GENESIS_HASH, not onto the empty string."""
        store = RunHistoryStore(data_dir=str(tmp_path))
        store._entries.appendleft({
            "id": 1, "tool": "legacy", "endpoint": "", "params": {}, "session_id": "",
            "stdout": "", "stderr": "", "return_code": 0, "success": True,
            "timed_out": False, "partial_results": False, "execution_time": 0.0,
            "timestamp": "", "prev_hash": "", "hash": "",
        })
        chained = store.record(tool="nmap", endpoint="/e1", params={}, result={"stdout": "a"})
        assert chained["prev_hash"] == GENESIS_HASH

    def test_hash_survives_reload(self, tmp_path):
        store = RunHistoryStore(data_dir=str(tmp_path))
        chained = store.record(tool="nmap", endpoint="/e1", params={}, result={"stdout": "a"})

        reloaded = RunHistoryStore(data_dir=str(tmp_path))
        entries = reloaded.get_all()
        assert len(entries) == 1
        assert entries[0]["hash"] == chained["hash"]
        assert entries[0]["prev_hash"] == chained["prev_hash"]

    def test_covers_sessionless_runs_too(self, tmp_path):
        """A run with no session_id still gets chained and is findable by hash —
        the whole point of anchoring the chain in RunHistoryStore, not per-session run_log."""
        store = RunHistoryStore(data_dir=str(tmp_path))
        chained = store.record(tool="nmap", endpoint="/e1", params={}, result={"stdout": "a"}, session_id=None)
        assert chained["session_id"] == ""
        found = find_run_by_hash(store.get_all(), chained["hash"])
        assert found is not None
        assert found["session_id"] == ""


# ---------------------------------------------------------------------------
# T-9: a Jev web run (web_run_goal) lands in the same tamper-evident chain,
# and web_get_evidence exposes that entry's hash/prev_hash + trace + screenshots.
# ---------------------------------------------------------------------------

def _jev_run_goal_response():
    """A successful Jev /run_goal response: the compressed subgoal contract (T-2)
    with the run identity fields."""
    return {
        "run_id": "jev-t9-0001",
        "status": "done",
        "session_id": "sess_t9",
        "elapsed_ms": 7100,
        "error": None,
        "verified": True,
        "summary": "DONE on 'obtain the flag' after 2 actions: TYPE_TEXT 1, CLICK 7.",
        "extracted": {"reflected_text": "flag{t9}", "final_url": "https://range.invalid/flag", "forms_seen": 2},
        "budget": {"actions_used": 2, "decisions_used": 3, "elapsed_ms": 7100},
        "evidence_hash": "sha256:" + "a" * 64,
        "attack_tactic": "Initial Access",
        "blocked_reason": None,
    }


def _jev_get_evidence_response():
    """The full evidence store record Jev's /get_evidence/{run_id} returns:
    trace (history) + snapshot + screenshots — the pieces that deliberately
    never travel in the compressed subgoal response (T-2)."""
    return {
        "run_id": "jev-t9-0001",
        "session_id": "sess_t9",
        "url": "https://range.invalid/login",
        "goal": "obtain the flag",
        "status": "done",
        "error": None,
        "elapsed_ms": 7100,
        "history": [
            {"step": 1, "action": "User name", "operation": "TYPE_TEXT", "target": "1", "url": "https://range.invalid/login"},
            {"step": 2, "action": "Login", "operation": "CLICK", "target": "7", "url": "https://range.invalid/flag"},
        ],
        "snapshot": {"url": "https://range.invalid/flag", "title": "Flag", "text": "flag{t9}", "elements": []},
        "evidence_hash": "sha256:" + "a" * 64,
        "screenshots": [
            {"index": 0, "step": None, "url": "https://range.invalid/login", "data_b64": "aW1hZ2U="},
            {"index": 1, "step": 2, "url": "https://range.invalid/flag", "data_b64": "aW1hZ2U="},
        ],
        "max_actions": 40,
        "max_decisions": 80,
        "created_at": 1234567890.0,
    }


@pytest.fixture
def web_client(monkeypatch, tmp_path):
    """The real Flask app with a scratch RunHistoryStore (so the test neither
    reads nor writes the shared run_history.json) and the Jev service calls
    monkey-patched (offline)."""
    store = RunHistoryStore(data_dir=str(tmp_path / "data"))
    monkeypatch.setattr(singletons, "run_history", store)
    monkeypatch.setattr(nyxstrike_server, "run_history", store)
    monkeypatch.setenv("JEV_URL", "http://jev.test:8765")
    fake = MagicMock()
    fake.post.return_value = MagicMock(status_code=200, text="", json=lambda: _jev_run_goal_response())
    fake.get.return_value = MagicMock(status_code=200, text="", json=lambda: _jev_get_evidence_response())
    monkeypatch.setattr(web_interaction, "_requests", fake)
    nyxstrike_server.app.config["TESTING"] = True
    with nyxstrike_server.app.test_client() as c:
        yield c, store, fake


class TestWebRunInEvidenceChain:
    """T-9 acceptance: after a web_run_goal, run_history holds a chained entry
    whose hash/prev_hash verify_chain validates, and web_get_evidence exposes
    that hash + the trace + the screenshots."""

    def test_web_run_goal_creates_chained_entry(self, web_client):
        client, store, _fake = web_client
        resp = client.post(
            "/api/tools/web_run_goal",
            json={
                "url": "https://range.invalid/login",
                "goal": "obtain the flag",
                "session_id": "sess_t9",
                "scope_allowlist": ["range.invalid"],
            },
        )
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data["success"] is True
        assert data["return_code"] == 0
        # stdout carries summary + extracted (the contract fields the task asks for)
        assert "DONE on 'obtain the flag'" in data["stdout"]
        assert "flag{t9}" in data["stdout"]
        assert "run_id=jev-t9-0001" in data["stdout"]
        assert data["stderr"] == ""

        entries = store.get_all()
        assert len(entries) == 1, "web_run_goal must land exactly one entry in run_history"
        entry = entries[0]
        assert entry["tool"] == "web_run_goal"
        assert entry["endpoint"] == "/api/tools/web_run_goal"
        assert entry["session_id"] == "sess_t9"
        # Chained: prev_hash is the genesis of this fresh store, hash self-consistent.
        assert entry["prev_hash"] == GENESIS_HASH
        assert entry["hash"] == compute_hash(entry, entry["prev_hash"])
        # The Jev run id is inside the hashed content (stdout is a payload field).
        assert "jev-t9-0001" in entry["stdout"]

    def test_verify_chain_validates_the_web_entry(self, web_client):
        client, store, _fake = web_client
        client.post(
            "/api/tools/web_run_goal",
            json={"url": "https://range.invalid/login", "goal": "g", "session_id": "sess_t9"},
        )
        # Chain containing the web entry, oldest-first.
        result = verify_chain(list(reversed(store.get_all())))
        assert result["valid"] is True
        assert result["verified_runs"] == 1
        assert result["broken_at_index"] is None

    def test_web_run_chains_after_a_prior_tool_run(self, web_client):
        """A non-web run followed by a web run: the web entry's prev_hash must be
        the earlier entry's hash, and the whole chain must still verify."""
        client, store, _fake = web_client
        first = store.record(tool="nmap", endpoint="/api/tools/nmap", params={}, result={"stdout": "open 22"})
        client.post(
            "/api/tools/web_run_goal",
            json={"url": "https://range.invalid/login", "goal": "g", "session_id": "sess_t9"},
        )
        web_entry = store.get_all()[0]
        assert web_entry["tool"] == "web_run_goal"
        assert web_entry["prev_hash"] == first["hash"]
        assert verify_chain(list(reversed(store.get_all())))["valid"] is True
        assert find_run_by_hash(store.get_all(), first["hash"]) is not None

    def test_web_get_evidence_exposes_hash_prev_hash_trace_and_screenshots(self, web_client):
        client, store, _fake = web_client
        client.post(
            "/api/tools/web_run_goal",
            json={
                "url": "https://range.invalid/login",
                "goal": "obtain the flag",
                "session_id": "sess_t9",
                "scope_allowlist": ["range.invalid"],
            },
        )
        entry = store.get_all()[0]

        resp = client.get("/api/tools/web_get_evidence", query_string={"run_id": "jev-t9-0001"})
        assert resp.status_code == 200, resp.data
        data = resp.get_json()
        assert data["success"] is True
        assert data["return_code"] == 0
        # The chained entry's hash/prev_hash are exposed top-level in the response.
        assert data["hash"] == entry["hash"]
        assert data["prev_hash"] == entry["prev_hash"]
        # The full trace travels here, not in the compressed subgoal response.
        assert [h["operation"] for h in data["trace"]] == ["TYPE_TEXT", "CLICK"]
        assert data["trace"][1]["url"] == "https://range.invalid/flag"
        # The screenshots travel here too.
        assert len(data["screenshots"]) == 2
        assert data["screenshots"][1]["url"] == "https://range.invalid/flag"
        # The Jev-side evidence digest is still there, distinct from the chain hash.
        assert data["evidence_hash"] == "sha256:" + "a" * 64
        # stdout is self-describing (for run_history/session_flow capture).
        assert "hash=" in data["stdout"] and "trace=2 actions" in data["stdout"]

    def test_web_get_evidence_missing_entry_reported_not_forged(self, web_client):
        """With an empty run_history, web_get_evidence must still return the Jev
        evidence but report chain fields as None — never a fabricated hash."""
        client, store, _fake = web_client
        assert store.get_all() == []
        resp = client.get("/api/tools/web_get_evidence", query_string={"run_id": "jev-t9-0001"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["hash"] is None
        assert data["prev_hash"] is None
        assert data["evidence_found"] is False
        assert "chain" in data["stderr"] or "no matching" in data["stderr"].lower()
        # The trace still comes straight from the Jev evidence store.
        assert [h["operation"] for h in data["trace"]] == ["TYPE_TEXT", "CLICK"]

    def test_web_get_evidence_matches_by_stdout_run_id_not_session_only(self, web_client):
        """The lookup must key on the Jev run id (in the entry's stdout), not on
        session_id alone — two runs in the same session must not cross-link."""
        client, store, fake = web_client
        evidence_by_run = {
            "jev-t9-0001": _jev_get_evidence_response(),
        }
        second = dict(_jev_get_evidence_response())
        second["run_id"] = "jev-t9-0002"
        evidence_by_run["jev-t9-0002"] = second

        def fake_get(url, **kwargs):
            rid = url.rsplit("/", 1)[-1]
            return MagicMock(status_code=200, text="", json=lambda r=rid: evidence_by_run[r])

        fake.get.side_effect = fake_get
        client.post(
            "/api/tools/web_run_goal",
            json={"url": "https://range.invalid/login", "goal": "first goal", "session_id": "sess_t9"},
        )
        second_payload = dict(_jev_run_goal_response())
        second_payload["run_id"] = "jev-t9-0002"
        second_payload["summary"] = "DONE on 'first goal' after 2 actions: TYPE_TEXT 1, CLICK 7."
        fake.post.return_value = MagicMock(status_code=200, text="", json=lambda: second_payload)
        client.post(
            "/api/tools/web_run_goal",
            json={"url": "https://range.invalid/login", "goal": "first goal", "session_id": "sess_t9"},
        )

        entries = store.get_all()  # newest-first: [0002, 0001]
        assert [e["stdout"].split("run_id=")[1].split("\n")[0] for e in entries] == ["jev-t9-0002", "jev-t9-0001"]

        resp = client.get("/api/tools/web_get_evidence", query_string={"run_id": "jev-t9-0002"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["hash"] == entries[0]["hash"]  # the entry whose stdout names jev-t9-0002
        assert data["prev_hash"] == entries[1]["hash"]  # chained on the first run

        resp_first = client.get("/api/tools/web_get_evidence", query_string={"run_id": "jev-t9-0001"})
        first_data = resp_first.get_json()
        assert first_data["hash"] == entries[1]["hash"]  # NOT the newer entry's hash
