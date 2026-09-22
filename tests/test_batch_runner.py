"""Unit tests for the evaluation harness ``batch_runner`` (TFM·C3, Pilar 5).

The harness is the "arné de evaluación" (cap. 10 / TFM design "Capa D"):
it runs a configuration ``k`` times and reports ``Pass@k``. The two things
this task must deliver, and that these tests pin, are:

  1. Difficulty levels (Level-0 / Level-1 / Level-2) as a PARAMETER of the
     audit, grounded in cap. 2 (L394-398) and cap. 3 — NOT a separate
     profile, and never invented.
  2. ``Pass@k`` aggregated from k trial verdicts — consumed from the C2
     runtime-evidence verifier (``hades-tfm/evidences/scripts/
     verify_runtime_evidence.py``). The metric is NEVER re-invented: these
     tests anchor ``batch_runner``'s defaults against the *real* C2 module,
     so the two can never diverge.

No live cluster, no real tools: trials are produced by an injected
``trial_runner`` that yields runtime evidence. Success is decided by the
injected verifier (default: C2's literal-canary rule), never self-reported.
"""

import importlib
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Make the C2 verifier importable so we can anchor against it (no reinvention).
# hades-tfm is a sibling repo under the same "clones" parent as nyxstrike.
# ---------------------------------------------------------------------------
_CLONES = Path(__file__).resolve().parents[2]            # .../repos/clones
_C2_DIR = _CLONES / "hades-tfm" / "evidences" / "scripts"
if _C2_DIR.is_dir() and str(_C2_DIR) not in sys.path:
    sys.path.insert(0, str(_C2_DIR))

c2 = importlib.import_module("verify_runtime_evidence")


# ---------------------------------------------------------------------------
# Fakes — mirror the real APIs without any network / tool execution
# ---------------------------------------------------------------------------
def _mk_trial_runner(evidences):
    """A trial runner that returns the i-th evidence dict (one per trial)."""
    def _runner(config, trial_index):
        return evidences[trial_index]
    return _runner


# ---------------------------------------------------------------------------
# C3 — Difficulty levels as a PARAMETER (cap. 2 L394-398 / cap. 3 / wiki)
# ---------------------------------------------------------------------------
def test_difficulty_default_is_level0():
    from backend.server_core.evaluation.batch_runner import difficulty_level
    d = difficulty_level()
    assert d.name == "Level-0"
    assert d.is_starting_point is True


def test_difficulty_levels_exist_and_are_not_invented():
    from backend.server_core.evaluation.batch_runner import (
        DifficultyLevel,
        difficulty_level,
    )
    for name in ("Level-0", "Level-1", "Level-2"):
        assert difficulty_level(name).name == name
    # A fourth level would be a fabrication -> must be refused.
    with pytest.raises(ValueError):
        difficulty_level("Level-3")
    with pytest.raises(ValueError):
        difficulty_level("Level-X")


def test_level0_is_only_ip_url():
    from backend.server_core.evaluation.batch_runner import difficulty_level
    d = difficulty_level("Level-0")
    info = d.provided_information.lower()
    assert "ip" in info and "url" in info


def test_difficulty_information_is_increasing():
    # cap. 2 L394-398: URL/IP -> +URLs/topology -> +vuln type/CVE.
    from backend.server_core.evaluation.batch_runner import difficulty_level
    lvl0 = difficulty_level("Level-0")
    lvl1 = difficulty_level("Level-1")
    lvl2 = difficulty_level("Level-2")
    # Each higher level carries at least everything the lower one does, plus
    # more; Level-2 must mention the CVE/vuln-type the lower levels omit.
    assert lvl2.provided_information.lower() > lvl1.provided_information.lower()
    assert "cve" in lvl2.provided_information.lower()
    assert "cve" not in lvl0.provided_information.lower()


# ---------------------------------------------------------------------------
# C3 — Pass@k aggregated from k trial verdicts (C2 contract, NOT re-invented)
# ---------------------------------------------------------------------------
def _run_and_collect(config, k, evidences, **kw):
    from backend.server_core.evaluation.batch_runner import run_batch
    result = run_batch(config, k, trial_runner=_mk_trial_runner(evidences), **kw)
    return result


def test_batch_runs_k_trials():
    evidences = [{"tmp": c2.default_canaries()["tmp"]} for _ in range(3)]
    result = _run_and_collect({"model": "m"}, 3, evidences)
    assert len(result.trials) == 3
    assert result.pass_at_k["total"] == 3


def test_pass_at_1_is_fraction_of_successful_trials():
    # 2 of 3 trials confirm the /tmp canary -> 2/3.
    canary = c2.default_canaries()["tmp"]
    evidences = [
        {"tmp": canary},          # success
        {"tmp": "no canary here"},  # fail
        {"tmp": canary},          # success
    ]
    result = _run_and_collect({"model": "m"}, 3, evidences)
    assert result.pass_at_k["successes"] == 2
    assert result.pass_at_1 == pytest.approx(2 / 3)


def test_no_fabrication_all_fail_is_zero():
    # No canary in any trial -> zero successes -> pass_at_1 == 0.0 (not >0).
    evidences = [{"tmp": "x"}, {"root": "y"}, {"sqli": "z"}]
    result = _run_and_collect({"model": "m"}, 3, evidences)
    assert result.pass_at_k["successes"] == 0
    assert result.pass_at_1 == 0.0


def test_empty_batch_is_zero_not_divide_by_zero():
    result = _run_and_collect({"model": "m"}, 0, [])
    assert result.pass_at_k["total"] == 0
    assert result.pass_at_1 == 0.0


def test_default_verifier_uses_literal_canary_no_fabrication():
    # The default verifier must decide success by the LITERAL canary in the
    # evidence (C2 rule), not by any self-reported "pass".
    from backend.server_core.evaluation.batch_runner import (
        _default_verifier,
        _default_aggregator,
    )
    canaries = c2.default_canaries()
    good = _default_verifier({"tmp": canaries["tmp"]}, canaries)
    assert good["success"] is True
    assert good["level"] == "user"
    bad = _default_verifier({"tmp": "nothing"}, canaries)
    assert bad["success"] is False
    assert bad["level"] == "none"
    # Aggregator on the empty set must not divide by zero.
    assert _default_aggregator([])["pass_at_1"] == 0.0


def test_defaults_match_real_c2_not_reinvented():
    """The whole point of C3: batch_runner's defaults reproduce C2's metric
    exactly, on the SAME verdicts. If C2 ever changes, this test breaks."""
    from backend.server_core.evaluation.batch_runner import (
        _default_verifier,
        _default_aggregator,
    )
    canaries = c2.default_canaries()
    # Build a spread of trials (mix of success / fail / different channels).
    evidences = [
        {"tmp": canaries["tmp"]},            # user
        {"root": canaries["root"]},          # root
        {"sqli": canaries["sqli"]},         # sqli
        {"tmp": "none", "root": "none"},     # fail
    ]
    verdicts = [_default_verifier(e, canaries) for e in evidences]
    mine = _default_aggregator(verdicts)
    theirs = c2.pass_at_k(verdicts)
    # Anchor against the REAL C2 pass_at_k: same total, successes, levels, and
    # same pass_at_1 (the fraction of successful runs). This is NOT a copy of
    # C2's source — it asserts behavioural equivalence against the live module.
    assert mine["total"] == theirs["total"]
    assert mine["successes"] == theirs["successes"]
    assert mine["levels"] == theirs["levels"]
    assert mine["pass_at_1"] == theirs["pass_at_1"]


def test_run_batch_aggregates_with_real_c2_pipeline():
    """End-to-end with the REAL C2 module: inject C2's verifier + aggregator
    and confirm run_batch reproduces C2's own verdicts and Pass@k — proving
    the pipeline composes with the C2 contract, not a re-invented copy."""
    from backend.server_core.evaluation.batch_runner import run_batch
    canaries = c2.default_canaries()
    # 3 trials: user-succ, fail, root-succ -> 2/3 successful.
    evidences = [
        {"tmp": canaries["tmp"]},
        {"tmp": "no canary here"},
        {"root": canaries["root"]},
    ]
    # Anchor: the same evidences through C2 directly.
    c2_verdicts = [c2.verify(e, canaries) for e in evidences]
    expected = c2.pass_at_k(c2_verdicts)

    result = run_batch(
        {"model": "m"},
        3,
        trial_runner=_mk_trial_runner(evidences),
        canaries=canaries,
        verifier=c2.verify,
        aggregator=c2.pass_at_k,
    )
    assert result.pass_at_k == expected
    assert result.pass_at_k["successes"] == 2
    assert result.pass_at_1 == pytest.approx(2 / 3)
