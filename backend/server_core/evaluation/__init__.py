"""Evaluation harness package for NyxStrike (Capa D of the TFM design).

This package hosts the evaluation harness that turns a single audit
configuration into a reproducible ``Pass@k`` result. It is the "arné de
evaluación" of cap. 10 / the TFM design (wiki ``diseno-arnes-ofensivo-
hades-nyxstrike.md`` "Capa D — Arné de evaluación: ``batch_runner`` para
``Pass@k``, niveles de dificultad como parámetro, verificador por
evidencia").

The module is intentionally dependency-injectable: a ``trial_runner``
(produces per-trial runtime evidence) and a ``verifier``/``aggregator``
(decides success and aggregates) can be supplied by the caller. The
defaults encode the CAGE-style contract from the C2 verifier
(``hades-tfm/evidences/scripts/verify_runtime_evidence.py``); the test
``tests/test_batch_runner.py`` anchors those defaults against the *real*
C2 module so the metric is never re-invented.
"""

from __future__ import annotations
