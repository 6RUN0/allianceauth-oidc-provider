"""
Cross-version test-matrix sessions.

Three off-default sessions that exercise the test suite against
Python/AA version combinations the dev environment does not pin:

* ``tests_matrix`` — every supported Python interpreter against the
  Alliance Auth 5.x *range* (``allianceauth>=5,<6``), off-lock. This is
  the "does the suite still pass across the whole AA-5 window" probe —
  deliberately NOT the lock pin, so a new AA 5.x point release that
  breaks the suite is caught here rather than only after the lock moves.
* ``tests_aa4`` — Alliance Auth 4.x / Django 4.x range, off-lock,
  across the AA-4-compatible Python subset.
* ``tests_compat`` — ad-hoc compatibility probe against an arbitrary
  ``allianceauth`` pin supplied via the ``AA_PIN`` env var (e.g. a beta
  / RC release, a point release between the two pinned matrices, or a
  downgrade test).

All three render their command through the pure builder in
``_nox/_testing.py`` (``TestPlan`` -> ``build_django_test_argv`` /
``build_canary_argv``) and provision via ``uv run --python X
--isolated`` — ``venv_backend="none"`` because uv, not nox, owns the
per-interpreter environment. ``@nox.parametrize`` fans each session out
one cell per interpreter (session IDs like
``tests_aa4(python_version='3.12')``) so the CI matrix can invoke a
single cell and a failure points at the responsible interpreter.
Imported from ``noxfile.py`` for registration side effects —
``@nox.session`` registers globally at import time.

CI division of labour: the lock-driven ``tests`` session stays the
per-PR gate (it pins the exact versions users get from ``uv.lock``);
``tests_matrix`` (the AA-5 *range*) is a local / scheduled probe and is
intentionally NOT wired into the per-PR matrix, so CI never stops
testing the locked versions.
"""

from __future__ import annotations

import os

import nox

from _nox._testing import (
    TestPlan,
    build_canary_argv,
    build_django_test_argv,
)
from _nox.shared import (
    PYTHON_VERSIONS,
    PYTHON_VERSIONS_AA4,
    TEST_RUNTIME_DEPS,
    test_env,
)

# Force single-process across the whole matrix. Django's parallel runner
# serialises test results through a multiprocessing pool whose machinery
# cannot transport ``traceback`` objects between workers (most visible on
# Python 3.10; PEP 657 frame-handling rework in 3.11 narrowed but did not
# eliminate it). Any failing test then crashes the pool with ``TypeError:
# cannot ... traceback object`` and hides the real diagnostics. These
# sessions exist to *find* per-version regressions, so failure clarity
# outweighs the per-CPU speedup. The default ``tests`` session keeps
# ``--parallel=auto`` (locked stack, expected green).
_MATRIX_PARALLEL = "1"


@nox.session(venv_backend="none")
@nox.parametrize("python_version", PYTHON_VERSIONS)
def tests_matrix(session: nox.Session, python_version: str) -> None:
    """
    Run the Django test suite on every supported Python against AA 5.x.

    Off-lock by design: ``uv run --group aa5`` resolves the
    ``allianceauth>=5,<6`` *range* fresh in an isolated per-interpreter
    venv instead of the single version the lock froze. Catches both
    Python-version regressions (typing-extension semantics, deprecated
    stdlib modules, native-wheel gaps) and AA-5 point-release breakage.
    Pass extra args to ``django test`` after ``--`` like with ``tests``.
    """
    plan = TestPlan(
        python=python_version,
        aa_group="aa5",
        extra_deps=tuple(TEST_RUNTIME_DEPS),
        parallel=_MATRIX_PARALLEL,
        labels=tuple(session.posargs),
    )
    _run_offlock(session, plan)


@nox.session(venv_backend="none")
@nox.parametrize("python_version", PYTHON_VERSIONS_AA4)
def tests_aa4(session: nox.Session, python_version: str) -> None:
    """
    Run the Django test suite against the Alliance Auth 4.x stack.

    The default ``tests`` session runs against whatever AA / Django the
    lock resolves to (AA 5.x today). ``tests_aa4`` provisions an
    off-lock venv with the ``aa4`` group (``allianceauth>=4,<5`` +
    ``django<5``) so the older stack stays exercised locally and in CI
    even as the dev environment moves forward.

    Parametrised across ``PYTHON_VERSIONS_AA4`` (3.10 / 3.11 / 3.12) —
    AA 4.13.x's ``requires-python <3.13`` excludes Python 3.13 from this
    dimension.
    """
    plan = TestPlan(
        python=python_version,
        aa_group="aa4",
        extra_deps=tuple(TEST_RUNTIME_DEPS),
        parallel=_MATRIX_PARALLEL,
        labels=tuple(session.posargs),
    )
    _run_offlock(session, plan)


@nox.session(venv_backend="none")
@nox.parametrize("python_version", PYTHON_VERSIONS)
def tests_compat(session: nox.Session, python_version: str) -> None:
    """
    Run the test suite against an arbitrary ``allianceauth`` pin.

    The pin is taken from the ``AA_PIN`` env var (a PEP 508 requirement
    string), e.g. ``AA_PIN='allianceauth==5.1rc1'`` or
    ``AA_PIN='allianceauth>=5.0,<5.1'``. ``--with`` injects the pin into
    an off-lock venv; the AA major-version groups are intentionally not
    selected so the override is the sole AA pin.

    Use this for one-off probes the standard ``tests`` (lock-driven) and
    ``tests_aa4`` (``aa4`` group) matrices cannot reach: AA beta / RC
    builds, downgrade tests, or compatibility checks between the two
    pinned matrices (e.g. an AA 5.0.x -> 5.1.x bridge).

    Failure mode: if ``AA_PIN`` is unset the session errors out with a
    hint rather than silently degrading into the default ``tests``
    behaviour.
    """
    aa_pin = os.environ.get("AA_PIN", "").strip()
    if not aa_pin:
        session.error(
            "tests_compat requires AA_PIN to be set to a PEP 508 "
            "requirement string for ``allianceauth``. Examples:\n"
            "  AA_PIN='allianceauth==5.1rc1' uv run nox -s tests_compat\n"
            "  AA_PIN='allianceauth>=5.0,<5.1' uv run nox -s tests_compat"
        )

    plan = TestPlan(
        python=python_version,
        pin=aa_pin,
        extra_deps=tuple(TEST_RUNTIME_DEPS),
        parallel=_MATRIX_PARALLEL,
        labels=tuple(session.posargs),
    )
    _run_offlock(session, plan)


def _run_offlock(session: nox.Session, plan: TestPlan) -> None:
    """
    Run the import canary then the Django suite for an off-lock plan.

    The canary (``_nox/_canary_imports.py``) imports every test module
    once before handing off to the Django runner, so a test module that
    top-level-imports a package the off-lock venv does not provide is
    reported as a list of broken module names rather than a
    unittest-loader traceback halfway through discovery. ``external=True``
    because ``uv`` lives outside the (``none``-backend) session venv.
    """
    env = test_env(session)
    session.run(*build_canary_argv(plan), env=env, external=True)
    session.run(*build_django_test_argv(plan), env=env, external=True)
