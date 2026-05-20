"""
Cross-version test-matrix sessions.

Three off-default sessions that exercise the test suite against
Python/AA version combinations the dev environment does not pin:

* ``tests_matrix`` — every supported Python interpreter against the
  locked AA 5.x / Django 5.x stack.
* ``tests_aa4`` — Alliance Auth 4.x / Django 4.x stack, off-lock,
  across the AA-4-compatible Python subset.
* ``tests_compat`` — ad-hoc compatibility probe against an arbitrary
  ``allianceauth`` pin supplied via the ``AA_PIN`` env var (e.g. a
  beta / RC release, a point release between the two pinned matrices,
  or a downgrade test).

All three use ``venv_backend="uv"`` so nox provisions a per-interpreter
isolated venv (vs the default ``none`` backend that re-uses the
active venv). Imported from ``noxfile.py`` for session registration
side effects — ``@nox.session`` registers globally at import time.
"""

from __future__ import annotations

import os

import nox

from _nox.shared import (
    PYTHON_VERSIONS,
    PYTHON_VERSIONS_AA4,
    TEST_ARGS_BASE,
    TEST_RUNTIME_DEPS,
    resolve_test_labels,
    test_env,
)


@nox.session(python=PYTHON_VERSIONS, venv_backend="uv")
def tests_matrix(session: nox.Session) -> None:
    """
    Run the Django test suite against every supported Python version.

    Spawns a per-interpreter uv-managed venv (vs the default ``none``
    backend that re-uses the active venv) and ``uv sync``s into it
    before running ``django test``. Slower than ``tests`` but catches
    version-specific regressions — typing-extension semantics,
    deprecated stdlib modules, native wheel availability gaps. Pass
    extra args to ``django test`` after ``--`` like with ``tests``.
    """
    session.run_install(
        "uv",
        "sync",
        f"--python={session.python}",
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
    # Force single-process for the entire matrix. Django's parallel
    # runner serialises test results through a multiprocessing pool
    # whose machinery cannot transport ``traceback`` objects between
    # workers (the issue is most visible on Python 3.10 — PEP 657
    # frame-handling rework in 3.11 narrowed it but did not eliminate
    # it). Any failing test therefore crashes the pool with
    # ``TypeError: cannot ... traceback object`` and hides the real
    # diagnostics. ``tests_matrix`` is the "find a per-version
    # regression" session — failure clarity outweighs the per-CPU
    # speedup here. The default ``tests`` session keeps
    # ``--parallel=auto`` (locked AA 5.x stack, expected green).
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=1",
        *resolve_test_labels(tuple(session.posargs)),
        env=test_env(session),
    )


@nox.session(python=PYTHON_VERSIONS_AA4, venv_backend="uv")
def tests_aa4(session: nox.Session) -> None:
    """
    Run the Django test suite against the Alliance Auth 4.x stack.

    The default ``tests`` session runs against whatever AA / Django
    versions ``uv.lock`` resolves to — which today is AA 5.0.1 + Django
    5.2.x. ``tests_aa4`` provisions a parallel venv off-lock with
    ``allianceauth<5`` + ``django<5`` so the older stack stays exercised
    locally and in CI even though the dev environment moves forward.

    Parametrised across ``PYTHON_VERSIONS_AA4`` (3.10 / 3.11 / 3.12) —
    AA 4.13.x's ``requires-python <3.13`` constraint excludes Python 3.13
    from this matrix dimension.

    Off-lock by design: ``uv pip install`` (not ``uv sync``) is used so
    the AA-version constraint from ``[dependency-groups].aa4`` (PEP 735,
    declared in ``pyproject.toml``) can intersect with the package's
    ``allianceauth>=4,<6`` contract and resolve to AA 4.x. Test
    dependencies that aren't imported transitively via AA are listed in
    ``TEST_RUNTIME_DEPS`` so they don't have to be discovered via
    ``[dependency-groups].dev``.
    """
    session.run_install(
        "uv",
        "pip",
        "install",
        "-e",
        ".",
        "--group",
        "aa4",
        *TEST_RUNTIME_DEPS,
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
    # Canary: import every tests/test_*.py once before handing off to
    # the Django runner. Catches the TEST_RUNTIME_DEPS-drift class of
    # bug (cosmic_ray and django-prometheus both surfaced this way)
    # cheaply — failure here is reported as a list of broken module
    # names, not a unittest-loader traceback halfway through discovery.
    session.run(
        "python",
        "_nox/_canary_imports.py",
        env=test_env(session),
    )
    # AA 4.x ships Django 4.2's parallel runner which serialises test
    # results through the multiprocessing pool the same way 3.10 does
    # — any failing test crashes the pool with the
    # ``cannot serialise 'traceback' object`` error rather than the
    # actual diagnostics. Forcing single-process here makes failures
    # legible across the whole AA4 Python matrix.
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=1",
        *resolve_test_labels(tuple(session.posargs)),
        env=test_env(session),
    )


@nox.session(python=PYTHON_VERSIONS, venv_backend="uv")
def tests_compat(session: nox.Session) -> None:
    """
    Run the test suite against an arbitrary ``allianceauth`` pin.

    The pin is taken from the ``AA_PIN`` env var (a PEP 508
    requirement string), e.g. ``AA_PIN='allianceauth==5.1rc1'`` or
    ``AA_PIN='allianceauth>=5.0,<5.1'``. ``--with`` injects the pin
    into an off-lock venv built around the ``dev`` group; the AA
    major-version groups (``aa4`` / ``aa5``) are intentionally not
    selected so the override is the sole AA pin.

    Use this for one-off probes the standard ``tests`` (lock-driven)
    and ``tests_aa4`` (PEP 735 ``aa4`` group) matrices cannot reach:
    AA beta / RC builds, downgrade tests against an older point
    release, or compatibility checks between the two pinned matrices
    (e.g. an AA 5.0.x → 5.1.x bridge).

    Failure mode: if ``AA_PIN`` is unset the session errors out with
    a hint rather than silently degrading into the default ``tests``
    behaviour. The pattern is borrowed from ``aa_discord_audit``'s
    ``tests_compat``.
    """
    aa_pin = os.environ.get("AA_PIN", "").strip()
    if not aa_pin:
        session.error(
            "tests_compat requires AA_PIN to be set to a PEP 508 "
            "requirement string for ``allianceauth``. Examples:\n"
            "  AA_PIN='allianceauth==5.1rc1' uv run nox -s tests_compat\n"
            "  AA_PIN='allianceauth>=5.0,<5.1' uv run nox -s tests_compat"
        )

    session.run_install(
        "uv",
        "pip",
        "install",
        "-e",
        ".",
        "--group",
        "dev",
        "--with",
        aa_pin,
        *TEST_RUNTIME_DEPS,
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
    session.run(
        "python",
        "_nox/_canary_imports.py",
        env=test_env(session),
    )
    # ``--parallel=1`` for the same Django-multiprocessing-pool
    # rationale documented above (the parallel runner cannot
    # serialise traceback objects across forks). Failure clarity
    # outweighs the per-CPU speedup on compatibility probes.
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=1",
        *resolve_test_labels(tuple(session.posargs)),
        env=test_env(session),
    )
