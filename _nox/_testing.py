"""
Pure argv builder for the Django-test nox session family.

Separates *what command to run* (a declarative :class:`TestPlan`) from
*how nox runs it*, so the token sequence each ``tests*`` session emits
can be unit-tested without a nox runtime or a booted Django (see
``tests/unit/test_nox_testing.py``).

The argv order is load-bearing and the builder encodes it once:

* ``uv`` consumes its own flags (``--python``, ``--group``, ``--with``,
  ``--isolated``) before the ``python`` it execs, so every uv flag must
  precede the ``python -m django test`` tail.
* The AA-stack ``--group`` / ``--with`` selectors must precede
  ``--isolated`` — ``--isolated`` closes uv's own option list.
* Django parses positional test labels only at the very end, after
  ``--parallel=...``; :func:`resolve_test_labels` keeps a user-supplied
  ``-- tests.foo`` subset there.

Three provisioning modes, keyed off the :class:`TestPlan` fields:

* in-venv (``python is None``) — no uv prefix; runs against whatever
  the active lock-driven venv resolved (AA 5.x today). Backs the
  default ``tests`` session.
* AA-group off-lock (``aa_group`` set) — ``uv run --python X
  --no-default-groups --group <aaN> --isolated`` provisions a fresh
  interpreter with the AA major-line *range* (not the lock pin), so
  the matrix exercises the supported AA window rather than the one
  version the lock happened to freeze.
* pin off-lock (``pin`` set) — ``--with <pep508>`` injects an arbitrary
  ``allianceauth`` requirement for ad-hoc compatibility probes.

Off-lock venvs are deliberately light: they carry the AA stack plus the
suite's direct third-party imports (the ``test-runtime`` dependency
group, threaded through ``extra_groups``) but NOT the heavyweight
``dev`` tooling (cosmic-ray, basedpyright, ...) the suite never
imports. Runtime deps ride a *group* rather than ``--with`` because a
``uv run --with`` overlay resolves outside the project's constraints —
``--with django-prometheus`` used to pull an unconstrained Django 5.2
into the overlay, shadowing the ``aa4`` group's Django 4.2 base venv
on ``sys.path``. ``extra_deps`` (``--with``) remains for per-session
extras that pull no Django of their own (e.g. ``mysqlclient``).
"""

from __future__ import annotations

from dataclasses import dataclass

from _nox.shared import (
    PYTHON_VERSIONS,
    TEST_ARGS_BASE,
    resolve_test_labels,
)

__all__ = [
    "MARIADB_SMOKE_PYTHON",
    "TEST_ARGS_BASE",
    "TestPlan",
    "build_canary_argv",
    "build_django_test_argv",
    "resolve_test_labels",
]

# Single-Python smoke slot for DB-backed matrices (e.g. MariaDB): the
# DB axis runs on one interpreter so CI cost stays linear in the
# DB/AA dimension rather than the full Python fan-out.
MARIADB_SMOKE_PYTHON = PYTHON_VERSIONS[-1]


@dataclass(frozen=True)
class TestPlan:
    """
    Declarative spec for one ``django test`` invocation.

    ``python`` None selects the in-venv (lock-driven) mode; a version
    string selects an off-lock ``uv run`` mode. ``aa_group`` and ``pin``
    are mutually exclusive AA selectors (``pin`` wins if both are set).
    ``extra_groups`` are additional ``--group`` selectors resolved
    jointly with the AA group (Django-safe); ``extra_deps`` are
    off-lock ``--with`` overlay requirements and must not pull Django;
    ``parallel`` maps to ``--parallel=<value>``; ``labels`` are the raw
    posargs forwarded to :func:`resolve_test_labels`.
    """

    python: str | None = None
    aa_group: str | None = None
    pin: str | None = None
    extra_groups: tuple[str, ...] = ()
    extra_deps: tuple[str, ...] = ()
    parallel: str = "auto"
    labels: tuple[str, ...] = ()


def _uv_prefix(plan: TestPlan) -> list[str]:
    """Build the ``uv run`` prefix for ``plan`` (empty when in-venv)."""
    if plan.python is None:
        return []
    prefix = ["uv", "run", "--python", plan.python]
    # ``--no-default-groups`` makes the off-lock set explicit: only the
    # AA selector below (and any ``--with`` extras) are provisioned, not
    # whatever the project's default groups happen to be. Defensive
    # rather than load-bearing here — this project declares no
    # ``default-groups`` — but it pins the resolution intent so a future
    # ``default-groups`` cannot silently widen the matrix venvs.
    if plan.pin:
        prefix += ["--no-default-groups", "--with", plan.pin]
    elif plan.aa_group:
        prefix += ["--no-default-groups", "--group", plan.aa_group]
    for group in plan.extra_groups:
        prefix += ["--group", group]
    for dep in plan.extra_deps:
        prefix += ["--with", dep]
    prefix.append("--isolated")
    return prefix


def build_django_test_argv(plan: TestPlan) -> list[str]:
    """Render the full ``django test`` command for ``plan``."""
    return [
        *_uv_prefix(plan),
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        f"--parallel={plan.parallel}",
        *resolve_test_labels(plan.labels),
    ]


def build_canary_argv(plan: TestPlan) -> list[str]:
    """Render the import-canary command in ``plan``'s environment."""
    return [*_uv_prefix(plan), "python", "_nox/_canary_imports.py"]
