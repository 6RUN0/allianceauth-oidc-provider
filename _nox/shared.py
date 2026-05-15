"""
Shared constants and helpers for nox sessions split across modules.

The root ``noxfile.py`` historically owned all sessions plus a small
collection of constants and helpers. As session modules were split
out into ``_nox/*`` (see ``_nox.mutation``, ``_nox.matrix``,
``_nox.conformance``) each submodule needed access to the same
runtime config: the test settings module name, the base ``django
test`` argv, the supported Python interpreter matrix, and the env
builder. Putting them here keeps the canonical definition in one
place — submodules and ``noxfile.py`` import from this module rather
than duplicating the values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # ``nox`` is only referenced as a type annotation (``nox.Session``)
    # in this module; with PEP 563 / ``from __future__ import
    # annotations`` the symbol is never resolved at runtime, so a
    # ``TYPE_CHECKING``-guarded import keeps the runtime import graph
    # minimal and satisfies ruff TC002.
    import nox

# Test runner config:
# - tests.test_settingsAA4 boots Alliance Auth and (via tests/_fakeredis.py)
#   monkey-patches django_redis with a fakeredis shim. Set AA_USE_FAKE_REDIS=0
#   to skip the patch and run against a real Redis. The settings module is
#   shared between the AA 4.x (``tests_aa4`` session) and AA 5.x (default
#   ``tests`` session) runs — its ``STORAGES`` override neutralises Django
#   5.x's ManifestStaticFilesStorage default, which would otherwise demand a
#   ``staticfiles.json`` produced by ``collectstatic``.
TEST_SETTINGS = "tests.test_settingsAA4"

# Options-only base — the positional `tests` label is appended last
# inside the session so that subset labels passed via `-- ...` end up
# AFTER `--parallel=auto`, where Django's argparse accepts them.
TEST_ARGS_BASE = [
    f"--settings={TEST_SETTINGS}",
    "-v",
    "2",
    "--debug-mode",
]

# Per-version Python interpreters used by ``tests_matrix``. Mirrors
# ``pyproject.toml::requires-python = ">=3.10,<3.14"``: 3.10 is the
# floor (mypy / basedpyright also pin to it), 3.13 is the most recent
# tested. Update this list when bumping ``requires-python`` upper
# bound.
PYTHON_VERSIONS = ["3.10", "3.11", "3.12", "3.13"]

# Per-version Python interpreters used by ``tests_aa4``. AA 4.13.x
# declares ``requires-python = >=3.8,<3.13`` upstream — Python 3.13 is
# therefore not a valid combination and would either fail to install
# AA<5 or silently resolve to an older AA the suite never targeted.
# Drop the upper-bound entry from ``PYTHON_VERSIONS`` so the matrix
# only schedules runs that can actually succeed.
PYTHON_VERSIONS_AA4 = ["3.10", "3.11", "3.12"]

# Third-party runtime dependencies the test suite imports directly,
# independent of the AA / Django versions resolved in the lock. Used by
# ``tests_aa4`` (and any future ``tests_aaN``) to provision a venv
# off-lock against an older AA stack. Keep in sync with the imports under
# ``tests/`` — anything else needed for the suite to import lives in
# ``[dependency-groups].dev`` in ``pyproject.toml``.
TEST_RUNTIME_DEPS = [
    "fakeredis>=2.33",
    "parameterized>=0.9",
    "jwcrypto",
    "requests>=2.32",
    # tests/test_metrics.py top-level-imports ``prometheus_client`` to
    # measure the real Counter / Histogram / Gauge side effects from
    # allianceauth_oidc._metrics; without the dep, AA4 test discovery
    # crashes with ``ModuleNotFoundError`` before any test runs. The
    # ``[metrics]`` extra is not pulled in by ``-e .``, and AA 4.13.x
    # does not list ``django-prometheus`` transitively, so the AA4
    # matrix must provision it the same way the dev / AA5 environments
    # already do (see ``[dependency-groups].dev`` in pyproject.toml).
    "django-prometheus>=2.3",
]


def resolve_test_labels(posargs: tuple[str, ...]) -> list[str]:
    """
    Decide which positional test labels to run.

    Honour any user-supplied label (e.g. ``tests.test_signals``); if none is
    given, default to running the whole ``tests`` package. Django argparse
    rejects positional args that follow some option flags, so the caller must
    pass these labels at the very end of the command — that is what every nox
    session does.
    """
    has_label = any(not arg.startswith("-") for arg in posargs)
    return list(posargs) if has_label else ["tests", *posargs]


def test_env(session: nox.Session) -> dict[str, str]:
    """
    Build the environment for test sessions.

    Honours an explicit AA_USE_FAKE_REDIS in the caller's environment so
    operators can flip to a real Redis without editing the noxfile.
    """
    return {
        "DJANGO_SETTINGS_MODULE": TEST_SETTINGS,
        "AA_USE_FAKE_REDIS": session.env.get("AA_USE_FAKE_REDIS", "1"),
    }
