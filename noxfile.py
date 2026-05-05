"""
Nox sessions — run via ``uv run nox``.

Default (no args): lint + tests.

Examples::

    uv run nox                                     # default (lint + tests)
    uv run nox -s lint                             # pre-commit hooks
    uv run nox -s tests                            # Django test suite
    uv run nox -s tests -- tests.test_token        # subset of tests
    uv run nox -s tests -- --keepdb                # forward extra args
    uv run nox -s typecheck                        # mypy + basedpyright
    uv run nox -s coverage                         # tests + coverage reports
    uv run nox -s audit                            # pip-audit
    AA_USE_FAKE_REDIS=0 uv run nox -s tests        # run against real Redis
"""

from __future__ import annotations

import nox

nox.options.sessions = ["lint", "tests"]
# `none`: nox does not create its own venv; it runs sessions in the active
# environment. Combined with `uv sync --all-groups`, this keeps the toolchain
# definition in pyproject.toml + uv.lock.
nox.options.default_venv_backend = "none"

# Test runner config:
# - tests.test_settingsAA4 boots Alliance Auth and (via tests/_fakeredis.py)
#   monkey-patches django_redis with a fakeredis shim. Set AA_USE_FAKE_REDIS=0
#   to skip the patch and run against a real Redis.
# - --debug-mode disables ManifestStaticFilesStorage's manifest check, which
#   would otherwise fail because we don't run collectstatic in CI.
TEST_SETTINGS = "tests.test_settingsAA4"
TEST_ARGS = ["tests", f"--settings={TEST_SETTINGS}", "-v", "2", "--debug-mode"]


def _test_env(session: nox.Session) -> dict[str, str]:
    """
    Build the environment for test sessions.

    Honours an explicit AA_USE_FAKE_REDIS in the caller's environment so
    operators can flip to a real Redis without editing the noxfile.
    """
    return {
        "DJANGO_SETTINGS_MODULE": TEST_SETTINGS,
        "AA_USE_FAKE_REDIS": session.env.get("AA_USE_FAKE_REDIS", "1"),
    }


@nox.session
def lint(session: nox.Session) -> None:
    """Run all linters and formatters via pre-commit."""
    session.run("pre-commit", "run", "--all-files")


@nox.session
def tests(session: nox.Session) -> None:
    """Run the Django test suite."""
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS,
        *session.posargs,
        env=_test_env(session),
    )


@nox.session
def coverage(session: nox.Session) -> None:
    """Run tests under coverage and emit term/html/xml reports."""
    session.run(
        "coverage",
        "run",
        "--source=allianceauth_oidc",
        "-m",
        "django",
        "test",
        *TEST_ARGS,
        *session.posargs,
        env=_test_env(session),
    )
    session.run("coverage", "report", "-m")
    session.run("coverage", "html")
    session.run("coverage", "xml")


@nox.session
def typecheck(session: nox.Session) -> None:
    """Run mypy and basedpyright type checkers."""
    session.run(
        "mypy",
        "--config-file",
        "pyproject.toml",
        "allianceauth_oidc",
    )
    session.run("basedpyright", "--project", "pyproject.toml")


@nox.session
def audit(session: nox.Session) -> None:
    """Audit dependencies for known vulnerabilities."""
    session.run("pip-audit")
