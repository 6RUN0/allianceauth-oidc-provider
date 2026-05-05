"""
Nox sessions — run via ``uv run nox``.

Default (no args): lint + tests.

Examples::

    uv run nox                       # default sessions (lint + tests)
    uv run nox -s lint               # all linters via pre-commit
    uv run nox -s tests              # Django test suite
    uv run nox -s tests -- -k policy # forward args to runtests.py
    uv run nox -s typecheck          # mypy + basedpyright
    uv run nox -s coverage           # tests with coverage report
    uv run nox -s audit              # pip-audit dependency scan
"""

from __future__ import annotations

import nox

nox.options.sessions = ["lint", "tests"]
# `none`: nox does not create its own venv; it runs sessions in the active
# environment. Combined with `uv sync --all-groups`, this keeps the toolchain
# definition in pyproject.toml + uv.lock.
nox.options.default_venv_backend = "none"

# Test runner config. Mirrors the invocation that the previous tox.ini used:
# - tests.test_settingsAA4 boots Alliance Auth in a way the suite can use.
# - AA_USE_FAKE_REDIS=1 makes runtests.py monkey-patch django_redis to a
#   fakeredis backend, so no real Redis is required.
# - --debug-mode disables ManifestStaticFilesStorage's manifest check, which
#   would otherwise fail because we don't run collectstatic in CI.
TEST_ENV = {
    "DJANGO_SETTINGS_MODULE": "tests.test_settingsAA4",
    "AA_USE_FAKE_REDIS": "1",
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
        "runtests.py",
        "tests",
        "-v",
        "2",
        "--debug-mode",
        *session.posargs,
        env=TEST_ENV,
    )


@nox.session
def coverage(session: nox.Session) -> None:
    """Run tests under coverage and emit term/html/xml reports."""
    session.run(
        "coverage",
        "run",
        "runtests.py",
        "tests",
        "-v",
        "2",
        "--debug-mode",
        *session.posargs,
        env=TEST_ENV,
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
