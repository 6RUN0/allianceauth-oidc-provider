"""
Nox sessions — run via ``uv run nox``.

Default (no args): lint + tests.

Examples::

    uv run nox                                     # default (lint + tests)
    uv run nox -s lint                             # pre-commit hooks
    uv run nox -s tests                            # Django test suite
    uv run nox -s tests -- tests.test_token        # subset of tests
    uv run nox -s tests -- --keepdb                # forward extra args
    uv run nox -s tests -- --parallel 1            # disable parallelism
    uv run nox -s typecheck                        # mypy + basedpyright
    uv run nox -s coverage                         # tests + coverage reports
    uv run nox -s audit                            # pip-audit
    uv run nox -s makemessages                     # extract -> .po + .pot
    uv run nox -s compilemessages                  # compile .po -> .mo
    AA_USE_FAKE_REDIS=0 uv run nox -s tests        # run against real Redis
"""

from __future__ import annotations

import pathlib

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
# Options-only base — the positional `tests` label is appended last
# inside the session so that subset labels passed via `-- ...` end up
# AFTER `--parallel=auto`, where Django's argparse accepts them.
TEST_ARGS_BASE = [
    f"--settings={TEST_SETTINGS}",
    "-v",
    "2",
    "--debug-mode",
]

# Locales we ship translations for. ``en`` is the source language —
# we keep the catalogue inside the tree because the Transifex config
# (``.tx/transifex.yml``) treats it as the source-of-truth file. Add
# new locales here as translations land; the lists are honoured by
# both ``makemessages`` (extract) and ``compilemessages`` (compile).
LOCALES = ["en", "ru", "uk"]
PACKAGE_DIR = pathlib.Path("allianceauth_oidc")


def _resolve_test_labels(posargs: tuple[str, ...]) -> list[str]:
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
    """
    Run the Django test suite (parallel by default).

    `--parallel=auto` distributes test classes across CPU cores. Django
    honours the last `--parallel` flag, so a caller can opt out with
    `... -- --parallel 1` for a focused subset where the fork overhead
    outweighs the speed-up, or while debugging a flaky test.
    """
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=auto",
        *_resolve_test_labels(tuple(session.posargs)),
        env=_test_env(session),
    )


@nox.session
def coverage(session: nox.Session) -> None:
    """
    Run tests under coverage and emit term/html/xml reports.

    Single-process: Django's --parallel forks worker processes whose
    per-process .coverage files would need `coverage combine`, adding
    pipeline complexity for a sub-second speed-up on this suite.
    """
    session.run(
        "coverage",
        "run",
        "--source=allianceauth_oidc",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        *_resolve_test_labels(tuple(session.posargs)),
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


@nox.session
def makemessages(session: nox.Session) -> None:
    """
    Extract translatable strings into the locale tree.

    Runs Django's ``makemessages`` once per locale, writing
    ``locale/<locale>/LC_MESSAGES/django.po`` plus a top-level
    ``django.pot`` template. ``--no-location`` keeps the .po diffs
    stable (no ``source.py:42`` refs that churn on every refactor);
    ``--keep-pot`` retains the template alongside the locale
    catalogues for translation-platform workflows. Invoked from
    inside ``allianceauth_oidc/`` so the catalogues land next to the
    package source, not in the host AA project's ``LOCALE_PATHS``.
    """
    locale_dir = PACKAGE_DIR / "locale"
    locale_dir.mkdir(exist_ok=True)
    with session.chdir(PACKAGE_DIR):
        for locale in LOCALES:
            session.run(
                "django-admin",
                "makemessages",
                "--locale",
                locale,
                "--no-location",
                "--keep-pot",
                env=_test_env(session),
            )


@nox.session
def compilemessages(session: nox.Session) -> None:
    """Compile shipped ``.po`` catalogues into ``.mo`` binaries."""
    with session.chdir(PACKAGE_DIR):
        session.run(
            "django-admin",
            "compilemessages",
            env=_test_env(session),
        )


@nox.session
def conformance(session: nox.Session) -> None:
    """
    Run the OpenID Conformance Suite against a Docker-Compose-built
    provider stack.

    Brings up MongoDB + the conformance suite + our provider, runs the
    default plan via ``run_plan.py``, and tears the stack down
    regardless of outcome. ``--`` args after the session name are
    forwarded to the runner — e.g.::

        uv run nox -s conformance -- --plan oidcc-basic-certification-test-plan
        uv run nox -s conformance -- --strict-warnings

    Excluded from default sessions because it pulls Docker images and
    takes 10-15 minutes; see tests/conformance/README.md for context.
    """
    compose_file = "tests/conformance/docker-compose.yml"
    try:
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "up",
            "-d",
            "--wait",
            external=True,
        )
        session.run(
            "python",
            "tests/conformance/run_plan.py",
            *session.posargs,
            external=True,
        )
    finally:
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "down",
            "-v",
            external=True,
            success_codes=[0, 1],
        )


@nox.session
def integration(session: nox.Session) -> None:
    """
    Run wire-level integration tests (mock-RP via LiveServerTestCase).

    Forces ``--parallel 1``: ``LiveServerTestCase`` boots a WSGI server
    in a thread that shares the test process's DB connection, which
    does not survive Django's test-runner ``fork()``.

    Excluded from the default sessions (``lint`` + ``tests``) because
    real-HTTP tests are an order of magnitude slower than the test-
    client ones and require ``requests`` from the dev group. Run on
    demand with ``uv run nox -s integration``.
    """
    posargs = tuple(session.posargs)
    has_label = any(not arg.startswith("-") for arg in posargs)
    labels: list[str] = (
        list(posargs)
        if has_label
        else ["tests.test_integration_mock_rp", *posargs]
    )
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=1",
        *labels,
        env=_test_env(session),
    )
