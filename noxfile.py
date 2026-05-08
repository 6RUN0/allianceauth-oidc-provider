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
    uv run nox -s makemigrations                   # generate Django migrations
    uv run nox -s markdown_lint                    # rumdl + lychee + vale
    uv run nox -s tests_matrix                     # tests on every Python
    uv run nox -s tests_aa4                        # tests against AA 4.x stack
    AA_USE_FAKE_REDIS=0 uv run nox -s tests        # run against real Redis
"""

from __future__ import annotations

import pathlib
import shutil

import nox

nox.options.sessions = ["lint", "tests"]
# `none`: nox does not create its own venv; it runs sessions in the active
# environment. Combined with `uv sync --all-groups`, this keeps the toolchain
# definition in pyproject.toml + uv.lock.
nox.options.default_venv_backend = "none"

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

# Locales we ship translations for. ``en`` is the source language —
# we keep the catalogue inside the tree because the Transifex config
# (``.tx/transifex.yml``) treats it as the source-of-truth file. Add
# new locales here as translations land; the lists are honoured by
# both ``makemessages`` (extract) and ``compilemessages`` (compile).
LOCALES = ["en", "ru", "uk"]
PACKAGE_DIR = pathlib.Path("allianceauth_oidc")

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
]


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


@nox.session(python=PYTHON_VERSIONS, venv_backend="uv")
def tests_matrix(session: nox.Session) -> None:
    """
    Run the Django test suite against every supported Python version.

    Spawns a per-interpreter uv-managed venv (vs the default ``none``
    backend that re-uses the active venv) and ``uv sync --all-groups``s
    into it before running ``django test``. Slower than ``tests`` but
    catches version-specific regressions — typing-extension semantics,
    deprecated stdlib modules, native wheel availability gaps. Pass
    extra args to ``django test`` after ``--`` like with ``tests``.
    """
    session.run_install(
        "uv",
        "sync",
        "--all-groups",
        f"--python={session.python}",
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
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
    the AA-version constraint can override what the lock says. Test
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
        "allianceauth<5",
        "django<5",
        "django-oauth-toolkit>=3.2,<4",
        *TEST_RUNTIME_DEPS,
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
    )
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
def markdown_lint(session: nox.Session) -> None:
    """
    Lint shipped Markdown files.

    Runs three system-installed tools when present, each independent:

    - ``rumdl`` — fast Markdown structural lint (heading levels,
      list spacing, line length, etc.).
    - ``lychee`` — link checker; default network mode validates
      external URLs.
    - ``vale`` — prose style linter; activated only when
      ``.vale.ini`` exists at the repo root.

    Each tool is skipped (with a warning) if it is not on ``PATH``.
    Use ``external=True`` because these are system binaries, not
    Python dependencies.
    """
    md_files = sorted(str(p) for p in pathlib.Path().glob("*.md"))
    if not md_files:
        session.skip("no top-level Markdown files to lint")

    if shutil.which("rumdl"):
        session.run("rumdl", "check", *md_files, external=True)
    else:
        session.warn("rumdl not installed; skipping markdown structural lint")

    if shutil.which("lychee"):
        session.run("lychee", "--no-progress", *md_files, external=True)
    else:
        session.warn("lychee not installed; skipping link check")

    if shutil.which("vale"):
        if pathlib.Path(".vale.ini").exists():
            session.run("vale", *md_files, external=True)
        else:
            session.warn("vale: .vale.ini missing; skipping prose lint")
    else:
        session.warn("vale not installed; skipping prose lint")


@nox.session
def actions_lint(session: nox.Session) -> None:
    """
    Lint GitHub Actions workflows.

    Runs two complementary system-installed tools when present, each
    independent — same opt-in pattern as ``markdown_lint``:

    - ``actionlint`` — correctness checks: YAML schema validation
      against the GitHub Actions grammar, ``${{ ... }}`` expression
      language lint, and ``shellcheck`` integration for every
      ``run:`` block. Install: Gentoo ``dev-util/actionlint`` or
      https://github.com/rhysd/actionlint.
    - ``zizmor`` — security audit: workflow injection, persistent
      credentials, broad permissions, dangerous triggers
      (``pull_request_target`` etc.), expired actions. Install:
      Gentoo ``dev-util/zizmor`` or https://github.com/woodruffw/zizmor.

    Each tool is skipped (with a warning) if it is not on ``PATH``.
    Use ``external=True`` because these are system binaries, not
    Python dependencies.
    """
    workflow_dir = pathlib.Path(".github/workflows")
    workflows = sorted(str(p) for p in workflow_dir.glob("*.yml")) + sorted(
        str(p) for p in workflow_dir.glob("*.yaml")
    )
    if not workflows:
        session.skip("no GitHub Actions workflows to lint")

    if shutil.which("actionlint"):
        session.run("actionlint", "-color", *workflows, external=True)
    else:
        session.warn(
            "actionlint not installed; skipping. "
            "Install via system package manager (Gentoo: "
            "dev-util/actionlint) or "
            "https://github.com/rhysd/actionlint"
        )

    if shutil.which("zizmor"):
        # ``--persona=regular`` is the default; spell it out so a future
        # bump to ``pedantic`` (more aggressive findings) is an explicit
        # choice rather than a silent regression.
        session.run(
            "zizmor",
            "--persona=regular",
            *workflows,
            external=True,
        )
    else:
        session.warn(
            "zizmor not installed; skipping security audit. "
            "Install via system package manager (Gentoo: "
            "dev-util/zizmor) or "
            "https://github.com/woodruffw/zizmor"
        )


@nox.session
def diagrams(session: nox.Session) -> None:
    """
    Render diagram-as-code sources under ``assets/diagrams/`` to SVG
    via ``d2``, if installed.

    ``d2`` is a single Go binary; install via the official script
    (https://d2lang.com/install.sh) or the upstream releases page
    (https://github.com/terrastruct/d2). The session is a noop with
    a warning when the binary is missing — same opt-in pattern as
    ``markdown_lint`` and ``actions_lint``.

    Both the source (``.d2``) and the rendered output (``.svg``) are
    committed: source so the diagram is editable, output so the
    README renders without forcing every reader to install ``d2``.
    The ``diagrams-fresh`` CI step asserts the two stay in sync.
    """
    diagram_dir = pathlib.Path("assets/diagrams")
    sources = sorted(diagram_dir.glob("*.d2"))
    if not sources:
        session.skip("no .d2 sources under assets/diagrams/")
    if not shutil.which("d2"):
        session.warn(
            "d2 not installed; skipping. "
            "Install via the official script "
            "(curl -fsSL https://d2lang.com/install.sh | sh -s --) "
            "or https://github.com/terrastruct/d2"
        )
        return
    for src in sources:
        out = src.with_suffix(".svg")
        # ``--theme=0`` is the Neutral Default — readable on white
        # (PyPI) and on dark-mode GitHub via inverted text. ``--pad=20``
        # leaves breathing room around the diagram so README image
        # frames don't clip the labels.
        session.run(
            "d2",
            "--theme=0",
            "--pad=20",
            str(src),
            str(out),
            external=True,
        )


@nox.session
def makemigrations(session: nox.Session) -> None:
    """
    Generate Django migrations for the ``allianceauth_oidc`` app.

    Runs Django's ``makemigrations`` against the test settings module
    so AA + DOT are wired up the same way they are in the test suite.
    Pass extra args via ``--``: e.g.::

        uv run nox -s makemigrations -- --name rename_logo_url --dry-run
        uv run nox -s makemigrations -- --check

    Resulting files land in ``allianceauth_oidc/migrations/`` and
    should be reviewed before commit.
    """
    session.run(
        "python",
        "-m",
        "django",
        "makemigrations",
        "allianceauth_oidc",
        f"--settings={TEST_SETTINGS}",
        *session.posargs,
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
    cert_path = "tests/conformance/tls/ca.crt"
    # Generate the self-signed CA + provider cert if missing. The
    # conformance suite enforces ``https://`` for OIDC discovery, so
    # the provider container serves TLS via ``runsslserver`` and the
    # suite container imports the CA cert into its Java truststore on
    # startup. Certs are gitignored — re-running ``gen.sh`` is safe
    # (it overwrites). See ``tests/conformance/tls/`` for details.
    if not pathlib.Path(cert_path).is_file():
        session.run("sh", "tests/conformance/tls/gen.sh", external=True)
    try:
        # ``--build`` forces a rebuild on every invocation so a stale
        # provider image does not silently mask code edits between
        # iterations. Cheap when nothing changed (Docker reuses the
        # cached layers).
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "up",
            "-d",
            "--wait",
            "--build",
            external=True,
        )
        session.run(
            "python",
            "tests/conformance/run_plan.py",
            *session.posargs,
            external=True,
        )
    finally:
        # ``-v`` wipes the named MongoDB volume so the next run starts
        # from a clean suite-state. Runs unconditionally (try/finally)
        # so an interrupted plan still tears the stack down.
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
