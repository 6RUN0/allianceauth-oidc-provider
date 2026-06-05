"""
Nox sessions — run via ``uv run nox``.

Default (no args): lint + tests.

Full session inventory: ``uv run nox -l``. The catalogue below shows
the most-used invocations and the conventions specific to this repo
(posargs forwarding, env-var overrides). Domain-specific sessions
(matrix, mutation, conformance, dist) are documented in their
respective ``_nox/<module>.py`` docstrings.

Examples::

    uv run nox                                  # default (lint + tests)
    uv run nox -l                               # list every session
    uv run nox -s preflight                     # all push-gate checks
    uv run nox -s tests -- tests.test_token     # subset of tests
    uv run nox -s tests -- --keepdb             # forward extra args
    uv run nox -s tests -- --parallel 1         # disable parallelism
    AA_USE_FAKE_REDIS=0 uv run nox -s tests     # run against real Redis
"""

from __future__ import annotations

import pathlib
import shutil

import nox

# Importing the submodules is enough to register their sessions with
# nox — each ``@nox.session`` decorator runs at import time and adds
# the function to nox's global registry. Keeps the main noxfile
# readable while domain-specific orchestrations (mutation testing,
# conformance suite, cross-version matrices) live in their own files.
import _nox.conformance
import _nox.dist
import _nox.i18n
import _nox.matrix
import _nox.migrations
import _nox.mutation  # noqa: F401
from _nox.shared import (
    TEST_ARGS_BASE,
    resolve_test_labels,
    test_env,
)

nox.options.sessions = ["lint", "tests"]
# `none`: nox does not create its own venv; it runs sessions in the active
# environment. Combined with `uv sync --all-groups`, this keeps the toolchain
# definition in pyproject.toml + uv.lock.
nox.options.default_venv_backend = "none"

# `dev` is uv's only default dependency group; ``aa4`` / ``aa5`` are
# declared in ``pyproject.toml`` for matrix sessions and are mutually
# exclusive (``[tool.uv].conflicts``). Bare ``uv sync`` therefore
# installs project deps + ``dev`` only — equivalent to the older
# ``uv sync --all-groups`` semantics from before the AA-stack groups
# existed. ``--all-groups`` would now pull both incompatible groups
# and fail resolution; the matrix sessions instead select stacks
# explicitly via ``--group aa4`` (off-lock) or by leaving ``aa5`` to
# the lock's default resolution.


@nox.session
def lint(session: nox.Session) -> None:
    """Run all linters and formatters via pre-commit."""
    session.run("pre-commit", "run", "--all-files")


@nox.session
def preflight(session: nox.Session) -> None:
    """
    Run lint + typecheck + tests + the migration gates + messages_check
    sequentially.

    The default ``uv run nox`` session set is ``lint + tests`` (fast
    local feedback loop). ``preflight`` is the heavier "ready to push"
    pass that also enforces the type signature, the migrations sync and
    raw-DDL concurrency, and locale-catalogue integrity — the same set
    CI would otherwise run as separate jobs. ``messages_check`` ``skip``s
    locally when GNU gettext is absent, so it never blocks a push from a
    machine without the toolchain.

    Sessions are notified, not invoked inline, so nox stops at the
    first failure (a typecheck regression should not get masked by
    a downstream test pass that papers over it).
    """
    session.notify("lint")
    session.notify("typecheck")
    session.notify("tests")
    session.notify("migrations_check")
    session.notify("migrations_concurrency_check")
    session.notify("messages_check")
    session.log(
        "preflight queued: lint -> typecheck -> tests -> "
        "migrations_check -> migrations_concurrency_check -> "
        "messages_check"
    )


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
        *resolve_test_labels(tuple(session.posargs)),
        env=test_env(session),
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
        *resolve_test_labels(tuple(session.posargs)),
        env=test_env(session),
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
    """
    Audit dependencies for known vulnerabilities.

    Extra args after ``--`` are forwarded to ``pip-audit`` — used by
    ``.github/workflows/audit.yml`` to request a JSON report
    (``-- --format=json --output=audit.json``) that gets archived as
    a workflow artefact.

    Suppressed advisories:

    * PYSEC-2025-185 — ``python-jose`` algorithm-confusion bug. The
      library is unmaintained upstream (no 3.6.x line) and reaches us
      transitively via ``django-esi`` (AA's ESI client). We do not
      import ``python-jose`` directly anywhere in the package; AA's
      ESI flow is the only consumer. Revisit when django-esi migrates
      off python-jose (tracked upstream).
    """
    # TODO(2026-Q4): drop PYSEC-2025-185 suppression once django-esi
    # migrates off python-jose; revisit upstream status next quarter.
    ignored = ["--ignore-vuln", "PYSEC-2025-185"]
    session.run("pip-audit", *ignored, *session.posargs)


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
        # ``--persona=pedantic`` surfaces extra findings beyond the
        # default ``regular`` set: ``unpinned-uses`` outside composite
        # actions, ``bot-conditions`` (workflows gated on ``actor``
        # without an allow-list), broader ``excessive-permissions``,
        # and template-injection at lower severity. The release flow
        # publishes signed wheels — a workflow-injection finding there
        # is a supply-chain incident, so the aggressive persona is
        # worth its extra noise.
        #
        # ``--min-severity=low`` suppresses *informational* findings
        # (cosmetic, e.g. ``anonymous-definition`` for jobs without a
        # ``name:`` field) so the gate fails only on real security
        # signal. Lift to ``informational`` once workflows carry
        # explicit job names if the noise is acceptable.
        session.run(
            "zizmor",
            "--persona=pedantic",
            "--min-severity=low",
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

    ``d2`` is a single Go binary; install via your system package
    manager (Gentoo: ``app-misc/d2``; brew/apt provide it too) or the
    upstream releases page (https://github.com/terrastruct/d2). The
    session is a noop with a warning when the binary is missing —
    same opt-in pattern as ``markdown_lint`` and ``actions_lint``.

    Both the source (``.d2``) and the rendered output (``.svg``) are
    committed: source so the diagram is editable, output so the
    README renders without forcing every reader to install ``d2``.
    Freshness is enforced by hand for now (run this session locally
    before committing a diagram change); there is no CI step that
    asserts the two stay in sync.
    """
    diagram_dir = pathlib.Path("assets/diagrams")
    sources = sorted(diagram_dir.glob("*.d2"))
    if not sources:
        session.skip("no .d2 sources under assets/diagrams/")
    if not shutil.which("d2"):
        session.warn(
            "d2 not installed; skipping. "
            "Install via your system package manager "
            "(Gentoo: app-misc/d2; brew: d2) or "
            "https://github.com/terrastruct/d2/releases."
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
        env=test_env(session),
    )
