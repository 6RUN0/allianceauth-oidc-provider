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

import os
import pathlib
import shutil

import nox
import nox.registry

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
from _nox.makefile import (
    TARGETS,
    find_dangling_targets,
    find_uncovered_sessions,
    render_makefile,
)
from _nox.shared import (
    TEST_ARGS_BASE,
    resolve_test_labels,
    test_env,
)

# Path of the generated ``Makefile`` (repo root). The ``makefile``
# session writes it; ``makefile_check`` diffs against it. ``_nox.makefile``
# stays nox-free (so the off-lock test venvs can import its pure render /
# diff logic) — the sessions that touch the filesystem and the live nox
# registry live here.
_MAKEFILE_PATH = pathlib.Path("Makefile")

# Runner image the ``ci_local`` session hands to ``act``. The tag
# tracks the workflow's ``runs-on: ubuntu-24.04``; ``catthehacker``
# images are the ones act's own docs point at, and the plain
# (non-``-full``) variant is the smallest one that still carries
# ``sudo`` + ``apt-get``, which ``.github/actions/setup`` needs for
# ``default-libmysqlclient-dev``. Bump this in lockstep with
# ``runs-on`` in ``.github/workflows/main.yml``.
_ACT_RUNNER_IMAGE = "catthehacker/ubuntu:act-24.04"

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
    + makefile_check sequentially.

    The default ``uv run nox`` session set is ``lint + tests`` (fast
    local feedback loop). ``preflight`` is the heavier "ready to push"
    pass that also enforces the type signature, the migrations sync and
    raw-DDL concurrency, locale-catalogue integrity, and Makefile/session
    sync — the same set CI would otherwise run as separate jobs.
    ``messages_check`` ``skip``s locally when GNU gettext is absent, so it
    never blocks a push from a machine without the toolchain.

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
    session.notify("makefile_check")
    session.log(
        "preflight queued: lint -> typecheck -> tests -> "
        "migrations_check -> migrations_concurrency_check -> "
        "messages_check -> makefile_check"
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
def tests_timing(session: nox.Session) -> None:
    """
    Run the suite single-process and report the slowest test cases.

    Surfaces per-test wall-clock so a newly-slow test (an un-mocked
    network call, a forgotten per-test fixture rebuild) is visible
    before it bloats the whole suite. ``--durations=N`` is Django's
    passthrough to unittest's duration reporting (N=0 for all); ``N``
    comes from the ``OIDC_TIMING_DURATIONS`` env var (default 25).

    Forced ``--parallel=1`` so the durations table is one clean
    aggregate rather than one fragment per forked worker. A subset of
    tests can still be passed after ``--`` like with ``tests``.
    """
    durations = os.environ.get("OIDC_TIMING_DURATIONS", "25")
    session.run(
        "python",
        "-m",
        "django",
        "test",
        *TEST_ARGS_BASE,
        "--parallel=1",
        f"--durations={durations}",
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

    * PYSEC-2026-1325 — ``ecdsa`` side-channel advisory with no fixed
      release (the project declares side-channel resistance out of
      scope). Same chain as above: ``python-jose`` ← ``django-esi`` ←
      ``allianceauth``; nothing in this package imports ``ecdsa``, and
      the provider's own signing runs on ``jwcrypto``/``cryptography``.
      Falls away together with PYSEC-2025-185 when django-esi drops
      python-jose.
    """
    # TODO(2026-Q4): drop both suppressions once django-esi migrates
    # off python-jose (python-jose is the sole consumer of ecdsa too);
    # revisit upstream status next quarter.
    ignored = [
        "--ignore-vuln",
        "PYSEC-2025-185",
        "--ignore-vuln",
        "PYSEC-2026-1325",
    ]
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
def ci_local(session: nox.Session) -> None:
    """
    Run the CI workflow locally in Docker via ``act``.

    Closes the push-test-fix loop that ``preflight`` cannot: the nox
    sessions run in the developer's own environment, while CI runs them
    on a bare runner after ``uv sync``. Failures that only exist in that
    gap (a dev dependency present locally but absent from the lock, an
    ``apt-get`` package the composite action forgot, a step that assumes
    a warm cache) are invisible until a push burns a CI round-trip.

    ``act`` (https://github.com/nektos/act) replays the workflow in a
    container. Needs a running Docker daemon; both the binary and the
    daemon are opt-in, so the session warns and returns when either is
    missing - same pattern as ``actions_lint`` / ``diagrams``.

    Scope knobs, in the order you usually want them:

        make ci-local JOB=typecheck      # one job (the fast one)
        make ci-local EVENT=pull_request
        make ci-local                    # the whole push event
        uv run nox -s ci_local -- --dryrun
        uv run nox -s ci_local -- -j test --matrix python-version:3.12

    ``JOB``/``EVENT`` map to ``CI_LOCAL_JOB``/``CI_LOCAL_EVENT``;
    posargs are appended verbatim to the ``act`` command line.

    Three caveats that are not visible from the workflow file:

    - The bare ``make ci-local`` replays the full ``test`` matrix (7
      cells), each doing its own ``uv sync`` with a ``mysqlclient``
      sdist build inside the container. Budget an hour; narrow with
      ``JOB`` for anything but a pre-release sweep.
    - ``JOB=lint`` cannot pass. ``act`` does not run ``actions/checkout``
      for real - it copies the working tree in and leaves ``.git``
      out, so ``pre-commit run --all-files`` dies with "git failed. Is
      it installed, and are you in a Git repository directory?". Probed
      by running a workflow whose only step is ``test -e .git``: absent,
      while ``git --version`` reports 2.55.0. ``act --bind`` mounts the
      real directory instead of copying and does fix it, at the price of
      letting the container's root-owned ``uv sync`` write over the
      host ``.venv`` - so it stays opt-in, via posargs. Run the gate on
      the host (``nox -s lint``); the jobs that only need the working
      tree (``typecheck``, ``test``, ``package``) replay faithfully.
    - ``act``'s ``services:`` support is partial, so the ``mariadb``
      job is expected to misbehave locally even when CI is green. Use
      ``nox -s tests_mariadb`` (testcontainers) for that path instead.
    """
    if not shutil.which("act"):
        session.warn(
            "act not installed; skipping. Install via your system "
            "package manager (Gentoo: dev-util/act) or "
            "https://github.com/nektos/act/releases."
        )
        return
    if not shutil.which("docker"):
        session.warn("docker not on PATH; act needs a container runtime")
        return

    # ``or`` rather than a ``get`` default: the Makefile recipe always
    # exports both vars, so an unset ``EVENT=`` arrives as the empty
    # string and would shadow the default.
    event = os.environ.get("CI_LOCAL_EVENT") or "push"
    job = os.environ.get("CI_LOCAL_JOB") or ""

    # ``-P`` is mandatory, not a preference. The workflow pins
    # ``runs-on: ubuntu-24.04`` (not ``ubuntu-latest``), which act has
    # no built-in image for; with no mapping and no ``~/.actrc`` it
    # stops to ask which image size to use, hanging a ``make`` run on
    # an interactive prompt. Pinning the image here also keeps the run
    # reproducible across machines whose ``~/.actrc`` differs.
    #
    # ``--pull=false`` keeps the edit-run loop off the network; refresh
    # the image explicitly with ``docker pull``.
    args = [
        "act",
        event,
        "-W",
        ".github/workflows/main.yml",
        "-P",
        f"ubuntu-24.04={_ACT_RUNNER_IMAGE}",
        "--pull=false",
    ]
    if job:
        args += ["-j", job]
    session.run(*args, *session.posargs, external=True)


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


@nox.session
def makefile(session: nox.Session) -> None:
    """
    Regenerate ``./Makefile`` from the ``_nox/makefile.py`` table.

    The Makefile is generated, not hand-edited: change a target's wiring
    or help text in ``_nox.makefile.TARGETS`` (or add a target for a new
    session) and run this session to rewrite the file. ``makefile_check``
    gates the two staying in sync.
    """
    _MAKEFILE_PATH.write_text(render_makefile(), encoding="utf-8")
    session.log(f"regenerated {_MAKEFILE_PATH} from _nox/makefile.py")


@nox.session
def makefile_check(session: nox.Session) -> None:
    """
    Gate the generated ``Makefile`` against the session registry.

    Three independent drift checks, each reported together so one run
    surfaces every problem:

    #. **content** — the committed ``Makefile`` byte-matches
       ``render_makefile()`` (else: someone hand-edited it, or forgot to
       rerun ``nox -s makefile`` after editing the table).
    #. **coverage** — every registered nox session is wrapped by a
       target (else: a session was added with no ``make`` entry).
    #. **dangling** — every target naming a session names a real one
       (else: a session was renamed / removed and a target now points at
       nothing).

    The live session set comes from ``nox.registry`` (fully populated:
    importing this noxfile imported every ``_nox`` session module); the
    pure diff logic lives in the nox-free ``_nox.makefile``.
    """
    registered = set(nox.registry.get())
    problems: list[str] = []

    if not _MAKEFILE_PATH.exists():
        problems.append(
            f"{_MAKEFILE_PATH} is missing — run `uv run nox -s makefile`"
        )
    elif _MAKEFILE_PATH.read_text(encoding="utf-8") != render_makefile():
        problems.append(
            f"{_MAKEFILE_PATH} is out of sync with _nox/makefile.py — "
            "run `uv run nox -s makefile`"
        )

    uncovered = find_uncovered_sessions(registered, TARGETS)
    if uncovered:
        problems.append(
            "nox sessions with no Makefile target (add one to "
            "_nox/makefile.py::TARGETS or SESSIONS_WITHOUT_TARGET): "
            + ", ".join(sorted(uncovered))
        )

    dangling = find_dangling_targets(registered, TARGETS)
    if dangling:
        problems.append(
            "Makefile targets naming a non-existent session "
            "(fix the `session=` field in _nox/makefile.py::TARGETS): "
            + ", ".join(sorted(dangling))
        )

    if problems:
        session.error("\n".join(problems))
    session.log("Makefile is in sync with the nox session registry")
