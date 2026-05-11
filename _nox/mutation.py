"""
Mutation-testing sessions for ``allianceauth_oidc``.

Three sessions live here:

* ``mutation`` — full cosmic-ray sweep (init + exec + report). The
  serial pre-release gate.
* ``mutation_parallel`` — resumes ``mutation.sqlite`` across N
  isolated worker copies via cosmic-ray's HTTP distributor.
* ``mutation_html`` — renders the cosmic-ray HTML survivor report.

Everything is invoked via ``uv run nox -s <name>`` exactly as if
these functions still sat in ``noxfile.py``; the only structural
change is that they import their own helpers from this module
instead of the root noxfile, so changes to mutation infrastructure
no longer touch the shared file.

See ``docs/mutation-testing.md`` for runtime/interpretation notes
and ``cosmic-ray.toml`` for the operator/exclude configuration.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

import nox

# ``tomllib`` is stdlib only from Python 3.11+; the project supports
# 3.10 per ``requires-python``. Lazy-importing it inside
# ``mutation_parallel`` (the sole consumer) keeps ``nox -s tests`` /
# ``nox -s lint`` working on 3.10 — those sessions never trigger this
# module's parallel branch.

# Local copy of the test-settings helper that the root ``noxfile.py``
# defines for its other sessions. Duplicating five lines lets this
# module stay self-contained; if more sessions move here later, both
# helpers should be promoted to a shared ``_nox/_common.py``.
_TEST_SETTINGS = "tests.test_settingsAA4"


def _test_env(session: nox.Session) -> dict[str, str]:
    """Build the env mutation sessions need (mirrors ``noxfile._test_env``)."""
    return {
        "DJANGO_SETTINGS_MODULE": _TEST_SETTINGS,
        "AA_USE_FAKE_REDIS": session.env.get("AA_USE_FAKE_REDIS", "1"),
    }


@nox.session
def mutation(session: nox.Session) -> None:
    """
    Run mutation testing via cosmic-ray over production modules.

    Mutation testing measures *test adequacy*, not code correctness:
    it patches the source with small semantic edits ("mutants") and
    verifies the test suite catches each one. A surviving mutant
    means a real change went unnoticed by the tests — either a
    missing assertion, a tautological one, or a code path no test
    reaches. See ``docs/mutation-testing.md`` for interpretation
    guidance.

    This is a **pre-release gate**, not a CI-on-every-push gate. A
    full sweep over ``allianceauth_oidc/`` mutates thousands of
    lines x the ~7-10 s baseline test suite => multiple hours
    wall-clock. Run locally before a release cut, or narrow
    ``cosmic-ray.toml::module-path`` temporarily for a per-file
    sweep.

    Workflow (split into three cosmic-ray subcommands):

    1. ``cosmic-ray init`` — seed the sqlite work-queue with one
       mutant per AST mutation site under ``module-path``.
    2. ``cosmic-ray exec`` — drain the queue: for each mutant, run
       the ``test-command`` and record survived / killed / errored.
    3. ``cr-report`` — print the killed/survived/timeout tally.

    The session file (``mutation.sqlite``) is gitignored; deleting it
    forces a fresh sweep next run. Killing the session mid-``exec``
    is safe: cosmic-ray resumes from where the queue stood.
    """
    session_file = "mutation.sqlite"
    # Re-init wipes the queue if a prior partial run exists, so the
    # tally below corresponds to a complete current sweep rather than
    # a mix of old + new mutants.
    session.run(
        "cosmic-ray",
        "--verbosity=INFO",
        "init",
        "cosmic-ray.toml",
        session_file,
    )
    # ``exec`` runs the full queue. Exit code is nonzero if any
    # mutant survived — that is the diagnostic signal we want to
    # surface, NOT a session failure. ``success_codes`` accepts the
    # whole [0, 255] band; cr-report reads the sqlite directly and
    # prints the verdict regardless of exit code.
    session.run(
        "cosmic-ray",
        "--verbosity=INFO",
        "exec",
        "cosmic-ray.toml",
        session_file,
        env=_test_env(session),
        success_codes=list(range(256)),
    )
    session.run("cr-report", session_file)


@nox.session
def mutation_parallel(session: nox.Session) -> None:  # noqa: PLR0912, PLR0915
    """
    Resume a partial cosmic-ray sweep with N isolated worker copies.

    cosmic-ray's ``local`` distributor runs mutants serially because
    each mutant mutates source files on disk in the project tree
    (``cosmic_ray/mutating.py::apply_mutation``). N parallel workers
    in one tree would race on those files. This session materialises
    N isolated rsync copies under ``mktemp``, symlinks ``.venv`` into
    each, runs the configured ``test-command`` once as a baseline
    gate, and then drives the ``http`` distributor with workers bound
    to ``CR_BASE_PORT`` upward.

    Use after a ``cosmic-ray init`` (or after the first ``init``
    phase of ``nox -s mutation``) has populated ``mutation.sqlite``.
    This session never overwrites existing work_results; pending
    items get distributed across the workers.

    Args::

        nox -s mutation_parallel -- 4       # 4 workers (default)
        nox -s mutation_parallel -- 8       # 8 workers
        CR_BASE_PORT=10000 nox -s mutation_parallel -- 4

    Why baseline first: the worker subprocess invokes
    ``shlex.split(test_command)`` and ``subprocess.run`` with no
    shell, so a ``python`` token in the command resolves against
    PATH at exec time. If PATH does not include the project venv,
    Django is missing, every mutant gets a fake ``KILLED`` with
    empty stdout, and the whole run is silently meaningless. The
    baseline runs the test command once in worker-1's tree before
    spawning workers; a non-zero exit aborts the session.
    """
    project_dir = pathlib.Path.cwd()
    venv_bin = project_dir / ".venv" / "bin"
    session_file = project_dir / "mutation.sqlite"
    base_config = project_dir / "cosmic-ray.toml"
    base_port = int(session.env.get("CR_BASE_PORT", "9876"))

    n_arg = (
        session.posargs[0]
        if session.posargs
        else session.env.get("CR_PARALLEL_N", "4")
    )
    try:
        n_workers = int(n_arg)
    except ValueError as exc:
        session.error(f"N must be a positive integer, got: {n_arg!r} ({exc})")
    if n_workers < 1:
        session.error(f"N must be >= 1, got: {n_workers}")

    if not (venv_bin / "cosmic-ray").is_file():
        session.error(
            f"{venv_bin}/cosmic-ray not found — run 'make dev' first"
        )
    if not session_file.is_file():
        session.error(
            f"{session_file} missing — run "
            f"'uv run cosmic-ray init cosmic-ray.toml mutation.sqlite' "
            "first",
        )
    if not base_config.is_file():
        session.error(f"{base_config} missing")

    # Lazy import — see the top-of-file comment for why tomllib is
    # not at module scope.
    import tomllib

    # Read the base config so we can extract the test-command for the
    # baseline check and rewrite the distributor section for parallel.
    config_text = base_config.read_text(encoding="utf-8")
    config = tomllib.loads(config_text)
    test_command = config.get("cosmic-ray", {}).get("test-command")
    if not test_command:
        session.error("cosmic-ray.test-command missing from cosmic-ray.toml")

    # ``shutil.copytree`` with an ignore-pattern is the stdlib
    # equivalent of rsync's --exclude. We materialise N copies; each
    # gets a ``.venv`` symlink to the project's venv so all workers
    # share one Python install.
    ignore = shutil.ignore_patterns(
        ".git",
        ".venv",
        "mutation.sqlite",
        "mutation.sqlite-*",
        "html",
        "htmlcov",
        ".nox",
        ".coverage",
        "*.egg-info",
        "dist",
        "build",
        "__pycache__",
        "*.pyc",
        ".omc",
        ".claude",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    )

    # ``tempfile.mkdtemp`` is wrapped in a single ``try/finally`` so
    # ``shutil.rmtree`` runs even when a downstream ``session.error``
    # raises ``_SessionQuit`` (e.g. baseline test failed, worker
    # failed to bind). Without this wrap the workdir leaks one full
    # source-tree copy x N workers per failed run — gigabytes after
    # repeated baseline regressions.
    work_base = pathlib.Path(tempfile.mkdtemp(prefix="allianceauth-oidc-cr."))
    session.log(f"workdir = {work_base}")

    procs: list[subprocess.Popen[bytes]] = []
    log_files: list = []

    def shutdown() -> None:
        """Kill every worker process group, then drain logs."""
        for proc in procs:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # noqa: PERF203
                # Per-process wait MUST be in the loop body — the
                # escalation (SIGKILL + drain) only fires for the
                # specific worker that ignored SIGTERM. Hoisting it
                # out of the loop would either escalate every worker
                # or skip escalation entirely.
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2)
        for log_f in log_files:
            log_f.close()

    try:
        worker_dirs: list[pathlib.Path] = []
        worker_urls: list[str] = []
        for i in range(1, n_workers + 1):
            worker_dir = work_base / f"worker-{i}"
            shutil.copytree(
                project_dir, worker_dir, ignore=ignore, symlinks=False
            )
            (worker_dir / ".venv").symlink_to(project_dir / ".venv")
            worker_dirs.append(worker_dir)
            worker_urls.append(f"http://127.0.0.1:{base_port + i - 1}")
        session.log(f"materialised {n_workers} worker copies")

        # Worker env: prepend venv/bin to PATH so subprocess calls to
        # bare ``python`` in the test-command resolve to the project
        # interpreter (Django, AA, etc. installed), not the system
        # one.
        worker_env: dict[str, str] = {
            **os.environ,
            "PATH": f"{venv_bin}{os.pathsep}{os.environ['PATH']}",
        }

        # Baseline gate. ``timeout`` is 3x the configured per-mutant
        # ceiling (``cosmic-ray.toml::timeout``, ~60 s) so a flaky
        # baseline (deadlocked DB, fakeredis hang, signal-loop) fails
        # fast with a clear message instead of wedging the operator's
        # terminal indefinitely. The per-mutant cap only applies to
        # mutated runs cosmic-ray drives itself.
        session.log("baseline check: running test-command in worker-1")
        baseline_log = work_base / "baseline.log"
        baseline_timeout = 180
        with baseline_log.open("wb") as log_f:
            try:
                baseline_rc = subprocess.run(
                    ["bash", "-c", test_command],
                    cwd=worker_dirs[0],
                    env=worker_env,
                    stdout=log_f,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=baseline_timeout,
                ).returncode
            except subprocess.TimeoutExpired:
                session.error(
                    "baseline test-command exceeded "
                    f"{baseline_timeout}s — refusing to start "
                    "workers. Investigate before re-running "
                    "mutation_parallel (deadlocked DB, hanging "
                    "fakeredis, etc.)."
                )
        if baseline_rc != 0:
            tail = baseline_log.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[-30:]
            session.error(
                f"baseline test-command FAILED (rc={baseline_rc}) — "
                "refusing to start workers.\n"
                "Last 30 lines of baseline.log:\n" + "\n".join(tail),
            )
        session.log("baseline OK")

        # Synthesise a parallel-config TOML: strip the original
        # ``[cosmic-ray.distributor]`` (and any sub-tables) and
        # append our http distributor block. tomllib is read-only,
        # so we slice the text directly.
        #
        # Anchoring rules:
        # * ``(?:^|\n)`` — match the section even when it is the
        #   very first line of the file (the original
        #   ``\n``-anchored pattern silently missed that case and
        #   produced a config with two ``[cosmic-ray.distributor]``
        #   tables — a runtime ``TOMLDecodeError`` from cosmic-ray's
        #   parser).
        # * ``(?:\.[^\]]*)?\]`` — match either the bare section or
        #   any dotted sub-table (e.g.
        #   ``[cosmic-ray.distributor.http]``) but NOT a
        #   hypothetical sibling section that merely starts with
        #   the same prefix (e.g. a future
        #   ``[cosmic-ray.distributors_legacy]``).
        parallel_config = work_base / "cosmic-ray-parallel.toml"
        stripped = re.sub(
            r"(?:^|\n)\[cosmic-ray\.distributor(?:\.[^\]]*)?\].*?(?=\n\[|\Z)",
            "\n",
            config_text,
            flags=re.DOTALL,
        )
        worker_urls_toml = ", ".join(f'"{url}"' for url in worker_urls)
        parallel_config.write_text(
            stripped.rstrip()
            + '\n\n[cosmic-ray.distributor]\nname = "http"\n\n'
            + "[cosmic-ray.distributor.http]\n"
            + f"worker-urls = [{worker_urls_toml}]\n",
            encoding="utf-8",
        )

        session.log(
            f"spawning {n_workers} workers on ports "
            f"{base_port}-{base_port + n_workers - 1}"
        )
        for i, worker_dir in enumerate(worker_dirs):
            port = base_port + i
            log_path = work_base / f"worker-{i + 1}.log"
            log_f = log_path.open("wb")
            log_files.append(log_f)
            proc = subprocess.Popen(
                [
                    str(venv_bin / "cosmic-ray"),
                    "--verbosity=WARNING",
                    "http-worker",
                    "--port",
                    str(port),
                ],
                cwd=worker_dir,
                env=worker_env,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            procs.append(proc)

        # Concurrent bind-check: poll all workers in round-robin
        # within a single 30 s budget rather than 30 s per worker.
        # The previous per-worker loop took up to N x 30 s before
        # surfacing a stuck worker, which operators interpreted as
        # a hang. With the round-robin shape the total wait is
        # always ≤ 30 s regardless of N.
        session.log(
            f"waiting for {n_workers} workers to bind (30s total budget)..."
        )
        bind_deadline_iters = 60
        pending: dict[int, subprocess.Popen[bytes]] = dict(enumerate(procs))
        for _iteration in range(bind_deadline_iters):
            if not pending:
                break
            for i, proc in list(pending.items()):
                port = base_port + i
                if proc.poll() is not None:
                    log_text = (work_base / f"worker-{i + 1}.log").read_text(
                        encoding="utf-8", errors="replace"
                    )
                    session.error(
                        f"worker {i + 1} died before binding "
                        f"(rc={proc.returncode}).\n"
                        "Log tail:\n" + "\n".join(log_text.splitlines()[-20:]),
                    )
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.5
                    ):
                        pending.pop(i)
                except OSError:
                    continue
            if pending:
                time.sleep(0.5)
        if pending:
            stuck_ids = ", ".join(str(i + 1) for i in sorted(pending))
            session.error(
                f"worker(s) {stuck_ids} did not bind within 30s — "
                "check ``CR_BASE_PORT`` for port collisions"
            )
        session.log(f"all {n_workers} workers ready")

        session.log(f"launching coordinator (session={session_file})")
        session.run(
            "cosmic-ray",
            "--verbosity=INFO",
            "exec",
            str(parallel_config),
            str(session_file),
            env=worker_env,
            success_codes=list(range(256)),
        )
    finally:
        session.log("shutting down workers and cleaning up tempdir")
        shutdown()
        shutil.rmtree(work_base, ignore_errors=True)


@nox.session
def mutation_html(session: nox.Session) -> None:
    """
    Render the cosmic-ray HTML report from ``mutation.sqlite``.

    Run ``nox -s mutation`` first to populate the session file;
    this session reads it and writes ``html/mutation-report.html``
    with per-mutant diff pages. Output is gitignored.

    Pre-flights the session file's existence so the operator gets a
    clear error instead of a half-written empty report (the failure
    mode if ``cr-html`` is shell-redirected to a non-existent
    ``mutation.sqlite``).
    """
    session_file = pathlib.Path("mutation.sqlite")
    if not session_file.is_file():
        session.error(
            f"{session_file} missing — run "
            "``make mutation`` (or ``uv run cosmic-ray init "
            "cosmic-ray.toml mutation.sqlite``) first"
        )
    html_dir = pathlib.Path("html")
    html_dir.mkdir(parents=True, exist_ok=True)
    # Write to a sibling temp file first then atomic-rename, so the
    # rendered report only replaces an existing one when ``cr-html``
    # actually succeeds — otherwise the prior good report (or no
    # file at all) is preserved.
    final = html_dir / "mutation-report.html"
    staging = html_dir / "mutation-report.html.partial"
    with staging.open("wb") as out:
        session.run(
            "cr-html",
            str(session_file),
            stdout=out,
        )
    staging.replace(final)
