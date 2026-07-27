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

import os
import pathlib
import shutil
import socket
import subprocess
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

# Locales we ship translations for. ``en`` is the source language —
# we keep the catalogue inside the tree because the Transifex config
# (``.tx/transifex.yml``) treats it as the source-of-truth file. Add
# new locales here as translations land; the lists are honoured by
# ``makemessages`` (extract), ``compilemessages`` (compile), and the
# ``messages_check`` integrity gate (all in ``_nox/i18n.py``).
LOCALES = ["en", "ru", "uk"]

# Package root — the locale tree lives under ``<PACKAGE_DIR>/locale``.
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

# Dependency group carrying the third-party packages the test suite
# imports directly, independent of the AA / Django versions the lock
# resolves (see ``[dependency-groups].test-runtime`` in pyproject.toml).
# Off-lock sessions select it via ``uv run --group`` NEXT TO the AA
# selector group so everything resolves in one pass under the AA
# group's Django pin. These deps must NOT be threaded as ``--with``:
# a ``uv run --with`` overlay resolves outside the project's
# constraints, and ``--with django-prometheus`` used to pull an
# unconstrained Django 5.2 that shadowed the ``aa4`` venv's Django 4.2
# on ``sys.path`` — surfaced as an AA ``system_package_mariadb`` check
# crash on the MariaDB cell, silent everywhere else.
TEST_RUNTIME_GROUP = "test-runtime"

# Django major version each AA-stack group is expected to resolve.
# Threaded to the import canary (AA_OIDC_EXPECT_DJANGO_MAJOR) so an
# off-lock venv whose Django does not match its cell fails before the
# suite runs. Pinned against the pyproject group specifiers by
# ``tests/unit/test_nox_testing.py``.
AA_GROUP_DJANGO_MAJOR = {"aa4": "4", "aa5": "5"}


def is_ci() -> bool:
    """
    Return ``True`` when running under a CI runner.

    GitHub Actions (and most CI providers) set ``CI=true``; honour the
    common truthy spellings. Used by gates that degrade to a local
    ``session.skip`` when an optional system tool is absent but must
    hard-fail in CI, where the tool is provisioned by an earlier step
    (e.g. ``messages_check`` requires GNU gettext).
    """
    return os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}


def is_docker_available() -> bool:
    """
    Return ``True`` when a usable Docker daemon is reachable.

    Probes ``docker info`` (not just the binary on ``PATH``) because a
    present client with a stopped daemon is the common local failure
    mode. Used by container-backed sessions (e.g. ``tests_mariadb``) to
    degrade to a ``session.skip`` rather than erroring out when Docker
    is unavailable.
    """
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


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


def pick_free_ports(n: int) -> tuple[int, ...]:
    """
    Return ``n`` distinct ephemeral ports the kernel is willing to hand out.

    Binds ``n`` sockets to port 0 *simultaneously* (rather than one
    at a time and closing each) so the kernel cannot recycle a port
    between picks and hand the same number back twice. After
    collecting the assignments the sockets are closed, leaving a
    short TOCTOU window before the caller binds them; for local
    test orchestration this is acceptable — the failure mode is a
    loud ``EADDRINUSE`` from the next binder, not a silent collision.

    ``127.0.0.1`` rather than ``0.0.0.0`` so the reservation matches
    a loopback-only publish (cosmic-ray's ``http-worker`` defaults,
    integration sidecars).
    """
    sockets: list[socket.socket] = []
    try:
        for _ in range(n):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return tuple(s.getsockname()[1] for s in sockets)
    finally:
        for sock in sockets:
            sock.close()
