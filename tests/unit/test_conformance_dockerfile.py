"""
Drift gate: ``Dockerfile.provider``'s ``tests/`` slice vs real imports.

The conformance provider image copies a *granular* slice of ``tests/``
(settings, URLConf, fakeredis hook, RSA key) instead of the whole
package, so the image stays free of the host-only unit-test suite. The
cost of that granularity is drift: any new ``from tests.X import`` in
the settings chain silently breaks the container at boot
(``ModuleNotFoundError`` -> healthcheck failure -> ``compose up --wait``
exit 1) without any host-side test noticing. That is exactly how the
``tests._mariadb_container`` import added for the MariaDB smoke broke
the ``conformance``/``conformance_basic`` sessions.

This gate statically computes the transitive ``tests.*`` import closure
of the container's Python entrypoints (settings, ``seed.py``,
``wsgi.py``) — including dotted-path *strings* like
``ROOT_URLCONF = "tests.urls"`` — and asserts every resolved file is
named in a ``COPY`` instruction of ``Dockerfile.provider``.

ORM-free unit tier: pure file parsing, no Django, no nox runtime.
"""

from __future__ import annotations

import pathlib
import re
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO_ROOT / "tests" / "conformance" / "Dockerfile.provider"

# Python entrypoints executed inside the provider container
# (``entrypoint.sh``: migrate/seed via ``DJANGO_SETTINGS_MODULE`` and
# gunicorn via ``wsgi:application``). Repo-relative.
_CONTAINER_ENTRYPOINTS = (
    "tests/conformance/conformance_settings.py",
    "tests/conformance/seed.py",
    "tests/conformance/wsgi.py",
)

# ``from tests.x.y import ...`` / ``import tests.x.y`` at any indent
# (lazy in-function imports run in-container too).
_IMPORT_RE = re.compile(
    r"^\s*(?:from|import)\s+(tests(?:\.\w+)+)", re.MULTILINE
)
# Dotted module paths referenced as settings strings, e.g.
# ``ROOT_URLCONF = "tests.urls"`` — imported by Django at runtime just
# the same.
_STRING_RE = re.compile(r"""["'](tests(?:\.\w+)+)["']""")


def _module_to_file(module: str) -> pathlib.Path | None:
    """Map ``tests.x.y`` to its repo file, or ``None`` if unresolvable."""
    candidate = _REPO_ROOT / pathlib.Path(*module.split("."))
    for path in (
        candidate.with_suffix(".py"),
        candidate / "__init__.py",
    ):
        if path.is_file():
            return path
    return None


def _import_closure(roots: tuple[str, ...]) -> set[str]:
    """Repo-relative files reachable from ``roots`` via ``tests.*``."""
    seen: set[str] = set()
    queue = [_REPO_ROOT / root for root in roots]
    while queue:
        path = queue.pop()
        rel = path.relative_to(_REPO_ROOT).as_posix()
        if rel in seen:
            continue
        seen.add(rel)
        source = path.read_text(encoding="utf-8")
        modules = set(_IMPORT_RE.findall(source))
        modules |= set(_STRING_RE.findall(source))
        for module in sorted(modules):
            resolved = _module_to_file(module)
            if resolved is not None:
                queue.append(resolved)
    return seen


def _copied_paths() -> set[str]:
    """``tests/...`` source tokens across all Dockerfile COPY lines."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    # Join backslash continuations so a multi-line COPY reads as one
    # logical instruction.
    logical = text.replace("\\\n", " ")
    copied: set[str] = set()
    for line in logical.splitlines():
        stripped = line.strip()
        if not stripped.startswith("COPY "):
            continue
        # Last token is the destination; everything between COPY and it
        # is a source. Destinations start with ``./`` in this file, but
        # keep the slice defensive and drop the final token regardless.
        tokens = stripped.split()[1:-1]
        copied.update(t for t in tokens if t.startswith("tests/"))
    return copied


class ConformanceImageSliceTests(unittest.TestCase):
    """The granular COPY slice must cover the runtime import closure."""

    def test_copy_slice_covers_container_import_closure(self) -> None:
        needed = _import_closure(_CONTAINER_ENTRYPOINTS)
        copied = _copied_paths()
        missing = sorted(needed - copied)
        self.assertEqual(
            [],
            missing,
            "Modules imported by the conformance provider container are "
            "not copied into the image by Dockerfile.provider "
            f"(add them to the COPY slice): {missing}",
        )

    def test_closure_reaches_known_anchors(self) -> None:
        # Self-check that the static scan is actually following the
        # chain: were the regexes to rot, the closure would silently
        # shrink and the gate above would pass vacuously.
        needed = _import_closure(_CONTAINER_ENTRYPOINTS)
        self.assertIn("tests/test_settingsAA4.py", needed)
        self.assertIn("tests/_fakeredis.py", needed)
        self.assertIn("tests/urls.py", needed)
        self.assertIn("tests/conformance/runner/config.py", needed)


if __name__ == "__main__":
    unittest.main()
