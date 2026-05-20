"""
Distribution-shape verification session.

``verify_wheel`` builds a wheel into a throwaway directory and audits
its manifest against two pinned inventories:

* a *required* set — files whose absence demotes a downstream feature
  silently (locale ``.mo`` binaries fall back to source strings;
  the Django migration package collapses if ``__init__.py`` is missing;
  ``apps.py`` is the entry point AA loads on startup);
* a *forbidden* set — patterns that should never reach a published
  artefact (build-time scratch, the test suite, nox plumbing, the
  Makefile).

The pattern is borrowed from ``eveo7-mumbleserver-ice``'s
``verify_wheel`` (which guards its PEP 561 surface the same way) and
codifies the manual ``python -m zipfile -l dist/*.whl | grep ...``
checks the operator would otherwise run by hand after every backend
change. The 0.3.0 release-cut surfaced exactly that gap: the Makefile
``package`` target had silently rotted onto ``flit build`` after the
backend migrated to ``uv_build``, and the failure was invisible
until ``make package`` was invoked. With this gate green, a future
backend swap or ``[tool.uv.build-backend]`` tweak that drops the
locale tree from the wheel fails CI rather than landing in PyPI.
"""

from __future__ import annotations

import pathlib
import tempfile
import zipfile

import nox

# Files we expect to find inside every published wheel. Keep the set
# small and load-bearing — pinning every Python source file turns
# this gate into a churning maintenance burden without catching new
# regression classes. The chosen entries each represent a distinct
# packaging contract:
#
# * ``__init__.py`` — the Python package itself; missing = no import.
# * ``apps.py`` — AA's AppConfig entry point; missing = startup error
#   on ``INSTALLED_APPS`` load.
# * ``migrations/__init__.py`` + ``0001_initial.py`` — Django will
#   silently treat a migration-less app as ``--fake``-only on first
#   run; the inventory has to assert at least the bootstrap is
#   shipped.
# * ``locale/*/LC_MESSAGES/django.mo`` — compiled translation
#   catalogues. The source ``.po`` files are nice-to-have but Django
#   only loads ``.mo``; without them every user-facing string falls
#   back to English. Pinning all three locales we ship (en / ru / uk)
#   also catches a missing locale before it lands.
_REQUIRED_WHEEL_FILES: tuple[str, ...] = (
    "allianceauth_oidc/__init__.py",
    "allianceauth_oidc/apps.py",
    "allianceauth_oidc/migrations/__init__.py",
    "allianceauth_oidc/migrations/0001_initial.py",
    "allianceauth_oidc/locale/en/LC_MESSAGES/django.mo",
    "allianceauth_oidc/locale/ru/LC_MESSAGES/django.mo",
    "allianceauth_oidc/locale/uk/LC_MESSAGES/django.mo",
)

# Substring patterns that must not appear anywhere in the wheel's
# namelist. Matching is substring-based (not glob) so a path like
# ``allianceauth_oidc/tests/__init__.py`` is caught the same as a
# top-level ``tests/__init__.py``. The forbidden set is intentionally
# narrow — false positives here block legitimate releases, so each
# entry is something a clean ``uv build`` of the project can never
# legitimately produce.
_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    "__pycache__",  # build-time bytecode scratch
    ".pyc",  # compiled Python (should never ship in source wheels)
    ".tmp",  # editor / build temp artefacts
    "tests/",  # repo's test suite — excluded by uv-build by default
    "_nox/",  # nox session plumbing
    "noxfile.py",  # nox entry point
    "/Makefile",  # build shim — leading slash so README-style
    # paths (e.g. references in docstrings) cannot
    # false-positive
    "conftest.py",  # pytest config — also test-only
)


@nox.session
def verify_wheel(session: nox.Session) -> None:
    """
    Build a wheel into a tempdir and audit its file inventory.

    Catches packaging regressions that no other gate sees: a wheel
    that ``twine check`` accepts and that ``pip install`` happily
    consumes can still be missing a locale binary or shipping the
    test suite by accident. This session runs ``uv build --wheel``
    into a throwaway directory, enumerates the resulting zip's
    namelist, and asserts both the must-have inventory
    (``_REQUIRED_WHEEL_FILES``) and the must-not-have inventory
    (``_FORBIDDEN_PATTERNS``).

    Designed as a pre-release gate — runs in well under a second once
    the build cache is warm. Cheap enough to wire into CI alongside
    ``twine check``; complementary, not redundant.
    """
    with tempfile.TemporaryDirectory(prefix="verify-wheel-") as tmp:
        out_dir = pathlib.Path(tmp)
        session.run(
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(out_dir),
            external=True,
        )
        wheels = list(out_dir.glob("*.whl"))
        if not wheels:
            session.error("uv build produced no wheel")
        if len(wheels) != 1:
            session.error(
                "expected exactly one wheel, got "
                f"{len(wheels)}: " + ", ".join(w.name for w in wheels)
            )
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as zf:
            names = set(zf.namelist())

        missing = sorted(set(_REQUIRED_WHEEL_FILES) - names)
        if missing:
            session.error(
                "wheel missing required files:\n  "
                + "\n  ".join(missing)
                + "\nReview the build-backend configuration in "
                "pyproject.toml (``[tool.uv.build-backend]``) and the "
                "source-tree layout."
            )

        forbidden = sorted(
            n for n in names if any(p in n for p in _FORBIDDEN_PATTERNS)
        )
        if forbidden:
            session.error(
                "wheel contains forbidden entries:\n  "
                + "\n  ".join(forbidden)
                + "\nReview the build-backend include/exclude rules."
            )

        session.log(
            f"{wheel.name} OK — ships {len(_REQUIRED_WHEEL_FILES)} "
            f"required files; no forbidden patterns out of "
            f"{len(names)} total entries."
        )
