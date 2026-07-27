"""
Import-only sweep of ``tests/test_*.py`` for the AA4 venv shape.

This guards against the class of bug where a test module
top-level-imports a package that ``[dependency-groups].aa4`` plus the
``test-runtime`` group do not provide. Django's test discovery would
crash with ``ModuleNotFoundError`` before any test ran, masking the
underlying "missing test-runtime entry" cause behind a long
unittest-loader traceback.

The sweep also verifies the venv's Django major against the cell's
expectation (``AA_OIDC_EXPECT_DJANGO_MAJOR``, threaded by the matrix
sessions from their AA group). Regression guard for the ``uv run
--with`` overlay bug where an unconstrained Django 5.2 shadowed the
``aa4`` group's Django 4.2 and the matrix silently stopped testing
the stack it was named after.

The helper runs in the AA4 venv (provisioned by ``tests_aa4``) right
before ``django test``. It collects every failure rather than
exiting on the first one, so a single CI run reports the complete
set of broken modules — operators don't have to fix-rerun-fix-rerun.

``django.setup()`` runs first — many test modules use
``allianceauth_oidc`` model imports at module scope, which require
the app registry to be ready. Without it every module except the
one with the actually-missing dep would falsely fail with
``AppRegistryNotReady``, drowning the real signal. The Django
settings module is taken from the caller's environment
(``DJANGO_SETTINGS_MODULE``); the ``tests_aa4`` nox session sets it
to ``tests.test_settingsAA4`` via ``test_env()``.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import sys


def django_version_mismatch(
    expected_major: str | None, actual_version: str
) -> str | None:
    """
    Return an error message when ``actual_version`` has the wrong major.

    ``expected_major`` is the cell's expected Django major version
    (e.g. ``"4"`` for the ``aa4`` group); ``None`` or ``""`` means the
    caller has no expectation (``tests_compat`` with an arbitrary
    ``AA_PIN``) and the guard stays silent.
    """
    if not expected_major:
        return None
    if actual_version.split(".", 1)[0] == expected_major:
        return None
    return (
        f"Django {actual_version} resolved in this venv, but the cell "
        f"expects Django {expected_major}.x. A dependency threaded via "
        "'uv run --with' likely pulled its own Django into the overlay "
        "environment, shadowing the AA group's pin — move it into a "
        "dependency group (see pyproject.toml::test-runtime) instead."
    )


def main() -> int:
    """Return 0 on success, 1 if any tests/test_*.py fails to import."""
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    tests_dir = repo_root / "tests"
    sys.path.insert(0, str(repo_root))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settingsAA4")
    import django

    mismatch = django_version_mismatch(
        os.environ.get("AA_OIDC_EXPECT_DJANGO_MAJOR"), django.get_version()
    )
    if mismatch:
        print(mismatch, file=sys.stderr)
        return 1

    django.setup()

    errors: list[str] = []
    # Top-level suite modules plus the ORM-free unit tier under
    # tests/unit/. ``tests/conformance/`` is deliberately excluded — its
    # modules pull docker/orchestration deps the off-lock test venv does
    # not (and should not) provision. The dotted module name is derived
    # from the path relative to the repo root so a sub-package module
    # (``tests/unit/test_x.py``) resolves to ``tests.unit.test_x`` rather
    # than a bare ``tests.test_x``.
    paths = sorted(
        [*tests_dir.glob("test_*.py"), *tests_dir.glob("unit/test_*.py")]
    )
    for path in paths:
        name = ".".join(path.relative_to(repo_root).with_suffix("").parts)
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"  {name}: {type(exc).__name__}: {exc}")

    if errors:
        header = (
            "Test-module import failures (likely a missing entry in "
            "pyproject.toml::[dependency-groups].test-runtime or a "
            "misplaced top-level import in tests/):"
        )
        print(header, file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"canary OK: {len(paths)} test modules importable in this venv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
