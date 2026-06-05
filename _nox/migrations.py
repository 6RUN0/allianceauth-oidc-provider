"""
Migration sessions — the single owner of the migration toolchain.

Mirrors ``_nox/i18n.py``: every migration-related session lives here
rather than being split between ``noxfile.py`` and a separate gate
module.

* ``makemigrations`` — generate migrations for ``allianceauth_oidc``.
* ``migrations_check`` — model/migration sync plus the
  ``django-migration-linter`` backward-compatibility pass.
* ``migrations_concurrency_check`` — MySQL/MariaDB online-DDL gate over
  raw ``RunSQL`` operations (pure AST, no Django boot).

The two checks are deliberately disjoint. ``migrations_check`` boots
Django and runs ``django-migration-linter``, which reasons about ORM
operations (data-loss drops, ``NOT NULL`` additions, type changes).
``migrations_concurrency_check`` covers the linter's blind spot — raw
SQL — and is a fast, Django-free scan, so it can run in the lint job
next to the other static gates. See ``_nox/_migration_scan.py`` for the
online-DDL policy and why it targets ``RunSQL`` rather than ORM
operations.
"""

from __future__ import annotations

import nox

from _nox._migration_scan import find_blocking_runsql
from _nox.shared import PACKAGE_DIR, TEST_SETTINGS, test_env

_MIGRATIONS_DIR = PACKAGE_DIR / "migrations"


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
        env=test_env(session),
    )


@nox.session
def migrations_check(session: nox.Session) -> None:
    """
    Verify migrations are in sync and free of unsafe operations.

    Two checks run in sequence:

    1. ``makemigrations --check --dry-run`` — writes nothing, exits
       non-zero if the model layer would generate a fresh migration.
       Catches an out-of-sync model change before it reaches CI.
    2. ``django-migration-linter`` (lintmigrations) — flags unsafe
       operations such as irreversible column drops, ``NOT NULL``
       additions without defaults, renames that break running
       deployments. Run via ``uv run --with`` so the linter does
       not pollute the dev dependency group; the dedicated settings
       module ``tests.test_settings_migration_linter`` pins ten
       pre-existing migrations as baseline so the gate fires only on
       new findings.

    Raw-SQL concurrency is covered separately by
    ``migrations_concurrency_check`` (the linter does not read raw SQL).
    """
    session.run(
        "python",
        "-m",
        "django",
        "makemigrations",
        "allianceauth_oidc",
        "--check",
        "--dry-run",
        f"--settings={TEST_SETTINGS}",
        env=test_env(session),
    )
    session.run(
        "uv",
        "run",
        "--with",
        "django-migration-linter",
        "python",
        "-m",
        "django",
        "lintmigrations",
        "--include-apps",
        "allianceauth_oidc",
        "--settings=tests.test_settings_migration_linter",
        env=test_env(session),
        external=True,
    )


@nox.session
def migrations_concurrency_check(session: nox.Session) -> None:
    """
    Flag raw ``RunSQL`` DDL that would block writers on MySQL/MariaDB.

    A fast, Django-free AST scan of every ``allianceauth_oidc`` migration
    (``0001_initial`` is skipped — initial schema creation has no live
    table to lock). A ``RunSQL`` operation that issues blocking DDL must
    either annotate it online (``ALGORITHM=INPLACE, LOCK=NONE`` /
    ``ALGORITHM=INSTANT``) or carry the reasoned opt-out marker
    ``# allianceauth-oidc: blocking-op-ok - <reason>``. See
    ``_nox/_migration_scan.py`` for the full policy.

    Complements ``migrations_check``: the ``django-migration-linter`` pass
    there reasons about ORM operations but cannot read raw SQL, which is
    exactly where the online-DDL footgun lives.
    """
    files = sorted(
        path
        for path in _MIGRATIONS_DIR.glob("0*.py")
        if not path.name.startswith("0001_")
    )
    failures: list[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        failures.extend(
            f"  {path.name}:{finding.lineno}: {finding.reason}"
            for finding in find_blocking_runsql(source)
        )

    if failures:
        session.error(
            "Blocking migration DDL found (annotate online or add an "
            "opt-out marker):\n" + "\n".join(failures)
        )
    session.log(
        f"migrations_concurrency_check OK: {len(files)} migration(s) scanned"
    )
