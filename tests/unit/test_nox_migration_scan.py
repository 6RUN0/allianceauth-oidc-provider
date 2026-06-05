"""
Golden tests for the blocking-DDL migration scanner.

Pin the classification :func:`find_blocking_runsql` makes for every
branch of the MySQL/MariaDB online-DDL policy: a bare blocking
``ALTER`` fails, the same statement annotated ``ALGORITHM=INPLACE,
LOCK=NONE`` (or ``ALGORITHM=INSTANT``) passes, a reasoned opt-out marker
waives it, a bare marker does not, and pure DML / whole-table creation
is never flagged. Dynamic (non-literal) SQL must carry the marker.

ORM-free unit tier: a pure import from ``_nox._migration_scan`` — no
Django models, no nox runtime (the canary sweeps ``tests/unit/``).
"""

from __future__ import annotations

import textwrap
import unittest

from _nox._migration_scan import find_blocking_runsql


def _migration(operations_body: str) -> str:
    """Wrap an ``operations`` list body in a minimal migration module."""
    return (
        "from django.db import migrations\n\n\n"
        "class Migration(migrations.Migration):\n"
        "    operations = [\n"
        + textwrap.indent(textwrap.dedent(operations_body), " " * 8)
        + "    ]\n"
    )


class FindBlockingRunsqlTests(unittest.TestCase):
    """Branch-by-branch parity for the blocking-DDL classifier."""

    def test_bare_blocking_alter_is_flagged(self) -> None:
        src = _migration(
            'migrations.RunSQL("ALTER TABLE app ADD COLUMN c integer"),\n'
        )
        findings = find_blocking_runsql(src)
        self.assertEqual(len(findings), 1)
        self.assertIn("online-DDL clause", findings[0].reason)

    def test_inplace_lock_none_passes(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "ALTER TABLE app ADD COLUMN c integer, "\n'
            '    "ALGORITHM=INPLACE, LOCK=NONE"\n'
            "),\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_algorithm_instant_passes(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "ALTER TABLE app ADD COLUMN c integer, ALGORITHM=INSTANT"\n'
            "),\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_inplace_without_lock_is_flagged(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "ALTER TABLE app ADD COLUMN c integer, ALGORITHM=INPLACE"\n'
            "),\n"
        )
        self.assertEqual(len(find_blocking_runsql(src)), 1)

    def test_reasoned_marker_inline_waives(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "ALTER TABLE app ADD COLUMN c integer"\n'
            "),  # allianceauth-oidc: blocking-op-ok - off-peak window\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_reasoned_marker_above_waives(self) -> None:
        src = _migration(
            "# allianceauth-oidc: blocking-op-ok - tiny table\n"
            'migrations.RunSQL("ALTER TABLE app ADD COLUMN c integer"),\n'
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_bare_marker_is_flagged(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "ALTER TABLE app ADD COLUMN c integer"\n'
            "),  # allianceauth-oidc: blocking-op-ok\n"
        )
        findings = find_blocking_runsql(src)
        self.assertEqual(len(findings), 1)
        self.assertIn("mandatory reason", findings[0].reason)

    def test_pure_dml_is_not_flagged(self) -> None:
        src = _migration(
            'migrations.RunSQL("UPDATE app SET c = 1 WHERE c IS NULL"),\n'
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_create_table_is_not_flagged(self) -> None:
        src = _migration(
            'migrations.RunSQL("CREATE TABLE app_new (id integer)"),\n'
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_create_index_without_clause_is_flagged(self) -> None:
        src = _migration('migrations.RunSQL("CREATE INDEX idx ON app (c)"),\n')
        self.assertEqual(len(find_blocking_runsql(src)), 1)

    def test_create_index_online_passes(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            '    "CREATE INDEX idx ON app (c) ALGORITHM=INPLACE LOCK=NONE"\n'
            "),\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_dynamic_sql_requires_marker(self) -> None:
        src = _migration("migrations.RunSQL(STATEMENT),\n")
        findings = find_blocking_runsql(src)
        self.assertEqual(len(findings), 1)
        self.assertIn("dynamically", findings[0].reason)

    def test_dynamic_sql_with_marker_passes(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            "    STATEMENT\n"
            "),  # allianceauth-oidc: blocking-op-ok - reviewed by dba\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])

    def test_bare_runsql_name_is_detected(self) -> None:
        src = (
            "from django.db.migrations import RunSQL\n\n\n"
            "class Migration:\n"
            "    operations = [\n"
            '        RunSQL("ALTER TABLE app ADD COLUMN c integer"),\n'
            "    ]\n"
        )
        self.assertEqual(len(find_blocking_runsql(src)), 1)

    def test_runsql_noop_is_not_flagged(self) -> None:
        src = _migration("migrations.RunSQL(migrations.RunSQL.noop),\n")
        self.assertEqual(find_blocking_runsql(src), [])

    def test_statement_list_flags_blocking_member(self) -> None:
        src = _migration(
            "migrations.RunSQL(\n"
            "    [\n"
            '        "UPDATE app SET c = 1",\n'
            '        "ALTER TABLE app ADD COLUMN d integer",\n'
            "    ]\n"
            "),\n"
        )
        self.assertEqual(len(find_blocking_runsql(src)), 1)

    def test_clear_migration_returns_empty(self) -> None:
        src = _migration(
            'migrations.AddField("app", "c", None),\n'
            "migrations.RunPython(lambda *a: None),\n"
        )
        self.assertEqual(find_blocking_runsql(src), [])
