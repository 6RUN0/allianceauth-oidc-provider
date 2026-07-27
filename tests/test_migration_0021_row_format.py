"""
Tests for the row-format pre-step in migration 0021.

0021 widens ``client_id`` to 255 chars and rebuilds its unique index —
255 x 4 bytes under utf8mb4 = 1020 bytes, over the 767-byte index
limit of InnoDB's legacy ``COMPACT``/``REDUNDANT`` row formats
(``ERROR 1071``). The migration therefore opens with a conditional
``RunPython`` that converts the application table to ``DYNAMIC``
first, but only on a MySQL-family backend and only when
``information_schema`` reports a legacy format. Everywhere else
(sqlite, PostgreSQL, already-DYNAMIC tables — the default since
MariaDB 10.2 / MySQL 5.7) it must not touch the schema.

Mock-based unit tier: sqlite cannot express ``ROW_FORMAT`` at all, so
the MariaDB decision paths are pinned against a faked connection; the
real-backend end-to-end coverage is the ``tests_mariadb`` cells, where
this migration runs during test-database creation (fresh tables are
``DYNAMIC`` → the no-op path executes for real on every run).
"""

from __future__ import annotations

from importlib import import_module
from unittest import mock

from django.db import migrations as dj_migrations
from django.test import SimpleTestCase

_MIGRATION_MODULE = (
    "allianceauth_oidc.migrations"
    ".0021_allianceauthapplication_cimd_expires_at_and_more"
)

_TABLE = "allianceauth_oidc_allianceauthapplication"


def _fake_schema_editor(vendor: str, row_format: str | None):
    """Build a schema_editor mock whose cursor reports ``row_format``."""
    cursor = mock.MagicMock()
    cursor.fetchone.return_value = (
        (row_format,) if row_format is not None else None
    )
    cm = mock.MagicMock()
    cm.__enter__.return_value = cursor
    cm.__exit__.return_value = False
    connection = mock.MagicMock()
    connection.vendor = vendor
    connection.cursor.return_value = cm
    connection.ops.quote_name = lambda name: f"`{name}`"
    schema_editor = mock.MagicMock()
    schema_editor.connection = connection
    return schema_editor, cursor


def _fake_apps():
    """Historical-apps mock resolving the application model's table."""
    model = mock.MagicMock()
    model._meta.db_table = _TABLE
    apps = mock.MagicMock()
    apps.get_model.return_value = model
    return apps


class TestEnsureDynamicRowFormat(SimpleTestCase):
    def setUp(self) -> None:
        self.migration = import_module(_MIGRATION_MODULE)

    def _run(self, vendor: str, row_format: str | None):
        schema_editor, cursor = _fake_schema_editor(vendor, row_format)
        self.migration._ensure_dynamic_row_format(_fake_apps(), schema_editor)
        return [call.args[0] for call in cursor.execute.call_args_list]

    def test_noop_on_non_mysql_vendor(self) -> None:
        # sqlite / postgres have no ROW_FORMAT concept; the helper must
        # return before issuing any SQL at all.
        self.assertEqual(self._run("sqlite", None), [])
        self.assertEqual(self._run("postgresql", None), [])

    def test_alters_compact_table_to_dynamic(self) -> None:
        statements = self._run("mysql", "Compact")
        self.assertEqual(2, len(statements), statements)
        self.assertIn("ROW_FORMAT=DYNAMIC", statements[1])
        self.assertIn(_TABLE, statements[1])

    def test_alters_redundant_table_to_dynamic(self) -> None:
        statements = self._run("mysql", "REDUNDANT")
        self.assertEqual(2, len(statements), statements)
        self.assertIn("ROW_FORMAT=DYNAMIC", statements[1])

    def test_noop_when_already_dynamic(self) -> None:
        statements = self._run("mysql", "Dynamic")
        # Exactly the information_schema probe — no ALTER.
        self.assertEqual(1, len(statements), statements)
        self.assertNotIn("ALTER", statements[0].upper())

    def test_noop_when_table_missing(self) -> None:
        # A fresh install where the operation order somehow probes
        # before the table exists must not crash the migration.
        statements = self._run("mysql", None)
        self.assertEqual(1, len(statements), statements)


class TestMigration0021Wiring(SimpleTestCase):
    def test_row_format_step_precedes_client_id_alter(self) -> None:
        # The RunPython must be the FIRST operation: the 1020-byte
        # unique index is built by the client_id AlterField, so the
        # row format has to be DYNAMIC before that runs.
        migration_module = import_module(_MIGRATION_MODULE)
        operations = migration_module.Migration.operations
        first = operations[0]
        self.assertIsInstance(first, dj_migrations.RunPython)
        self.assertIs(first.code, migration_module._ensure_dynamic_row_format)
        # Reversible so ``migrate`` back across 0021 stays possible —
        # DYNAMIC is a safe format to leave behind on rollback.
        self.assertIsNotNone(first.reverse_code)
