"""
Tests for ``manage.py oidc_fix_uuid_columns``.

The command converts DOT's native-uuid columns
(``oauth2_provider_idtoken.jti`` and
``oauth2_provider_refreshtoken.token_family``) to the native ``uuid``
type Django expects on MariaDB >= 10.7. It must be a safe no-op on every
other backend, so on the sqlite default suite it reports ``skipped`` for
each column and never touches the schema. The actual ALTER is exercised
only on a native-uuid backend (the MariaDB smoke).
"""

from __future__ import annotations

import json
from io import StringIO

from django.core.management import call_command
from django.db import connection

from ._oidc_testcase import OIDCTestCase

# Columns the command diagnoses/fixes, in emission order.
_EXPECTED_COLUMNS = {"jti", "token_family"}


class TestOIDCFixUuidColumnsCommand(OIDCTestCase):
    def _run(self, *args: str) -> list[dict]:
        out = StringIO()
        call_command(
            "oidc_fix_uuid_columns", "--format=json", *args, stdout=out
        )
        rows = json.loads(out.getvalue())
        # One row per target column.
        self.assertEqual(len(_EXPECTED_COLUMNS), len(rows))
        self.assertEqual(_EXPECTED_COLUMNS, {r["column"] for r in rows})
        return rows

    def test_runs_without_error_and_reports_action(self) -> None:
        for row in self._run():
            self.assertIn(row["action"], {"skipped", "noop", "altered"}, row)

    def test_noop_on_non_native_backend(self) -> None:
        # Native-uuid is a *Django* feature (5.x on MariaDB >= 10.7),
        # not a bare MariaDB-version property: Django 4.2 writes
        # 32-char hex on the same server and its char(32) columns are
        # correct. The command must mirror
        # ``connection.features.has_native_uuid_field`` — on the AA4
        # MariaDB cell (Django 4.2) it must skip, not convert.
        is_native = connection.vendor == "mysql" and getattr(
            connection.features, "has_native_uuid_field", False
        )
        for row in self._run():
            if is_native:
                # Fresh smoke schema already created columns as native.
                self.assertEqual("noop", row["action"], row)
            else:
                self.assertEqual("skipped", row["action"], row)

    def test_skips_when_django_has_no_native_uuid(self) -> None:
        # Simulated Django <= 4.2 backend: MariaDB >= 10.7 but no
        # ``has_native_uuid_field`` feature. Converting a char(32)
        # column there is premature — Django still writes 32-char hex —
        # and the ALTER's implicit commit is exactly what poisoned the
        # AA4 MariaDB suite run. ``--dry-run`` keeps this test
        # read-only on every backend.
        from unittest import mock

        cursor = mock.MagicMock()
        cursor.fetchone.return_value = ("char",)
        cm = mock.MagicMock()
        cm.__enter__.return_value = cursor
        cm.__exit__.return_value = False
        conn = mock.MagicMock()
        conn.vendor = "mysql"
        conn.mysql_is_mariadb = True
        conn.mysql_version = (10, 11)
        conn.features.has_native_uuid_field = False
        conn.cursor.return_value = cm

        with (
            mock.patch(
                "allianceauth_oidc.management.commands"
                ".oidc_fix_uuid_columns.connections",
                {"default": conn},
            ),
            mock.patch(
                "django.db.router.db_for_write", return_value="default"
            ),
        ):
            rows = self._run("--dry-run")
        for row in rows:
            self.assertEqual("skipped", row["action"], row)

    def test_dry_run_never_alters(self) -> None:
        # On a non-native backend the dry-run is indistinguishable from a
        # plain run (both skip); the assertion is that it stays read-only
        # and parseable regardless of backend.
        for row in self._run("--dry-run"):
            self.assertNotEqual("altered", row["action"], row)
