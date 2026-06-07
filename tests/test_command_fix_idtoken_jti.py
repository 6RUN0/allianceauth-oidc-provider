"""
Tests for ``manage.py oidc_fix_idtoken_jti``.

The command converts DOT's ``oauth2_provider_idtoken.jti`` to the native
``uuid`` type Django expects on MariaDB >= 10.7. It must be a safe no-op
on every other backend, so on the sqlite default suite it reports
``skipped`` and never touches the schema. The actual ALTER is exercised
only on a native-uuid backend (the MariaDB smoke).
"""

from __future__ import annotations

import json
from io import StringIO

from django.core.management import call_command
from django.db import connection

from ._oidc_testcase import OIDCTestCase


class TestOIDCFixIdtokenJtiCommand(OIDCTestCase):
    def _run(self, *args: str) -> dict:
        out = StringIO()
        call_command(
            "oidc_fix_idtoken_jti", "--format=json", *args, stdout=out
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        return rows[0]

    def test_runs_without_error_and_reports_action(self) -> None:
        row = self._run()
        self.assertIn(row["action"], {"skipped", "noop", "altered"})

    def test_noop_on_non_native_backend(self) -> None:
        # sqlite (and any non-MariaDB->=10.7 backend) has no native uuid
        # type, so the command must skip without altering anything.
        is_native = (
            connection.vendor == "mysql"
            and getattr(connection, "mysql_is_mariadb", False)
            and connection.mysql_version >= (10, 7)
        )
        row = self._run()
        if is_native:
            # Fresh smoke schema already created the column as native uuid.
            self.assertEqual("noop", row["action"])
        else:
            self.assertEqual("skipped", row["action"])

    def test_dry_run_never_alters(self) -> None:
        # On a non-native backend the dry-run is indistinguishable from a
        # plain run (both skip); the assertion is that it stays read-only
        # and parseable regardless of backend.
        row = self._run("--dry-run")
        self.assertNotEqual("altered", row["action"])
