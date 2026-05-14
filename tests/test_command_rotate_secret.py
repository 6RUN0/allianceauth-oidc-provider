"""
Tests for ``manage.py oidc_*`` operator commands.

The commands are thin wrappers around the ORM; tests verify the
contract operators rely on:

* `--dry-run` on destructive commands does not write.
* `--format=json` produces parseable output.
* Idempotent behaviour (re-running a destructive command on a
  cleaned-up subject is a no-op).
"""

from __future__ import annotations

import json
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError

from ._oidc_testcase import OIDCTestCase


class TestOIDCRotateSecretCommand(OIDCTestCase):
    def test_dry_run_does_not_change_secret(self) -> None:
        original_secret = self.oauth_app.client_secret
        out = StringIO()
        call_command(
            "oidc_rotate_secret",
            f"--client-id={self.oauth_id}",
            "--dry-run",
            "--format=json",
            stdout=out,
        )
        self.oauth_app.refresh_from_db()
        self.assertEqual(original_secret, self.oauth_app.client_secret)
        result = json.loads(out.getvalue())
        self.assertTrue(result[0]["dry_run"])

    def test_writes_new_secret_on_real_run(self) -> None:
        original_secret = self.oauth_app.client_secret
        out = StringIO()
        call_command(
            "oidc_rotate_secret",
            f"--client-id={self.oauth_id}",
            "--format=json",
            stdout=out,
        )
        self.oauth_app.refresh_from_db()
        self.assertNotEqual(original_secret, self.oauth_app.client_secret)
        result = json.loads(out.getvalue())
        # Raw secret in the response, not the hashed one in DB.
        self.assertTrue(result[0]["client_secret"])

    def test_unknown_client_id_fails_loudly(self) -> None:
        with self.assertRaises(CommandError):
            call_command(
                "oidc_rotate_secret",
                "--client-id=does-not-exist",
                stdout=StringIO(),
            )

    def test_missing_client_id_argument_is_rejected(self) -> None:
        # Pin ``required=True`` on ``--client-id``.
        # ``ReplaceTrueWithFalse`` would make argparse accept an
        # empty invocation, and the command would crash downstream
        # on ``Application.objects.get(client_id=None)``.
        with self.assertRaises(CommandError):
            call_command(
                "oidc_rotate_secret",
                stdout=StringIO(),
            )

    def test_dry_run_secret_prefix_is_exactly_four_characters(self) -> None:
        # Pin ``new_secret[:4] + "…"`` against ``NumberReplacer``
        # flipping the slice bound to 3 or 5. The existing
        # ``test_dry_run_does_not_change_secret`` reads the row but
        # never inspects the prefix length; a flip would silently
        # leak more or fewer characters of the about-to-be-set
        # secret.
        out = StringIO()
        call_command(
            "oidc_rotate_secret",
            f"--client-id={self.oauth_id}",
            "--dry-run",
            "--format=json",
            stdout=out,
        )
        rendered = json.loads(out.getvalue())[0]["would_set_secret_prefix"]
        # Trailing ellipsis ``"…"`` plus exactly 4 prefix characters.
        self.assertTrue(rendered.endswith("…"))
        prefix = rendered[:-1]
        self.assertEqual(
            4,
            len(prefix),
            f"prefix length {len(prefix)} differs from expected 4 — "
            "NumberReplacer on the slice bound?",
        )
