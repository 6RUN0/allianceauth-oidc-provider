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
from datetime import timedelta
from io import StringIO

from allianceauth.authentication.models import State
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)

from allianceauth_oidc.management.commands._format import render_rows

from ._oidc_testcase import REDIRECT_URI, OIDCTestCase


class TestRenderRowsHelper(OIDCTestCase):
    """Unit tests for the shared format helper — no DB required."""

    def test_table_format_aligns_columns(self) -> None:
        out = render_rows(
            [{"a": "x", "b": "yyyy"}, {"a": "longer", "b": "z"}],
            columns=("a", "b"),
            fmt="table",
        )
        self.assertIn("a", out)
        self.assertIn("longer", out)
        # Column header followed by separator line.
        self.assertIn("\n--", out)

    def test_json_format_is_parseable(self) -> None:
        out = render_rows(
            [{"a": 1, "b": None}],
            columns=("a", "b"),
            fmt="json",
        )
        parsed = json.loads(out)
        self.assertEqual([{"a": 1, "b": ""}], parsed)

    def test_csv_format_has_header_and_row(self) -> None:
        out = render_rows(
            [{"a": "x"}],
            columns=("a",),
            fmt="csv",
        )
        # CSV: header line + value line.
        lines = out.strip().splitlines()
        self.assertEqual(["a", "x"], lines)

    def test_empty_rows_yield_explicit_marker(self) -> None:
        self.assertEqual(
            "(no rows)",
            render_rows([], columns=("a",), fmt="table"),
        )


class TestOIDCCreateAppCommand(OIDCTestCase):
    def test_creates_app_and_emits_credentials(self) -> None:
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Test New App",
            f"--user-id={self.user1.pk}",
            f"--redirect-uri={REDIRECT_URI}",
            "--format=json",
            stdout=out,
        )
        result = json.loads(out.getvalue())
        self.assertEqual(1, len(result))
        row = result[0]
        # Raw client_secret is shown ONCE — operator must capture it.
        self.assertTrue(row["client_secret"])
        self.assertEqual("Test New App", row["name"])
        # App actually exists in the DB with the rendered client_id.
        Application = get_application_model()
        self.assertTrue(
            Application.objects.filter(client_id=row["client_id"]).exists()
        )

    def test_unknown_user_id_fails_loudly(self) -> None:
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=x",
                "--user-id=999999",
                stdout=StringIO(),
            )
        self.assertIn("999999", str(ctx.exception))

    def test_unknown_state_fails_before_app_is_created(self) -> None:
        Application = get_application_model()
        before = Application.objects.count()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=will-not-exist",
                f"--user-id={self.user1.pk}",
                "--state=NoSuchState",
                stdout=StringIO(),
            )
        self.assertIn("NoSuchState", str(ctx.exception))
        # Atomic: failed validation must not leave a partial app.
        self.assertEqual(before, Application.objects.count())

    def test_state_and_group_links_are_persisted(self) -> None:
        State.objects.get_or_create(name="Member")
        grp, _ = Group.objects.get_or_create(name="cmd-grp")
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=With Restrictions",
            f"--user-id={self.user1.pk}",
            "--state=Member",
            "--group=cmd-grp",
            "--format=json",
            stdout=out,
        )
        client_id = json.loads(out.getvalue())[0]["client_id"]
        Application = get_application_model()
        app = Application.objects.get(client_id=client_id)
        self.assertIn("Member", app.states.values_list("name", flat=True))
        self.assertIn(grp, app.groups.all())

    def test_default_pkce_required_is_true(self) -> None:
        """
        No flag → app.pkce_required matches the model default (True,
        per RFC 9700 secure-by-default). The rendered row also shows
        the flag so the operator sees what was created.
        """
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Default PKCE",
            f"--user-id={self.user1.pk}",
            "--format=json",
            stdout=out,
        )
        row = json.loads(out.getvalue())[0]
        self.assertTrue(row["pkce_required"])
        Application = get_application_model()
        app = Application.objects.get(client_id=row["client_id"])
        self.assertTrue(app.pkce_required)

    def test_no_pkce_required_flag_disables(self) -> None:
        """
        ``--no-pkce-required`` (BooleanOptionalAction) is the documented
        opt-out for legacy clients. The created row must persist with
        ``pkce_required=False``.
        """
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Legacy Client",
            f"--user-id={self.user1.pk}",
            "--no-pkce-required",
            "--format=json",
            stdout=out,
        )
        row = json.loads(out.getvalue())[0]
        self.assertFalse(row["pkce_required"])
        Application = get_application_model()
        app = Application.objects.get(client_id=row["client_id"])
        self.assertFalse(app.pkce_required)


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


class TestOIDCRevokeUserTokensCommand(OIDCTestCase):
    def _seed_tokens(self) -> tuple[int, int]:
        """Create one access + one refresh token for user1."""
        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        at = AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="rev-test-at",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        rt = RefreshToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            access_token=at,
            token="rev-test-rt",  # nosec B106
        )
        return at.pk, rt.pk

    def test_dry_run_reports_counts_without_revoking(self) -> None:
        at_pk, _rt_pk = self._seed_tokens()
        out = StringIO()
        call_command(
            "oidc_revoke_user_tokens",
            f"--username={self.user1.username}",
            "--dry-run",
            "--format=json",
            stdout=out,
        )
        result = json.loads(out.getvalue())[0]
        self.assertTrue(result["dry_run"])
        self.assertGreaterEqual(int(result["access_tokens"]), 1)
        # Tokens still present.
        AccessToken = get_access_token_model()
        self.assertTrue(AccessToken.objects.filter(pk=at_pk).exists())

    def test_revokes_access_and_refresh_tokens(self) -> None:
        at_pk, rt_pk = self._seed_tokens()
        out = StringIO()
        call_command(
            "oidc_revoke_user_tokens",
            f"--username={self.user1.username}",
            "--format=json",
            stdout=out,
        )
        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        # ``revoke()`` removes access tokens entirely; refresh tokens
        # are kept but marked revoked. The exact persistence rule is
        # DOT's responsibility; the command's contract is "no longer
        # active".
        self.assertFalse(AccessToken.objects.filter(pk=at_pk).exists())
        # Refresh either gone or revoked.
        rt_qs = RefreshToken.objects.filter(pk=rt_pk)
        if rt_qs.exists():
            self.assertIsNotNone(rt_qs.first().revoked)

    def test_idempotent_on_clean_user(self) -> None:
        # No tokens for user1 — second run is a no-op, no error.
        for _ in range(2):
            out = StringIO()
            call_command(
                "oidc_revoke_user_tokens",
                f"--username={self.user1.username}",
                "--format=json",
                stdout=out,
            )

    def test_unknown_username_fails_loudly(self) -> None:
        with self.assertRaises(CommandError):
            call_command(
                "oidc_revoke_user_tokens",
                "--username=ghost",
                stdout=StringIO(),
            )


class TestOIDCAuditTokensCommand(OIDCTestCase):
    def _seed_token(
        self, *, expired: bool = False, scope: str = "openid"
    ) -> object:
        AccessToken = get_access_token_model()
        delta = timedelta(hours=-1 if expired else 1)
        return AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=f"audit-{'exp' if expired else 'live'}",  # nosec B106
            expires=timezone.now() + delta,
            scope=scope,
        )

    def test_lists_active_tokens_only_by_default(self) -> None:
        live = self._seed_token(expired=False)
        self._seed_token(expired=True)
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--format=json",
            stdout=out,
        )
        ids = {row["id"] for row in json.loads(out.getvalue())}
        self.assertIn(live.pk, ids)
        # Expired is filtered out.
        self.assertEqual(1, len(ids))

    def test_include_expired_widens_listing(self) -> None:
        self._seed_token(expired=False)
        self._seed_token(expired=True)
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--include-expired",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(2, len(rows))

    def test_filter_by_username(self) -> None:
        self._seed_token()
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            f"--username={self.user1.username}",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(self.user1.username, rows[0]["user"])

    def test_filter_by_client_id(self) -> None:
        self._seed_token()
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            f"--client-id={self.oauth_id}",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))

    def test_unknown_username_fails_loudly(self) -> None:
        with self.assertRaises(CommandError):
            call_command(
                "oidc_audit_tokens",
                "--username=ghost",
                stdout=StringIO(),
            )

    def test_audit_surfaces_pkce_required_per_application(self) -> None:
        """
        Each row exposes the application's ``pkce_required`` flag so an
        operator triaging tokens can see "is this from a strict-PKCE
        client?" without context-switching to admin. Both directions of
        the flag are pinned to guard against a regression that hard-
        codes the column to ``True`` (or strips it on
        ``None``-coalesce).
        """
        self._seed_token()
        # Shared fixture ships ``pkce_required=False``; flip it
        # explicitly to assert both directions in one test.
        self.oauth_app.pkce_required = True
        self.oauth_app.save()
        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertTrue(rows[0]["pkce"])

        self.oauth_app.pkce_required = False
        self.oauth_app.save()
        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertFalse(rows[0]["pkce"])
