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
from typing import Any

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
from oauth2_provider.settings import oauth2_settings

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

    def test_json_uses_two_space_indent(self) -> None:
        # ``json.dumps(..., indent=2, ...)`` pins exactly two spaces
        # of indentation per nested level. ``NumberReplacer`` flips
        # the literal to 1 / 3 (or 0 which yields a single-line
        # document — observable here as the absence of newlines).
        # Operator habit: parse pipelines tab-complete on a stable
        # indent so a flip silently breaks awk/grep filters.
        #
        # Output shape for one row: ``[\n  {\n    "a": 1\n  }\n]``
        # — top-level array gets 2 spaces, nested object key gets 4.
        out = render_rows([{"a": 1}], columns=("a",), fmt="json")
        # Top-level array element indented by exactly 2 spaces.
        self.assertIn("[\n  {", out)
        # Three-space indent (NumberReplacer 2 -> 3) would render
        # ``[\n   {``.
        self.assertNotIn("[\n   {", out)
        # Single-space indent (2 -> 1) would render ``[\n {``.
        self.assertNotIn("[\n {", out)

    def test_json_preserves_column_order(self) -> None:
        # ``sort_keys=False`` in ``json.dumps`` keeps the per-row
        # dict iteration order intact, so columns appear in the
        # caller-specified order regardless of alphabet. Flipping
        # ``False`` to ``True`` (``ReplaceFalseWithTrue``) would
        # sort keys alphabetically and silently reorder every
        # admin / CSV-tooling expectation.
        out = render_rows(
            [{"z": 1, "a": 2, "m": 3}],
            columns=("z", "a", "m"),  # NOT alphabetical
            fmt="json",
        )
        # Sub-string positions: ``"z"`` appears before ``"a"``,
        # which appears before ``"m"``. With sort_keys=True the
        # ``"a"`` key would land first.
        z_pos = out.index('"z"')
        a_pos = out.index('"a"')
        m_pos = out.index('"m"')
        self.assertLess(z_pos, a_pos)
        self.assertLess(a_pos, m_pos)

    def test_enum_dispatch_distinguishes_csv_from_json(self) -> None:
        # ``fmt_enum is OutputFormat.CSV`` carries an ``Is_LtE``
        # mutant. ``OutputFormat`` inherits from ``str`` so member
        # comparison falls back to string lex order:
        #   ``"csv" <= "json"`` is True (``c`` < ``j``).
        # Original branch (``is``): for CSV input, ``fmt_enum is
        # OutputFormat.JSON`` is False, then ``fmt_enum is
        # OutputFormat.CSV`` is True → CSV branch.
        # Mutated branch (``<=``): for CSV input, ``fmt_enum <=
        # OutputFormat.JSON`` is True → JSON branch fires first,
        # returning the JSON document instead of CSV.
        out = render_rows(
            [{"a": "x"}],
            columns=("a",),
            fmt="csv",
        )
        # CSV-specific shape: header line + value line, no
        # bracket/brace tokens.
        self.assertNotIn("[", out)
        self.assertNotIn("{", out)
        self.assertIn("a\r\n", out)  # csv.writer line terminator


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

    def test_unknown_group_fails_before_app_is_created(self) -> None:
        """
        Symmetric with ``test_unknown_state_fails_before_app_is_created``:
        an unknown ``--group`` must raise ``CommandError`` before the
        app is persisted, not silently drop the group reference.
        """
        Application = get_application_model()
        before = Application.objects.count()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=will-not-exist-grp",
                f"--user-id={self.user1.pk}",
                "--group=NoSuchGroup",
                stdout=StringIO(),
            )
        self.assertIn("NoSuchGroup", str(ctx.exception))
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

    def test_missing_name_argument_is_rejected(self) -> None:
        # Pin ``required=True`` on ``--name``. ``ReplaceTrueWithFalse``
        # would make the argument optional and let argparse pass an
        # empty / missing name through to the model layer, where it
        # would silently create an app with an empty name field.
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                f"--user-id={self.user1.pk}",
                stdout=StringIO(),
            )
        self.assertIn("name", str(ctx.exception).lower())

    def test_missing_user_id_argument_is_rejected(self) -> None:
        # Symmetric: pin ``required=True`` on ``--user-id``.
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=No User",
                stdout=StringIO(),
            )
        self.assertIn("user-id", str(ctx.exception).lower())

    def test_mixed_valid_and_invalid_state_lists_only_invalid(self) -> None:
        # Pin ``missing = set(options[...]) - {s.name for s in states}``
        # against the ``Sub_BitOr`` mutant. The OR mutation would
        # collapse subtraction into set union, leaking VALID state
        # names into the error message alongside the invalid ones.
        # The XOR mutation happens to agree with subtraction on the
        # "all-missing" input the existing test uses, so the
        # discriminator requires a mix of valid + invalid.
        # Priority is unique; pick a high value unlikely to collide
        # with the fixture-bootstrapped states (Member=10, Blue=20,
        # Guest=0 etc.).
        State.objects.get_or_create(
            name="MixedGood",
            defaults={"priority": 9001},
        )
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=mix-state",
                f"--user-id={self.user1.pk}",
                "--state=MixedGood",
                "--state=MixedBad",
                stdout=StringIO(),
            )
        msg = str(ctx.exception)
        self.assertIn("MixedBad", msg)
        # The valid state name MUST NOT appear in the error —
        # ``Sub_BitOr`` mutation would surface it.
        self.assertNotIn("MixedGood", msg)

    def test_mixed_valid_and_invalid_group_lists_only_invalid(self) -> None:
        # Symmetric: same ``Sub_BitOr`` mutant on the group lookup.
        Group.objects.get_or_create(name="MixedGoodGroup")
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=mix-group",
                f"--user-id={self.user1.pk}",
                "--group=MixedGoodGroup",
                "--group=MixedBadGroup",
                stdout=StringIO(),
            )
        msg = str(ctx.exception)
        self.assertIn("MixedBadGroup", msg)
        self.assertNotIn("MixedGoodGroup", msg)

    def test_logentry_write_failure_does_not_undo_creation(self) -> None:
        # Pin ``except Exception`` on the LogEntry write.
        # ``ExceptionReplacer`` narrowing the catch (e.g. to
        # ``OSError``) would let a real DB failure during audit
        # propagate, breaking the creation flow that already
        # committed the app. The contract documented in-source:
        # "LogEntry is best-effort; failing to record audit must
        # not undo the creation."
        from unittest import mock

        Application = get_application_model()
        before = Application.objects.count()
        with mock.patch(
            "django.contrib.admin.models.LogEntry.objects.log_action",
            side_effect=RuntimeError("admin log table on fire"),
        ):
            out = StringIO()
            call_command(
                "oidc_create_app",
                "--name=Audit Failure Recovery",
                f"--user-id={self.user1.pk}",
                "--format=json",
                stdout=out,
            )
        # App was created and rendered despite the audit failure.
        result = json.loads(out.getvalue())
        self.assertEqual(1, len(result))
        self.assertEqual("Audit Failure Recovery", result[0]["name"])
        self.assertEqual(before + 1, Application.objects.count())


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

    def test_missing_username_argument_is_rejected(self) -> None:
        # Pin ``required=True`` on ``--username``. ``ReplaceTrueWithFalse``
        # would make the argument optional, and argparse would invoke
        # ``handle()`` with ``options["username"]=None``, crashing
        # downstream on ``User.objects.get(username=None)``.
        with self.assertRaises(CommandError):
            call_command(
                "oidc_revoke_user_tokens",
                stdout=StringIO(),
            )

    def test_revoke_reports_exact_token_counts(self) -> None:
        # Pin the ``revoked_access = 0`` initial value and the
        # ``revoked_access += 1`` increment.  ``NumberReplacer``
        # flipping the initial 0 → 1 would yield revoked_access=2
        # (initial + counter). Flipping ``+= 1`` → ``+= 0`` keeps the
        # counter at 0 even though tokens were revoked. The
        # existing ``test_revokes_access_and_refresh_tokens`` checks
        # the side effect (rows gone) but not the counter; this test
        # pins the rendered tally exactly.
        #
        # Three tokens total: one access (matched with refresh
        # access_token=at), one stand-alone access, and one refresh
        # piggy-backed on the first access. AccessToken.revoke()
        # cascades the linked refresh, but the iterator iteration
        # count is what the increment math tracks.
        self._seed_tokens()
        # Second standalone access token.
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="rev-test-at-2",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        out = StringIO()
        call_command(
            "oidc_revoke_user_tokens",
            f"--username={self.user1.username}",
            "--format=json",
            stdout=out,
        )
        row = json.loads(out.getvalue())[0]
        # Two access tokens iterated and revoked. The +=1 mutation
        # to +=0 would render 0 here; the initial 0→1 mutation
        # would render 3 (start at 1, increment twice).
        self.assertEqual(2, row["revoked_access"])
        self.assertEqual(1, row["revoked_refresh"])

    def test_revoke_dedups_logout_signal_when_multiple_apps_one_repeated(
        self,
    ) -> None:
        # Pin ``if key in seen: continue`` against
        # ``ReplaceContinueWithBreak``. The dedup loop walks the
        # ``(user_pk, app_pk)`` pairs; ``break`` on the first
        # duplicate stops emission entirely, missing every
        # subsequent app. The discriminator is a fixture with at
        # least two distinct apps PLUS a duplicate access token
        # for one of them: the loop must skip the duplicate and
        # continue, emitting one signal per app.
        from allianceauth_oidc.signals import oidc_logout_required

        from ._factories import make_app

        # Second app with its own active access token.
        second_creds = make_app(owner=self.user1)
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="dedup-at-1a",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,  # duplicate app on purpose
            token="dedup-at-1b",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        AccessToken.objects.create(
            user=self.user1,
            application=second_creds.app,
            token="dedup-at-2",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )

        captured: list[int] = []

        def sink(sender, user, application, reason, **kw):
            captured.append(application.pk)

        oidc_logout_required.connect(sink, dispatch_uid="test.dedup.sink")
        try:
            out = StringIO()
            call_command(
                "oidc_revoke_user_tokens",
                f"--username={self.user1.username}",
                "--format=json",
                stdout=out,
            )
        finally:
            oidc_logout_required.disconnect(dispatch_uid="test.dedup.sink")

        # Both app pks must appear exactly once. ``break`` on the
        # duplicate would emit only the first ``oauth_app`` entry
        # before stopping; ``continue`` (correct) skips the
        # duplicate and proceeds to ``second_creds.app``.
        self.assertEqual(
            sorted({self.oauth_app.pk, second_creds.app.pk}),
            sorted(captured),
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

    def test_unknown_client_id_fails_loudly(self) -> None:
        """
        Symmetric with ``test_unknown_username_fails_loudly`` —
        ``--client-id`` pointing at a non-existent app must raise
        ``CommandError``, not silently filter to an empty result set.
        """
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_audit_tokens",
                "--client-id=does-not-exist",
                stdout=StringIO(),
            )
        self.assertIn("does-not-exist", str(ctx.exception))

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
        self.assertTrue(rows[0]["pkce_required"])

        self.oauth_app.pkce_required = False
        self.oauth_app.save()
        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertFalse(rows[0]["pkce_required"])

    def test_audit_surfaces_format_column_jwt_vs_opaque(self) -> None:
        """
        ``docs/JWT_ACCESS_TOKENS.md`` migration recipe Step 5 instructs
        operators to grep the audit output for a ``format`` column to
        confirm the per-app rollout (one RP under JWT mode, others
        still on opaque). The column derives from the persisted token
        bytes via ``views.classify_token_format``: tokens whose
        compact form is a 3-segment ``at+jwt`` JWS render ``"jwt"``;
        anything else renders ``"opaque"`` (including hashed-at-rest
        tokens, which the heuristic cannot decode).

        Locks the migration recipe into a regression: if the column
        is dropped, renamed, or hardcoded, this test fails loudly.
        """
        # Seed a real JWT-shaped token. The classification heuristic
        # only looks at the header bytes, so a plausibly-formed JWT
        # (3 segments, header with ``typ="at+jwt"``) is sufficient
        # without going through the issuance path.
        import base64

        from oauth2_provider.models import get_access_token_model

        AccessToken = get_access_token_model()

        def _b64(payload: bytes) -> str:
            return (
                base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
            )

        jwt_like = ".".join(
            (
                _b64(b'{"typ":"at+jwt","alg":"RS256","kid":"x"}'),
                _b64(b'{"sub":"1","aud":"a","exp":1}'),
                _b64(b"signature-bytes"),
            )
        )

        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=jwt_like,
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="opaque-random-string-no-dots",  # nosec B106 - test fixture
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )

        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertEqual(2, len(rows))

        # Each row exposes a ``format`` key.
        for row in rows:
            self.assertIn("format", row, f"missing format column in {row!r}")

        formats = {row["format"] for row in rows}
        self.assertEqual(
            {"jwt", "opaque"},
            formats,
            f"expected one jwt + one opaque row, got {formats!r}",
        )

    # -----------------------------------------------------------------
    # ``--suspicious`` filter: surfaces tokens that do not match the
    # operator's current configuration. Each check pins a single class
    # of anomaly; the joined ``reasons`` column lets the operator
    # see at a glance why each row was flagged.
    # -----------------------------------------------------------------

    def _seed_token_with_expiry(
        self, *, expires_at: Any, app: Any = None, label: str = "sus"
    ) -> object:
        """Plant a token with explicit ``expires``; default app is the fixture."""
        AccessToken = get_access_token_model()
        return AccessToken.objects.create(
            user=self.user1,
            application=app or self.oauth_app,
            token=f"audit-{label}",  # nosec B106 - test fixture
            expires=expires_at,
            scope="openid",
        )

    def test_suspicious_returns_no_rows_when_token_is_normal(self) -> None:
        """
        Token planted within the deployment-default TTL on a live app
        passes both checks. ``--suspicious`` filters everything out.
        """
        from oauth2_provider.settings import oauth2_settings

        normal_ttl = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
        self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(seconds=normal_ttl - 5),
            label="normal",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual([], rows)

    def test_suspicious_flags_ttl_anomaly(self) -> None:
        """
        Token whose ``expires`` is farther in the future than a
        freshly-minted token would be (``now + ACCESS_TOKEN_EXPIRE_SECONDS
        + buffer``) is anomalous: the dispatcher would never produce
        such a row, so it was either issued under a longer-TTL config
        that has since been tightened or the row was hand-edited.
        Either way the operator should see it.
        """
        long_lived = self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(hours=1),
            label="long-ttl",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(long_lived.pk, rows[0]["id"])
        self.assertIn("ttl_anomaly", rows[0]["reasons"])

    def test_suspicious_flags_disabled_app(self) -> None:
        """
        ``application.active = False`` means the app is not allowed to
        issue new tokens, but old live tokens (``expires`` in the
        future) keep working until DOT's clear_expired or an explicit
        revoke. ``--suspicious`` surfaces these so the operator can
        decide whether to revoke proactively.
        """
        from oauth2_provider.settings import oauth2_settings

        normal_ttl = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
        self.oauth_app.active = False
        self.oauth_app.save(update_fields=["active"])
        token = self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(seconds=normal_ttl - 5),
            label="dis-app",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(token.pk, rows[0]["id"])
        self.assertIn("disabled_app", rows[0]["reasons"])

    def test_suspicious_joins_multiple_reasons(self) -> None:
        """
        A single token can match multiple checks. The ``reasons``
        column lists all of them — comma-joined — so the operator
        sees the full picture in one row instead of de-duplicating
        across multiple ``--suspicious`` queries.
        """
        self.oauth_app.active = False
        self.oauth_app.save(update_fields=["active"])
        self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(hours=1),
            label="both",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        reasons = rows[0]["reasons"]
        self.assertIn("ttl_anomaly", reasons)
        self.assertIn("disabled_app", reasons)

    def test_reasons_column_only_appears_under_suspicious(self) -> None:
        """
        Default ``oidc_audit_tokens`` output is the operator's daily
        view; adding a column unconditionally would break scripts that
        consume the JSON. ``reasons`` is therefore only emitted when
        ``--suspicious`` is set; the regular listing stays
        backwards-compatible.
        """
        self._seed_token()  # uses fixture default (1h TTL)
        out_default = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--format=json",
            stdout=out_default,
        )
        rows_default = json.loads(out_default.getvalue())
        self.assertNotIn("reasons", rows_default[0])

    def test_ttl_anomaly_skew_constant_is_five_seconds(self) -> None:
        # Pin ``_TTL_ANOMALY_SKEW = timedelta(seconds=5)``.
        # ``NumberReplacer`` flipping the literal changes the
        # boundary at which the ``ttl_anomaly`` check fires; the
        # constant is documented as "narrow enough not to mask a
        # token issued under a stale TTL config" and tests below
        # rely on its exact value as the boundary discriminator.
        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _TTL_ANOMALY_SKEW,
        )

        self.assertEqual(timedelta(seconds=5), _TTL_ANOMALY_SKEW)

    def test_suspicious_only_does_not_break_after_clean_token(self) -> None:
        # Pin ``if not reasons: continue`` against
        # ``ReplaceContinueWithBreak``. The dedup-style loop walks
        # tokens; ``break`` on the first normal token (empty
        # reasons list) stops listing and silently drops every
        # subsequent suspicious row.
        #
        # Fixture: ONE normal token + ONE disabled-app token. With
        # ``continue`` (correct), the suspicious-only output
        # contains the disabled-app row. With ``break``, the loop
        # halts at the normal row first and the suspicious row
        # never makes it into ``rows``.
        from ._factories import make_app

        # Normal token (active app, default TTL) — must be skipped.
        self._seed_token()
        # Disabled-app token (active=False) — must surface.
        creds = make_app(owner=self.user1)
        creds.app.active = False
        creds.app.save()
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=creds.app,
            token="audit-disabled",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        # Iteration order is ``order_by("-expires")`` so the two
        # tokens may arrive in either order depending on the test
        # clock. What pins ``continue`` against ``break`` is that
        # the disabled-app row IS present regardless of position.
        # In test settings, ``ACCESS_TOKEN_EXPIRE_SECONDS`` is short
        # (60s), so the 1-hour seed expiry above also flags
        # ``ttl_anomaly`` — the row may carry "disabled_app" alone
        # or combined with "ttl_anomaly".
        reasons_seen = " ".join(row.get("reasons", "") for row in rows)
        self.assertIn("disabled_app", reasons_seen)

    def test_classify_suspicious_returns_empty_for_missing_active_attr(
        self,
    ) -> None:
        # Pin ``getattr(app, "active", True)`` default. The default
        # ``True`` means "absent attribute looks like an active
        # app" — a defensive choice so orphaned tokens whose
        # application row was deleted (or test stubs with partial
        # surface) don't get flagged as ``disabled_app``.
        # ``ReplaceFalseWithTrue`` on the literal would let an
        # attribute-less mock fall through as if active=False and
        # spuriously flag every such token.
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _classify_suspicious,
        )

        # Token with a future expiry (no ttl_anomaly) and an app
        # that lacks the ``active`` attribute entirely. The result
        # must be ``[]`` — no spurious disabled_app reason.
        now = timezone.now()
        stub_app = SimpleNamespace()  # no ``active`` attribute
        stub_token = SimpleNamespace(
            expires=now + timedelta(seconds=60),
            application=stub_app,
        )
        self.assertEqual([], _classify_suspicious(stub_token, now=now))

    def test_classify_suspicious_active_true_is_not_disabled(self) -> None:
        # Pin ``getattr(app, "active", True) is False`` against the
        # ``Is_Eq`` mutant. For a real ``active=True`` token the
        # production code's ``True is False`` is False (not
        # flagged). The mutant ``True == False`` is also False —
        # they agree on this single shape. So this test alone does
        # NOT discriminate; pair with the companion below.
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _classify_suspicious,
        )

        now = timezone.now()
        stub_app = SimpleNamespace(active=True)
        stub_token = SimpleNamespace(
            expires=now + timedelta(seconds=60),
            application=stub_app,
        )
        self.assertEqual([], _classify_suspicious(stub_token, now=now))

    def test_classify_suspicious_active_false_yields_disabled_app(
        self,
    ) -> None:
        # Companion to the previous test — the actually-disabled
        # path. With ``Is_Eq`` flip, ``False == False`` is True
        # (same as ``False is False``) so this pair stays
        # equivalent; the test exists to lock in the documented
        # behaviour and prevent future regressions from silently
        # dropping the ``disabled_app`` reason entirely.
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _classify_suspicious,
        )

        now = timezone.now()
        stub_app = SimpleNamespace(active=False)
        stub_token = SimpleNamespace(
            expires=now + timedelta(seconds=60),
            application=stub_app,
        )
        self.assertEqual(
            ["disabled_app"], _classify_suspicious(stub_token, now=now)
        )

    def test_classify_suspicious_token_at_ttl_ceiling_is_not_anomaly(
        self,
    ) -> None:
        # Pin ``if expires > ceiling`` against ``>=``. Boundary:
        # ``expires`` exactly at ``ceiling`` (``now +
        # ACCESS_TOKEN_EXPIRE_SECONDS + skew``) must NOT flag
        # ``ttl_anomaly``. ``>=`` mutation would erroneously flag
        # every freshly-issued token sitting at the ceiling.
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _TTL_ANOMALY_SKEW,
            _classify_suspicious,
        )

        now = timezone.now()
        ttl_seconds = int(oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        ceiling = now + timedelta(seconds=ttl_seconds) + _TTL_ANOMALY_SKEW
        stub_app = SimpleNamespace(active=True)
        stub_token = SimpleNamespace(
            expires=ceiling,
            application=stub_app,
        )
        reasons = _classify_suspicious(stub_token, now=now)
        self.assertNotIn("ttl_anomaly", reasons)

    def test_classify_suspicious_token_one_second_above_ceiling_flagged(
        self,
    ) -> None:
        # Companion: one second past the ceiling fires the
        # ``ttl_anomaly`` reason. Together with the at-ceiling
        # test, the ``>``/``>=`` operator is pinned.
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _TTL_ANOMALY_SKEW,
            _classify_suspicious,
        )

        now = timezone.now()
        ttl_seconds = int(oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        ceiling = now + timedelta(seconds=ttl_seconds) + _TTL_ANOMALY_SKEW
        stub_app = SimpleNamespace(active=True)
        stub_token = SimpleNamespace(
            expires=ceiling + timedelta(seconds=1),
            application=stub_app,
        )
        self.assertIn(
            "ttl_anomaly",
            _classify_suspicious(stub_token, now=now),
        )


class TestOIDCJwksRotateCommand(OIDCTestCase):
    """
    ``manage.py oidc_jwks_rotate`` mints a fresh RSA private key and
    prints its RFC 7638 thumbprint so operators can plan the JWKS
    overlap window. Read-only by design — the command never touches
    Django settings or the database; the operator wires the new PEM
    into ``OAUTH2_PROVIDER`` themselves.

    JWT-mode operators reach this command on the canonical rotation
    paths: scheduled compliance rotation, leaked-key incident, or
    the initial flip from opaque-only to JWT.
    """

    PEM_BEGIN = "-----BEGIN PRIVATE KEY-----"
    PEM_END = "-----END PRIVATE KEY-----"

    def _extract_pem(self, blob: str) -> str:
        """Slice the PEM substring out of mixed stdout/file content."""
        start = blob.index(self.PEM_BEGIN)
        end = blob.index(self.PEM_END) + len(self.PEM_END)
        return blob[start:end]

    def test_default_emits_2048bit_pkcs8_pem(self) -> None:
        """
        Stdout carries a parseable RSA-2048 PEM. 2048 is the
        deployment-wide default to match
        ``django-oauth-toolkit``'s recommendation and keep generation
        cheap on container restart.
        """
        from cryptography.hazmat.primitives import serialization

        out = StringIO()
        call_command("oidc_jwks_rotate", stdout=out)
        text = out.getvalue()
        self.assertIn(self.PEM_BEGIN, text)
        self.assertIn(self.PEM_END, text)
        key = serialization.load_pem_private_key(
            self._extract_pem(text).encode(), password=None
        )
        # ``RSAPrivateKey`` is the only path through ``load_pem_private_key``
        # that exposes ``.key_size``; mypy/basedpyright narrow this via the
        # ``key_size`` access itself.
        self.assertEqual(2048, key.key_size)  # type: ignore[union-attr]

    def test_kid_line_matches_rfc7638_thumbprint(self) -> None:
        """
        The printed ``kid: <thumbprint>`` matches what
        ``oauth2_provider.utils.jwk_from_pem(...).thumbprint()``
        produces — the same call the JWT generator
        (``allianceauth_oidc/tokens.py:_build_jwt``) uses to populate
        the JWT header. Operators can therefore eyeball-correlate
        log lines, JWKS responses, and rotated keys without
        recomputing the thumbprint by hand.
        """
        from oauth2_provider.utils import jwk_from_pem

        out = StringIO()
        call_command("oidc_jwks_rotate", stdout=out)
        text = out.getvalue()
        pem = self._extract_pem(text)
        expected_kid = str(jwk_from_pem(pem).thumbprint())
        self.assertIn(f"kid: {expected_kid}", text)

    def test_out_path_writes_clean_pem_only(self) -> None:
        """
        ``--out PATH`` writes a bare PEM ready to drop into
        ``OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"]`` (or a
        ``Path.read_text()`` call from settings.py). Stdout in this
        mode still carries the kid + recipe so operators see the
        thumbprint, but it must NOT also contain the PEM (the file
        is the canonical artifact; printing it twice invites
        copy-paste of the wrong copy).
        """
        import os
        import tempfile
        from pathlib import Path

        from cryptography.hazmat.primitives import serialization

        # The command opens ``--out`` with ``O_EXCL`` to close the
        # create-then-chmod race; the path must NOT exist when the
        # call starts. ``mkstemp`` returns a unique path; close +
        # unlink immediately so the next ``os.open(..., O_EXCL)``
        # succeeds. ``Path.unlink(missing_ok=True)`` is the
        # ruff-PTH-friendly idiom for "remove if it still exists".
        fd, path_str = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        out_path = Path(path_str)
        out_path.unlink()
        self.addCleanup(lambda: out_path.unlink(missing_ok=True))
        path = path_str

        out = StringIO()
        call_command("oidc_jwks_rotate", "--out", path, stdout=out)

        stdout_text = out.getvalue()
        self.assertNotIn(self.PEM_BEGIN, stdout_text)
        # kid still surfaces in stdout so the operator sees what was
        # generated even when the PEM lands in a file.
        self.assertIn("kid:", stdout_text)

        from pathlib import Path as _Path

        file_text = _Path(path).read_text()
        self.assertTrue(file_text.startswith(self.PEM_BEGIN))
        # Trailing newline is fine; no recipe / kid in the file.
        self.assertNotIn("kid:", file_text)
        # Sanity: cryptography accepts the file's content.
        serialization.load_pem_private_key(file_text.encode(), password=None)

    def test_keysize_arg_honoured(self) -> None:
        """
        ``--key-size`` lets operators upgrade to compliance-grade
        sizes (FIPS 186-4 recommends >= 3072 for >= 128-bit
        security). 3072 chosen over 4096 to keep the test under
        one second on the lower-end CI runners.
        """
        from cryptography.hazmat.primitives import serialization

        out = StringIO()
        call_command("oidc_jwks_rotate", "--key-size", "3072", stdout=out)
        text = out.getvalue()
        key = serialization.load_pem_private_key(
            self._extract_pem(text).encode(), password=None
        )
        self.assertEqual(3072, key.key_size)  # type: ignore[union-attr]

    def test_rejects_below_minimum_keysize(self) -> None:
        """
        Sub-2048 RSA is broken by modern factoring research and
        explicitly disallowed by FIPS 186-4 / NIST SP 800-131A. The
        command refuses to generate one rather than letting an
        operator type ``--key-size 1024`` and silently produce a key
        no JWT consumer should accept. The regex pin ensures the
        rejection comes from our policy, not from a stray "Unknown
        command" or "Unknown argument" CommandError that would
        false-positive a missing implementation.
        """
        with self.assertRaisesRegex(
            CommandError, r"(?i)key.?size|2048|minimum"
        ):
            call_command(
                "oidc_jwks_rotate",
                "--key-size",
                "1024",
                stdout=StringIO(),
            )

    def test_min_key_size_constant_is_exactly_2048(self) -> None:
        # Pin ``_MIN_KEY_SIZE = 2048``. ``NumberReplacer`` flipping
        # the literal to neighbours (2047 / 2049) would silently
        # shift the FIPS 186-4 floor — a regression that
        # ``test_rejects_below_minimum_keysize`` does not catch
        # because 1024 < 2049 still fails. Only the exact literal
        # assertion pins it.
        from allianceauth_oidc.management.commands.oidc_jwks_rotate import (
            _MIN_KEY_SIZE,
        )

        self.assertEqual(2048, _MIN_KEY_SIZE)

    def test_outfile_written_with_mode_0o600(self) -> None:
        # Pin ``0o600`` (owner read+write only) on the ``os.open``
        # call. ``NumberReplacer`` flipping to 0o601 would silently
        # grant world-execute on a secret file. The existing
        # ``--out`` test verifies the bytes land in the file but
        # never inspects POSIX permissions.
        import os
        import stat
        import tempfile
        from pathlib import Path

        fd, path_str = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        out_path = Path(path_str)
        out_path.unlink()
        self.addCleanup(lambda: out_path.unlink(missing_ok=True))

        call_command("oidc_jwks_rotate", "--out", path_str, stdout=StringIO())
        mode = stat.S_IMODE(out_path.stat().st_mode)
        # Apply the standard umask the OS may impose; the command
        # opens with mode 0o600 which on a sensible umask (022 or
        # narrower) produces exactly 0o600. Any wider mode would
        # signal a regression on the literal.
        self.assertEqual(
            0o600,
            mode,
            f"file mode {oct(mode)} differs from expected 0o600; "
            "NumberReplacer on the literal?",
        )
