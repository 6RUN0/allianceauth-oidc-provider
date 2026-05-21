"""
Tests for ``manage.py oidc_*`` operator commands.

The commands are thin wrappers around the ORM; tests verify the
contract operators rely on:

* Where applicable, ``--dry-run`` on destructive commands does not
  write.
* ``--format=json`` produces parseable output.
* Destructive commands are idempotent (re-running on a cleaned-up
  subject is a no-op); read-only commands return stable output.
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_refresh_token_model,
)

from ._oidc_testcase import OIDCTestCase


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

    def test_reason_flag_propagates_to_logout_signal(self) -> None:
        """
        ``--reason=...`` forwards the operator-supplied free-form audit
        string to every emitted ``oidc_logout_required`` signal. The
        default (``"user_revoked"``) is also exercised by other tests
        in this module; this one pins the override path so a SIEM
        downstream can correlate "command-initiated revoke for incident
        INC-1234" with a known reason label.
        """
        from allianceauth_oidc.signals import oidc_logout_required

        self._seed_tokens()
        captured: list[str] = []

        def sink(sender, user, application, reason, **kw):
            captured.append(reason)

        oidc_logout_required.connect(sink, dispatch_uid="test.reason.sink")
        try:
            call_command(
                "oidc_revoke_user_tokens",
                f"--username={self.user1.username}",
                "--reason=incident-INC-1234",
                "--format=json",
                stdout=StringIO(),
            )
        finally:
            oidc_logout_required.disconnect(dispatch_uid="test.reason.sink")

        # One app in the fixture → one signal with the override reason.
        # The dedup test below verifies multi-app behaviour separately.
        self.assertEqual(["incident-INC-1234"], captured)

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
