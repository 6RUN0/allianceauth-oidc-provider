"""
Tests for ``allianceauth_oidc.tasks.clear_expired_tokens``.

The task is a thin wrapper around DOT's ``clear_expired()``; the test seeds a
small mix of expired and live Grant/AccessToken rows, runs the task
synchronously (``CELERY_TASK_ALWAYS_EAGER=True`` in test settings), and asserts
that only the expired rows are gone.

The goal is regression — this is not a stress test of DOT's batching.
"""

from datetime import timedelta

from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
)

from allianceauth_oidc.tasks import clear_expired_tokens

from ._oidc_testcase import OIDCTestCase


class TestClearExpiredTokensTask(OIDCTestCase):
    def test_expired_grants_are_deleted_live_grants_are_kept(self):
        """
        Run the task with one expired and one live Grant.

        After the task completes, only the live Grant must remain.
        """
        Grant = get_grant_model()
        now = timezone.now()

        expired = Grant.objects.create(
            user=self.user1,
            application=self.oauth_app,
            code="grant-expired",
            expires=now - timedelta(hours=1),
            redirect_uri="http://localhost/redir/",
            scope="openid",
        )
        live = Grant.objects.create(
            user=self.user1,
            application=self.oauth_app,
            code="grant-live",
            expires=now + timedelta(hours=1),
            redirect_uri="http://localhost/redir/",
            scope="openid",
        )

        # Eager Celery (configured in tests/test_settingsAA4.py) executes
        # synchronously; .delay() and direct call have the same effect
        # here, so call the task function for clearer stack traces.
        clear_expired_tokens()

        self.assertFalse(
            Grant.objects.filter(pk=expired.pk).exists(),
            "expired Grant should have been deleted",
        )
        self.assertTrue(
            Grant.objects.filter(pk=live.pk).exists(),
            "live Grant must NOT be deleted",
        )

    def test_orphan_expired_access_tokens_are_deleted(self):
        """
        AccessToken without a refresh_token and past its `expires` time is
        the canonical orphan that DOT's clear_expired removes.

        Live access tokens (future `expires`) must stay.
        """
        AccessToken = get_access_token_model()
        now = timezone.now()

        expired = AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="orphan-expired-at",  # nosec B106
            expires=now - timedelta(hours=1),
            scope="openid",
        )
        live = AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="orphan-live-at",  # nosec B106
            expires=now + timedelta(hours=1),
            scope="openid",
        )

        clear_expired_tokens()

        self.assertFalse(
            AccessToken.objects.filter(pk=expired.pk).exists(),
            "expired orphan AccessToken should have been deleted",
        )
        self.assertTrue(
            AccessToken.objects.filter(pk=live.pk).exists(),
            "live AccessToken must NOT be deleted",
        )

    def test_task_logs_cleanup_count_for_operator_visibility(self):
        """
        The task emits an INFO log line with the number of removed tokens
        and the duration.

        Operators rely on this to verify the Celery Beat schedule is actually
        firing.
        """
        AccessToken = get_access_token_model()
        now = timezone.now()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="orphan-expired-for-log",  # nosec B106
            expires=now - timedelta(hours=1),
            scope="openid",
        )

        with self.assertLogs(
            "extensions.allianceauth_oidc.tasks", level="INFO"
        ) as cm:
            clear_expired_tokens()

        joined = "\n".join(cm.output)
        self.assertIn("OIDC cleanup", joined)
        # Field names are explicit about scope (access-token only) so
        # dashboards built off this log line cannot accidentally claim
        # to count grants/refresh-tokens too.
        self.assertIn("removed_access=", joined)
        self.assertIn("before_access=", joined)
        self.assertIn("after_access=", joined)
        self.assertIn("duration=", joined)
        self.assertIn("ms", joined)

    def test_task_is_idempotent_on_clean_database(self):
        """
        Running the task on a database with no expired rows must be a no-op
        — used to be the regression case where overzealous cleanup would remove
        live tokens.
        """
        AccessToken = get_access_token_model()
        Grant = get_grant_model()
        before_at = AccessToken.objects.count()
        before_grant = Grant.objects.count()

        # Two consecutive runs to exercise idempotency.
        clear_expired_tokens()
        clear_expired_tokens()

        self.assertEqual(before_at, AccessToken.objects.count())
        self.assertEqual(before_grant, Grant.objects.count())
