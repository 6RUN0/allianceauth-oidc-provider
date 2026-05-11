"""
Tests for ``allianceauth_oidc.tasks``.

The cleanup task is a thin wrapper around DOT's ``clear_expired()``;
those tests seed a small mix of expired and live Grant/AccessToken
rows, run the task synchronously (``CELERY_TASK_ALWAYS_EAGER=True``
in test settings), and assert that only the expired rows are gone.

The retry-envelope tests pin the BCL dispatch task's Celery
retry-config knobs — the configuration itself is operational rather
than logical, but a regression that silently tightens the envelope
(e.g. dropping ``retry_jitter``) is a production correctness bug for
RP rolling deploys.
"""

from datetime import timedelta

from django.test import SimpleTestCase
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
)

from allianceauth_oidc.tasks import clear_expired_tokens, send_logout_token

from ._oidc_testcase import REDIRECT_URI, OIDCTestCase


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
            redirect_uri=REDIRECT_URI,
            scope="openid",
        )
        live = Grant.objects.create(
            user=self.user1,
            application=self.oauth_app,
            code="grant-live",
            expires=now + timedelta(hours=1),
            redirect_uri=REDIRECT_URI,
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

    def test_log_reports_exact_removed_access_count(self):
        # The existing log-shape test only checked that
        # ``removed_access=`` appears in the message — both
        # ``removed_access=0`` and ``removed_access=99`` satisfy that
        # assertion. Cosmic-ray's ``NumberReplacer`` on the ``max(..., 0)``
        # floor and binary-op flips on the ``before - after`` subtraction
        # therefore all survived. Pinning the exact value distinguishes
        # ``before - after`` from ``before + after`` / ``before * after``
        # / ``max(..., 1)`` etc.
        AccessToken = get_access_token_model()
        now = timezone.now()
        # Three expired access tokens — DOT removes them.
        for i in range(3):
            AccessToken.objects.create(
                user=self.user1,
                application=self.oauth_app,
                token=f"orphan-expired-{i}",  # nosec B106
                expires=now - timedelta(hours=1),
                scope="openid",
            )

        with self.assertLogs(
            "extensions.allianceauth_oidc.tasks", level="INFO"
        ) as cm:
            clear_expired_tokens()
        joined = "\n".join(cm.output)
        # Whitespace-bounded match so ``removed_access=3`` doesn't
        # also accept ``removed_access=33``.
        self.assertIn("removed_access=3 ", joined + " ")

    def test_clean_database_log_reports_zero_removed(self):
        # The ``max(expired_before - expired_after, 0)`` floor: when
        # nothing was expired, ``removed`` is exactly 0. ``NumberReplacer``
        # flipping the floor to 1 would log ``removed_access=1`` on
        # every clean-DB run, polluting dashboards with phantom work.
        AccessToken = get_access_token_model()
        # Reset any baseline rows from prior class setup.
        AccessToken.objects.filter(expires__lt=timezone.now()).delete()

        with self.assertLogs(
            "extensions.allianceauth_oidc.tasks", level="INFO"
        ) as cm:
            clear_expired_tokens()
        joined = "\n".join(cm.output)
        self.assertIn("removed_access=0 ", joined + " ")

    def test_duration_log_bounded_in_real_time(self):
        # ``duration_ms = (time.monotonic() - started) * 1000`` carries
        # ten BinaryOperator mutants (``-`` → ``+``/``*``/``/``...,
        # ``*`` → ``+``/``-``/...) plus ``NumberReplacer`` on the
        # ``1000`` constant. Most flips throw the duration outside any
        # plausible range — addition of two large monotonic timestamps,
        # subtraction yielding a huge negative number, ``*0`` collapsing
        # to zero. A loose upper-bound assertion catches them all.
        with self.assertLogs(
            "extensions.allianceauth_oidc.tasks", level="INFO"
        ) as cm:
            clear_expired_tokens()
        joined = "\n".join(cm.output)
        # Extract the duration value from the log line.
        import re

        match = re.search(r"duration=([\d.]+) ms", joined)
        self.assertIsNotNone(match, f"duration token missing in {joined!r}")
        duration_ms = float(match.group(1))
        # The whole task wall-clock is well under one minute even on
        # CI; tighter bound (e.g. 5_000 ms) would risk flakes.
        self.assertGreaterEqual(duration_ms, 0.0)
        self.assertLess(
            duration_ms,
            60_000.0,
            (
                f"duration_ms={duration_ms} outside plausible range — "
                "binary-op mutation on (now - started) * 1000?"
            ),
        )

    def test_function_is_registered_as_celery_task(self):
        # ``@shared_task(name=...)`` wraps the function so it gains
        # ``.delay`` / ``.apply``. ``RemoveDecorator`` strips the
        # wrapper; the resulting bare function survives every test
        # that calls it as a plain Python function (which is most of
        # this file). Probing the celery-task surface kills the
        # mutant cleanly.
        self.assertTrue(
            hasattr(clear_expired_tokens, "delay"),
            (
                "clear_expired_tokens has lost the @shared_task wrapper "
                "— Celery Beat will silently fail to schedule it."
            ),
        )
        self.assertTrue(hasattr(clear_expired_tokens, "apply"))


class TestSendLogoutTokenRetryEnvelope(SimpleTestCase):
    """
    BCL dispatch retry config must survive a typical RP rolling
    deploy (~60 seconds of 5xx responses while the new pod warms
    up). The geometric envelope and the ``retry_jitter`` knob are
    operational tunables that previously regressed in review.
    """

    def test_retry_jitter_is_enabled(self) -> None:
        """
        Without jitter, fan-out logouts from a single sign-out
        event would thunder against the RP in lockstep on every
        retry — exactly the worst case during a recovering RP.
        Celery's per-attempt jitter is the canonical fix.
        """
        self.assertTrue(
            send_logout_token.retry_jitter,
            "send_logout_token must enable Celery retry jitter",
        )

    def test_retry_envelope_covers_60s_rolling_deploy(self) -> None:
        """
        Compute the worst-case wall-clock envelope from the task's
        Celery config and assert it is at least 60 seconds — the
        canonical lower bound for an RP rolling deploy where the
        previous pod returned 5xx while the next pod is still
        booting.

        Envelope formula (Celery exponential backoff): for retry
        N (1-indexed) the wait is ``min(retry_backoff * 2^(N-1),
        retry_backoff_max)``. Summed across all ``max_retries``
        attempts gives the total wall-clock the task can absorb
        before it dead-letters.
        """
        b = send_logout_token.retry_backoff
        cap = send_logout_token.retry_backoff_max
        n = send_logout_token.max_retries
        envelope = sum(min(b * (2**i), cap) for i in range(n))
        self.assertGreaterEqual(
            envelope,
            60,
            (
                f"Retry envelope {envelope}s too tight for a 60s "
                f"RP rolling deploy (backoff={b}, cap={cap}, "
                f"max_retries={n})"
            ),
        )
