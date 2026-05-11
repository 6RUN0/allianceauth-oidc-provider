"""Celery tasks for the OIDC provider (token cleanup + BCL fan-out)."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from celery import shared_task
from django.utils import timezone
from oauth2_provider.models import (
    clear_expired,
    get_access_token_model,
    get_application_model,
)

from . import __version__
from ._metrics import bcl_delivery_seconds, tokens_cleaned
from .constants import TASK_CLEAR_EXPIRED_TOKENS, TASK_SEND_LOGOUT_TOKEN


def _bcl_outcome_for_status(status: int) -> str:
    """
    Map an RP HTTP status to the histogram ``outcome`` label.

    Values mirror the ``reason`` vocabulary on
    :data:`oidc_logout_dispatched` so dashboards joining the
    histogram with the dead-letter counter use a single label
    namespace.
    """
    if 200 <= status < 300:
        return "success"
    if 300 <= status < 400:
        return "redirect_blocked"
    if 400 <= status < 500:
        return "rp_client_error"
    return "rp_server_error"


logger = logging.getLogger(f"extensions.{__name__}")


@shared_task(name=TASK_CLEAR_EXPIRED_TOKENS)
def clear_expired_tokens() -> None:
    """
    Delete expired access/refresh/id tokens and grants via DOT.

    Wraps ``oauth2_provider.models.clear_expired()`` (which returns nothing)
    with before/after counts of expired access tokens and a duration
    measurement, so operators can verify the periodic Celery Beat schedule is
    actually running.
    """
    access_token_model = get_access_token_model()
    # Reuse a single `now` snapshot for both before/after counts so the
    # delta is an honest measure of what `clear_expired()` removed,
    # not "what expired during the cleanup window plus what it
    # removed". The task is idempotent and runs on a cron schedule —
    # any newly-expired rows show up on the next run.
    now = timezone.now()
    expired_before = access_token_model.objects.filter(expires__lt=now).count()
    started = time.monotonic()
    clear_expired()
    duration_ms = (time.monotonic() - started) * 1000
    expired_after = access_token_model.objects.filter(expires__lt=now).count()
    # The before/after delta is access-token-only by design — DOT's
    # `clear_expired()` also drops grants and refresh tokens, but
    # counting those is best-effort and would mislead operators if the
    # numbers diverged across DOT versions. Field naming makes the
    # scope explicit so dashboards do not over-promise.
    removed = max(expired_before - expired_after, 0)
    tokens_cleaned.inc(removed)
    logger.info(
        "OIDC cleanup: removed_access=%d (before_access=%d, after_access=%d, duration=%.1f ms)",  # noqa: E501
        removed,
        expired_before,
        expired_after,
        duration_ms,
    )


# Per plan v5 §5.4 AC-26a — connect timeout 5 s, read timeout 10 s.
# Bounded explicitly so a slow RP can't hold the worker indefinitely.
_HTTP_TIMEOUT: tuple[int, int] = (5, 10)


@shared_task(
    bind=True,
    name=TASK_SEND_LOGOUT_TOKEN,
    autoretry_for=(requests.RequestException,),
    retry_backoff=5,
    retry_backoff_max=125,
    # Envelope sum for max_retries=5 with backoff=5 cap=125 is
    # 5+10+20+40+80 = 155 seconds — comfortably above the 60-second
    # RP rolling-deploy lower bound enforced by
    # ``TestSendLogoutTokenRetryEnvelope`` in ``tests/test_tasks.py``.
    # Raising further trades faster operator feedback for tolerance
    # of longer RP outages; 5 is the smallest value that still
    # tolerates a typical k8s/ECS rollout.
    max_retries=5,
    # Without jitter, every queued logout from a single sign-out
    # event retries in lockstep, so a recovering RP that needs ~10s
    # to warm up gets hit by N synchronous bursts. Jitter spreads
    # them across the backoff window.
    retry_jitter=True,
)
def send_logout_token(
    self: Any,
    user_pk: int,
    application_pk: int,
    jti: str,
    signing_kid: str,
    iat: int,
) -> None:
    """
    Per OIDC BCL 1.0 §2.4 — POST a signed ``logout_token`` to the
    RP's ``backchannel_logout_uri``.

    Args are scalars only (int / str) so the broker carries no token
    material; the worker rebuilds the JWT against the captured
    ``signing_kid`` and the pinned ``(jti, iat)``, so retries are
    byte-identical (spec §2.4 recommendation, RPs MAY use ``iat`` /
    ``jti`` for idempotency within a 2-minute window — see plan §5.4
    AC-30 for the retry-window math).

    Outbound HTTP discipline (plan §5.4 AC-26a):

    * ``allow_redirects=False`` — never follow 3xx, instead log and
      audit ``reason="redirect_blocked"``. The fan-out semantic is
      "POST to the URI the operator registered, period"; an RP
      redirect would be ambiguous and security-fragile.
    * Response body NEVER read; only ``status_code`` matters.
    * ``response.close()`` called explicitly so the underlying socket
      returns to the pool even when the body would have been small.
    """
    from django.contrib.auth import get_user_model

    from .logout import SigningKeyRetiredError, build_logout_token
    from .signals import BackChannelLogoutSender, oidc_logout_dispatched
    from .utils import build_logout_debug_meta

    User = get_user_model()
    Application = get_application_model()
    try:
        user = User.objects.get(pk=user_pk)
        application = Application.objects.get(pk=application_pk)
    except (User.DoesNotExist, Application.DoesNotExist):
        logger.warning(
            "OIDC BCL: user or application disappeared between enqueue and dispatch (user_pk=%s, app_pk=%s)",  # noqa: E501
            user_pk,
            application_pk,
        )
        return
    attempt_count = (self.request.retries or 0) + 1
    try:
        token, _ = build_logout_token(
            user, application, jti=jti, iat=iat, signing_kid=signing_kid
        )
    except SigningKeyRetiredError:
        logger.warning(
            "OIDC BCL: signing kid retired; aborting logout dispatch meta=%s",
            build_logout_debug_meta(
                application=application,
                jti=jti,
                reason="signing_kid_retired",
            ),
        )
        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=False,
            attempt_count=attempt_count,
            reason="signing_kid_retired",
        )
        return
    # Histogram-friendly span: ``time.monotonic`` is immune to
    # wall-clock drift so the observation reflects true HTTP latency
    # even under NTP adjustment. Measured only across the
    # request/response round-trip — JWT building above is fast and
    # exception-free in practice, and including it would conflate
    # network performance with crypto throughput. ``requests.post``
    # raising a ``RequestException`` triggers Celery autoretry
    # before this body resumes, so network errors do not contribute
    # to the histogram by design (they show up via the dead-letter
    # counter on ``retries_exhausted`` instead).
    _bcl_started = time.monotonic()
    response = requests.post(
        application.backchannel_logout_uri,
        data={"logout_token": token},
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": f"allianceauth-oidc/{__version__}",
        },
        timeout=_HTTP_TIMEOUT,
        allow_redirects=False,
    )
    try:
        status = response.status_code
    finally:
        response.close()
    bcl_delivery_seconds.labels(
        client_id=application.client_id,
        outcome=_bcl_outcome_for_status(status),
    ).observe(time.monotonic() - _bcl_started)
    if 300 <= status < 400:
        logger.warning(
            "OIDC BCL: RP returned redirect, blocked per spec meta=%s",
            build_logout_debug_meta(
                application=application,
                jti=jti,
                status_code=status,
                reason="redirect_blocked",
            ),
        )
        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=False,
            attempt_count=attempt_count,
            reason="redirect_blocked",
        )
        return
    if 200 <= status < 300:
        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=True,
            attempt_count=attempt_count,
        )
        return
    if 400 <= status < 500:
        logger.warning(
            "OIDC BCL: RP returned %d (4xx, no retry) meta=%s",
            status,
            build_logout_debug_meta(
                application=application,
                jti=jti,
                status_code=status,
                reason="rp_client_error",
            ),
        )
        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=False,
            attempt_count=attempt_count,
            reason="rp_client_error",
        )
        return
    # 5xx — Celery autoretry kicks in via ``autoretry_for``. The
    # final retry (when ``self.request.retries == self.max_retries``)
    # is the spec-mandated last attempt; if it also fails, the task
    # records ``reason="retries_exhausted"`` instead of re-raising.
    logger.warning(
        "OIDC BCL: RP returned %d (5xx, will retry) meta=%s",
        status,
        build_logout_debug_meta(
            application=application,
            jti=jti,
            status_code=status,
            reason="rp_server_error",
        ),
    )
    if self.request.retries >= self.max_retries:
        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=False,
            attempt_count=attempt_count,
            reason="retries_exhausted",
        )
        return
    raise requests.HTTPError(f"RP returned {status}; Celery will retry")
