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
from .constants import TASK_CLEAR_EXPIRED_TOKENS, TASK_SEND_LOGOUT_TOKEN

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
    logger.info(
        "OIDC cleanup: removed_access=%d (before_access=%d, after_access=%d, duration=%.1f ms)",  # noqa: E501
        max(expired_before - expired_after, 0),
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
    max_retries=3,
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
