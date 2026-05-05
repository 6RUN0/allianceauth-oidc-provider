"""Celery tasks for the OIDC provider (token cleanup)."""

import logging
import time

from celery import shared_task
from django.utils import timezone
from oauth2_provider.models import clear_expired, get_access_token_model

from .constants import TASK_CLEAR_EXPIRED_TOKENS

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
    now = timezone.now()
    expired_before = access_token_model.objects.filter(expires__lt=now).count()
    started = time.monotonic()
    clear_expired()
    duration_ms = (time.monotonic() - started) * 1000
    expired_after = access_token_model.objects.filter(
        expires__lt=timezone.now()
    ).count()
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
