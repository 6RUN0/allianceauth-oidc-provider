"""Celery tasks for the OIDC provider (token cleanup)."""

import logging
import time

from celery import shared_task
from django.utils import timezone
from oauth2_provider.models import clear_expired, get_access_token_model

logger = logging.getLogger(f"extensions.{__name__}")


@shared_task(name="allianceauth_oidc.clear_expired_tokens")
def clear_expired_tokens() -> None:
    """
    Delete expired access/refresh/id tokens and grants via DOT.

    Wraps ``oauth2_provider.models.clear_expired()`` (which returns
    nothing) with before/after counts of expired access tokens and a
    duration measurement, so operators can verify the periodic Celery
    Beat schedule is actually running.
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
    logger.info(
        "OIDC cleanup: removed %d expired access tokens "
        "(before=%d, after=%d, %.1f ms)",
        max(expired_before - expired_after, 0),
        expired_before,
        expired_after,
        duration_ms,
    )
