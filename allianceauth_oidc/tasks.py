"""Celery tasks for the OIDC provider (token cleanup)."""

from celery import shared_task
from oauth2_provider.models import clear_expired


@shared_task(name="allianceauth_oidc.clear_expired_tokens")
def clear_expired_tokens():
    """Delete expired access/refresh/id tokens and grants via DOT."""
    clear_expired()
