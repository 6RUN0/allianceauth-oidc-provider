"""
Django system checks for the OIDC provider — fail-loud-fail-early.

Plan v5 §5.3 system-check enforcement (AC-19e/f/g): a deployment that
configures ``backchannel_logout_uri`` on any application MUST also
pin ``OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']``. The Celery worker has
no HTTP request context to derive ``iss`` from, so an unset issuer
would crash the first end-user logout; a hard ``Error`` at
``manage.py check`` surfaces the mistake before the first logout
ever has to be dispatched.
"""

from __future__ import annotations

import logging
from typing import Any

from django.apps import apps
from django.core import checks

logger = logging.getLogger(f"extensions.{__name__}")

# Public ID — operators grep for this string in CI logs and the
# README documents the migration path. Keep stable across releases.
E001_ID = "allianceauth_oidc.E001"


@checks.register(checks.Tags.compatibility)
def check_oidc_iss_endpoint_when_bcl_enabled(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.E001`` (Error) when any application has
    ``backchannel_logout_uri`` set and ``OIDC_ISS_ENDPOINT`` is not.

    Severity is intentionally **Error** (not Warning) per plan v5
    m-V3-1: a demotion to Warning would let CI/start-up succeed and
    crash the first end-user logout. Fail-loud is the right posture
    for a structurally-required setting.

    Wrapped in a broad ``try/except`` so the check tolerates the
    bootstrap case where migrations have not yet run — ``manage.py
    migrate`` itself invokes ``check``, and a database-not-ready
    error during that path would block migration itself.
    """
    try:
        from oauth2_provider.settings import oauth2_settings

        Application = apps.get_model(
            "allianceauth_oidc", "AllianceAuthApplication"
        )
        bcl_count = Application.objects.exclude(
            backchannel_logout_uri=""
        ).count()
    except Exception:
        # Pre-migrate, app-registry-not-ready, or any other bootstrap
        # state. The check will re-run on the next ``manage.py check``
        # once the DB is in shape; no point blocking migrations on it.
        return []
    if bcl_count == 0:
        return []
    iss = getattr(oauth2_settings, "OIDC_ISS_ENDPOINT", "") or ""
    if iss:
        return []
    return [
        checks.Error(
            "Back-channel logout is configured on one or more applications, but `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` is not set. The Celery worker has no HTTP request context to derive the issuer from. Set `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` to your AS's issuer URL before enabling back-channel logout on any application.",  # noqa: E501
            id=E001_ID,
            hint="Add OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT'] = 'https://your-auth.example.org/o' to your settings.",  # noqa: E501
        )
    ]
