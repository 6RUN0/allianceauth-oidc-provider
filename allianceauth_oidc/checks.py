"""
Django system checks for the OIDC provider — fail-loud-fail-early.

Three structurally-required configurations are guarded here. Each
ID is part of the public API: operators grep for it in CI logs and
the README references the migration path.

* **E001** — back-channel logout requires ``OIDC_ISS_ENDPOINT``.
  The Celery worker has no HTTP request context to derive ``iss``
  from; an unset issuer would crash the first end-user logout, so
  a hard ``Error`` at ``manage.py check`` surfaces the mistake
  before the first logout is ever dispatched.

* **E002** — ``OAUTH2_PROVIDER_APPLICATION_MODEL`` must resolve to
  ``AllianceAuthApplication`` (or a subclass). Stock DOT model
  silently bypasses the three-layer policy enforcement documented
  in ``CLAUDE.md`` — every user can authenticate any app.

* **E003** — ``OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`` must
  resolve to ``AllianceAuthOAuth2Validator`` (or a subclass).
  Stock DOT validator drops layers 2 and 3 of the policy gate
  (``validate_code`` / ``validate_refresh_token`` /
  ``save_bearer_token``) — code-flow exchanges and refresh grants
  stop re-checking state/group membership.

Severity is intentionally ``Error`` for all three (per plan v5
m-V3-1): demoting any of them to ``Warning`` would let CI and
startup succeed and crash much later in production.
"""

from __future__ import annotations

import logging
from typing import Any

from django.apps import apps
from django.conf import settings
from django.core import checks
from django.db.utils import OperationalError, ProgrammingError
from django.utils.module_loading import import_string

logger = logging.getLogger(f"extensions.{__name__}")

# Public IDs — operators grep for these strings in CI logs and the
# README documents the migration path. Keep stable across releases.
E001_ID = "allianceauth_oidc.E001"
E002_ID = "allianceauth_oidc.E002"
E003_ID = "allianceauth_oidc.E003"

# Bootstrap-tolerant exception set. Narrower than a bare ``Exception``
# (which would mask coding bugs and post-migration schema mismatches),
# but wide enough to cover the legitimate "DB not ready yet" / "app
# registry not populated yet" scenarios where ``manage.py migrate``
# itself invokes ``check``. ``LookupError`` covers
# ``apps.get_model`` raising on a missing app/model;
# ``ImportError`` covers a misspelled validator dotted-path during
# bootstrap; ``ValueError`` covers a malformed
# ``"app.Model"`` literal. Any other exception surfaces.
_BOOTSTRAP_EXCEPTIONS: tuple[type[BaseException], ...] = (
    OperationalError,
    ProgrammingError,
    LookupError,
    ImportError,
    ValueError,
)


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
    except _BOOTSTRAP_EXCEPTIONS as exc:
        # Pre-migrate, app-registry-not-ready, or any other bootstrap
        # state. The check will re-run on the next ``manage.py check``
        # once the DB is in shape; no point blocking migrations on it.
        # Logged at warning so operators can still observe a repeated
        # boot-time miss in CI.
        logger.warning(
            "allianceauth_oidc.E001 deferred: %s",
            exc,
            exc_info=True,
        )
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


@checks.register(checks.Tags.compatibility)
def check_application_model(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.E002`` (Error) when
    ``OAUTH2_PROVIDER_APPLICATION_MODEL`` does not resolve to
    ``AllianceAuthApplication`` (or a subclass).

    The setting is a Django swappable-model reference
    (``"app_label.ModelName"``). When it points elsewhere — most
    commonly the stock ``oauth2_provider.Application`` — DOT
    instantiates the base model whose validators are unaware of
    the access-state / access-group whitelist, ``active`` flag,
    and ``debug_mode``. The end result is a silent policy bypass:
    every user authenticates every app.

    A custom subclass of ``AllianceAuthApplication`` is accepted
    because it inherits the policy fields and validator hooks —
    forbidding subclassing would block the legitimate "extend the
    model with extra columns" pattern.
    """
    expected_path = "allianceauth_oidc.AllianceAuthApplication"
    configured = getattr(settings, "OAUTH2_PROVIDER_APPLICATION_MODEL", None)
    if not configured:
        # No setting — DOT defaults to its own Application. That is
        # the silent-bypass scenario this check exists to catch.
        return [_e002(expected_path, configured)]
    try:
        from allianceauth_oidc.models import AllianceAuthApplication

        # ``apps.get_model`` accepts both "app.Model" and a model
        # class; it raises ``LookupError`` if the app/model is
        # unregistered, which lands in the bootstrap branch.
        Configured = apps.get_model(configured)
        if issubclass(Configured, AllianceAuthApplication):
            return []
    except _BOOTSTRAP_EXCEPTIONS as exc:
        logger.warning(
            "allianceauth_oidc.E002 deferred: %s",
            exc,
            exc_info=True,
        )
        return []
    return [_e002(expected_path, configured)]


def _e002(expected: str, configured: Any) -> checks.Error:
    return checks.Error(
        (
            "OAUTH2_PROVIDER_APPLICATION_MODEL must resolve to "
            f"{expected!r} (or a subclass), got {configured!r}. "
            "Stock DOT Application silently bypasses the "
            "AllianceAuth access-state / access-group policy."
        ),
        id=E002_ID,
        hint=(
            f"Set OAUTH2_PROVIDER_APPLICATION_MODEL = {expected!r}"
            " in your Django settings."
        ),
    )


@checks.register(checks.Tags.compatibility)
def check_validator_class(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.E003`` (Error) when
    ``OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`` does not resolve
    to ``AllianceAuthOAuth2Validator`` (or a subclass).

    Stock DOT validator (`oauth2_provider.oauth2_validators
    .OAuth2Validator`) implements neither ``validate_code`` nor
    ``validate_refresh_token`` re-checks nor the
    ``PermissionDenied → InvalidGrantError`` translation in
    ``save_bearer_token``. With a misconfigured validator class,
    layers 2 and 3 of the policy gate documented in ``CLAUDE.md``
    silently vanish — a user can keep using a previously-issued
    refresh token after losing the required state/group.

    Subclassing the AllianceAuth validator for further
    customization is supported.
    """
    expected_path = (
        "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"
    )
    oauth2_provider_cfg = getattr(settings, "OAUTH2_PROVIDER", None)
    configured: Any = None
    if isinstance(oauth2_provider_cfg, dict):
        configured = oauth2_provider_cfg.get("OAUTH2_VALIDATOR_CLASS")
    if not configured:
        return [_e003(expected_path, configured)]
    try:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        Configured = (
            import_string(configured)
            if isinstance(configured, str)
            else configured
        )
        if isinstance(Configured, type) and issubclass(
            Configured, AllianceAuthOAuth2Validator
        ):
            return []
    except _BOOTSTRAP_EXCEPTIONS as exc:
        logger.warning(
            "allianceauth_oidc.E003 deferred: %s",
            exc,
            exc_info=True,
        )
        return []
    return [_e003(expected_path, configured)]


def _e003(expected: str, configured: Any) -> checks.Error:
    return checks.Error(
        (
            "OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] must resolve "
            f"to {expected!r} (or a subclass), got {configured!r}. "
            "Stock DOT validator silently disables the AllianceAuth "
            "code-exchange and refresh-grant policy re-checks."
        ),
        id=E003_ID,
        hint=(
            "Set OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] = "
            f"{expected!r} in your Django settings."
        ),
    )
