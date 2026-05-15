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

* **E004** — ``OAUTH2_PROVIDER['SCOPES']`` must contain the
  ``openid`` scope. DOT's default ``SCOPES`` map is
  ``{"read": ..., "write": ...}`` — no ``openid``, which silently
  disables id_token issuance. Discovery still resolves, access
  tokens still mint, but every OIDC RP (i.e. every RP that needs
  an id_token) fails at the token endpoint with
  ``invalid_scope`` or receives a token response without an
  ``id_token`` member.

Severity is intentionally ``Error`` for all three (per plan v5
m-V3-1): demoting any of them to ``Warning`` would let CI and
startup succeed and crash much later in production.

In addition, two ``Warning``-level checks surface misconfigurations
that are not fatal but routinely cause incident-class confusion:

* **W001** — ``ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True`` while
  ``DEBUG=False``. Masked-fragment logging is a development aid;
  enabling it in a production-shaped environment leaks identifiable
  prefixes/suffixes of access tokens, refresh tokens, and client
  secrets into the log stream. Warning (not Error) because some
  operators run in an isolated staging environment with
  ``DEBUG=False`` and intentionally accept this trade-off.

* **W002** — half-wired JWT mode: either
  ``ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT='jwt'`` without
  ``ACCESS_TOKEN_GENERATOR`` pointing at our dispatcher (JWT mode
  silently inactive), or the dispatcher wired without setting the
  default format to ``'jwt'`` (per-app override still works but the
  global default does not). Warning (not Error) because both halves
  individually still permit a working ``'opaque'`` fallback —
  operators should see this on ``manage.py check`` but not be
  blocked from deploying while they finish the second half of the
  opt-in.
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
E004_ID = "allianceauth_oidc.E004"
W001_ID = "allianceauth_oidc.W001"
W002_ID = "allianceauth_oidc.W002"

# Dotted-path the W002 check compares ``ACCESS_TOKEN_GENERATOR``
# against. Kept as a module-level constant so the same string is
# used by the check, the warning hint, and the runtime advisory in
# ``apps._check_jwt_wiring`` — drift between the three is the
# canonical "I followed the README but JWT mode still off" footgun
# this check exists to catch.
_DISPATCHING_GENERATOR_PATH: str = (
    "allianceauth_oidc.tokens.dispatching_access_token_generator"
)

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


@checks.register(checks.Tags.compatibility)
def check_openid_scope_configured(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.E004`` (Error) when
    ``OAUTH2_PROVIDER['SCOPES']`` does not advertise the ``openid``
    scope.

    Without ``openid`` in DOT's ``SCOPES`` map, the token endpoint
    will not put an ``id_token`` member in the response and OIDC
    RPs that consume id_tokens silently degrade. DOT's documented
    default is ``{"read": ..., "write": ...}`` — the exact
    silent-bypass scenario this check catches.

    Reading via ``oauth2_settings.SCOPES`` (not raw
    ``settings.OAUTH2_PROVIDER['SCOPES']``) is the canonical
    resolver and survives operators who configured the legacy
    flat ``OAUTH2_PROVIDER_SCOPES`` setting.

    Both ``dict`` and ``list`` shapes are accepted: ``'openid' in
    scopes`` matches a dict key or a list element identically.
    """
    try:
        from oauth2_provider.settings import oauth2_settings

        scopes = oauth2_settings.SCOPES
    except _BOOTSTRAP_EXCEPTIONS as exc:
        logger.warning(
            "allianceauth_oidc.E004 deferred: %s",
            exc,
            exc_info=True,
        )
        return []
    # ``oauth2_settings.SCOPES`` is typed as a wide union in DOT's
    # stubs (dict/list/str/int/bool/callable) because the same
    # settings resolver fronts many DOT knobs. Narrow to the
    # container shapes that ``in`` is meaningful on; anything else
    # is treated as misconfigured and falls through to E004.
    if isinstance(scopes, (dict, list, tuple, set)) and "openid" in scopes:
        return []
    return [_e004(scopes)]


def _e004(configured: Any) -> checks.Error:
    return checks.Error(
        (
            "OAUTH2_PROVIDER['SCOPES'] must contain the 'openid' "
            f"scope, got {configured!r}. Without 'openid', DOT will "
            "not mint an id_token member on token responses — every "
            "OIDC RP that depends on the id_token silently breaks."
        ),
        id=E004_ID,
        hint=(
            "Set OAUTH2_PROVIDER['SCOPES'] = {'openid': 'openid', "
            "'email': 'email', 'profile': 'profile', ...} in your "
            "Django settings (or extend the existing map)."
        ),
    )


@checks.register(checks.Tags.security)
def check_masked_secret_logging_in_production(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.W001`` (Warning) when masked-fragment
    secret logging is enabled in a production-shaped environment
    (``DEBUG=False``).

    Masked-fragment logging (``"he…il"`` style) is a development aid
    for diagnosing "wrong secret was sent" without revealing the
    full token. In production it leaks identifiable head/tail bytes
    of access tokens, refresh tokens, and client secrets into log
    streams that often outlive the secrets they reference. The
    posture is "off in prod"; this check makes the deviation
    visible on every ``manage.py check`` run.

    Severity is **Warning** (not Error) because the trade-off is
    legitimate in some operator contexts — isolated staging
    environments with restricted log access, short-retention audit
    pipelines, etc. The check exists to surface the choice, not to
    veto it.
    """
    if not getattr(settings, "ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS", False):
        return []
    # ``DEBUG=True`` is the documented development posture; masked
    # logging is safe there. ``DEBUG=False`` means the operator
    # built a production-shaped image, and that is when the
    # head/tail leak becomes a real exposure.
    if getattr(settings, "DEBUG", False):
        return []
    return [
        checks.Warning(
            (
                "ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True with "
                "DEBUG=False — masked-fragment logging leaks "
                "head/tail bytes of access tokens, refresh tokens, "
                "and client secrets into production log streams."
            ),
            id=W001_ID,
            hint=(
                "Set ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS = False "
                "(or remove the setting) in production. The default "
                "redacts secrets to '<redacted>'."
            ),
        )
    ]


@checks.register(checks.Tags.compatibility)
def check_jwt_mode_wiring(
    app_configs: Any,
    **kwargs: Any,
) -> list[checks.CheckMessage]:
    """
    Emit ``allianceauth_oidc.W002`` (Warning) when JWT access-token
    mode is half-wired.

    Two ``OAUTH2_PROVIDER`` keys jointly activate RFC 9068 JWT
    access tokens: ``ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT
    = 'jwt'`` AND ``ACCESS_TOKEN_GENERATOR =
    'allianceauth_oidc.tokens.dispatching_access_token_generator'``.
    Two real misconfigurations have surfaced in operator deploys:

    1. Default-format set to ``'jwt'`` but generator not pointing
       at the dispatcher. Effective behaviour: opaque tokens with
       no warning surface (per-app override still works, so the
       state is technically valid but silent).
    2. Generator pointing at the dispatcher but default-format
       still ``'opaque'``. Effective behaviour: per-app override
       works, but the global default does nothing.

    Both produce confusing "I followed the docs and JWT still isn't
    on" support tickets. Warning (not Error) because both halves
    individually permit a working opaque fallback — operators see
    the diagnostic on ``manage.py check`` but are not blocked.

    Wrapped in the bootstrap-exception catch because
    ``oauth2_settings.ACCESS_TOKEN_GENERATOR`` triggers DOT's
    ``perform_import``, which can raise ``ImportError`` if the
    dotted-path is bogus or the app registry is mid-boot.
    """
    try:
        from oauth2_provider.settings import oauth2_settings

        from .tokens import dispatching_access_token_generator
    except _BOOTSTRAP_EXCEPTIONS as exc:
        logger.warning(
            "allianceauth_oidc.W002 deferred: %s",
            exc,
            exc_info=True,
        )
        return []

    default_format = oauth2_settings.user_settings.get(
        "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT", "opaque"
    )
    try:
        actual_generator = oauth2_settings.ACCESS_TOKEN_GENERATOR
    except _BOOTSTRAP_EXCEPTIONS as exc:
        logger.warning(
            "allianceauth_oidc.W002 deferred: %s",
            exc,
            exc_info=True,
        )
        return []
    is_dispatcher = actual_generator is dispatching_access_token_generator

    if default_format == "jwt" and not is_dispatcher:
        return [
            checks.Warning(
                (
                    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="
                    "'jwt' but OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] "
                    "is not the AllianceAuth dispatcher. JWT mode "
                    "will NOT be active for the global default; "
                    "per-app overrides still work."
                ),
                id=W002_ID,
                hint=(
                    "Set OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] = "
                    f"{_DISPATCHING_GENERATOR_PATH!r}."
                ),
            )
        ]
    if default_format != "jwt" and is_dispatcher:
        return [
            checks.Warning(
                (
                    "OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] points "
                    "at the AllianceAuth dispatcher but "
                    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT is "
                    f"{default_format!r}. The global default issues "
                    "opaque tokens; only per-app overrides activate "
                    "JWT mode."
                ),
                id=W002_ID,
                hint=(
                    "Set ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT "
                    "= 'jwt' in OAUTH2_PROVIDER to activate JWT mode "
                    "globally, or unset ACCESS_TOKEN_GENERATOR if the "
                    "per-app override is intentional."
                ),
            )
        ]
    return []
