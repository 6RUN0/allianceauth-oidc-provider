"""
OIDC Back-Channel Logout 1.0 — ``logout_token`` JWT builder.

References:
* OpenID Connect Back-Channel Logout 1.0 §2.4 (logout token structure)
* §2.6 (RP idempotency obligation on ``jti``)

This module is the spec-side primitive: build a signed ``logout+jwt``
for a given ``(user, application)`` pair. The dispatcher and Celery
fan-out live in ``logout`` callers (US-BCL-005), not here.

Sub-only logout per plan v5 path-b: no ``sid`` claim is ever emitted.
Spec §2.6 explicitly permits this and obliges RPs to terminate all
sessions for the ``sub`` when ``sid`` is absent.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from oauth2_provider.settings import oauth2_settings
from oauth2_provider.utils import jwk_from_pem

# Spec literal — do NOT "fix" to https://. OIDC BCL 1.0 §2.4
# defines this URI as ``http://schemas.openid.net/event/...``
# regardless of the transport. RPs MUST treat it as an opaque
# identifier; mutating it breaks every off-the-shelf RP library.
_LOGOUT_EVENT_URI = "http://schemas.openid.net/event/backchannel-logout"


class SigningKeyRetiredError(Exception):
    """
    Raised when ``build_logout_token`` is asked to sign with a kid
    that is no longer present in either the active key
    (``OIDC_RSA_PRIVATE_KEY``) or the inactive-key store
    (``OIDC_RSA_PRIVATE_KEYS_INACTIVE``).

    The dispatcher catches this and fires
    ``oidc_logout_dispatched(success=False,
    reason="signing_kid_retired")`` without retrying — there is no
    network or transient state to retry against.
    """


def _resolve_signing_key(signing_kid: str | None) -> Any:
    """
    Return the ``jwcrypto.jwk.JWK`` whose RFC 7638 thumbprint matches
    ``signing_kid`` (when given), preferring the active key.

    When ``signing_kid`` is None, returns the active key — same path
    a fresh logout dispatch takes.
    """
    active_pem: Any = oauth2_settings.OIDC_RSA_PRIVATE_KEY
    active_key = jwk_from_pem(active_pem)
    if signing_kid is None:
        return active_key
    if str(active_key.thumbprint()) == signing_kid:
        return active_key
    # ``OIDC_RSA_PRIVATE_KEYS_INACTIVE`` is a list of PEM strings at
    # runtime; DOT's IMPORT_STRINGS-wide type leaves it as ``Any``.
    inactive: Any = oauth2_settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE
    for inactive_pem in inactive or []:
        candidate = jwk_from_pem(inactive_pem)
        if str(candidate.thumbprint()) == signing_kid:
            return candidate
    raise SigningKeyRetiredError(
        f"signing_kid {signing_kid!r} not found in OIDC_RSA_PRIVATE_KEY or OIDC_RSA_PRIVATE_KEYS_INACTIVE"  # noqa: E501
    )


def build_logout_token(
    user: Any,
    application: Any,
    *,
    jti: str | None = None,
    iat: int | None = None,
    signing_kid: str | None = None,
) -> tuple[str, str]:
    """
    Build a signed ``logout+jwt`` for the given ``(user, application)``.

    Returns ``(jwt, jti)`` so callers can persist the ``jti`` for
    audit correlation without re-parsing the serialized token.

    Parameters:
    * ``jti`` / ``iat`` — when provided, used as-is so a Celery
      retry produces a byte-identical token. ``None`` means "pin
      fresh values now"; that path is the enqueue-time call from
      the dispatcher.
    * ``signing_kid`` — when set, the worker rebuilds the JWT with
      the kid the dispatcher captured at enqueue time; if the key
      has rotated out, ``SigningKeyRetiredError`` is raised. When
      ``None``, the active key is used.

    Spec discipline (do NOT relax without re-reading §2.4):

    * Header ``typ="logout+jwt"`` (literal, lowercase, with +).
    * Payload carries ``events`` with the spec event URI
      (``http://...``, NOT https — see ``_LOGOUT_EVENT_URI``).
    * Payload NEVER contains ``nonce`` (spec MUST NOT).
    * Payload NEVER contains ``sid`` in v1 (sub-only logout).
    * Payload NEVER contains PII (``email`` / ``name`` / ``picture`` /
      ``groups`` / ``locale`` / ``scope`` / character data).
    """
    from jwcrypto import jwt as jw  # type: ignore[import-untyped]

    key = _resolve_signing_key(signing_kid)
    jti_value = jti or uuid.uuid4().hex
    iat_value = iat if iat is not None else int(time.time())
    # The worker runs without an HTTP request context, so
    # ``oidc_issuer(None)`` falls through DOT to
    # ``OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']``. The Django system
    # check (US-BCL-003 / AC-19e) makes that setting structurally
    # required when any RP enables BCL, so this call is safe.
    issuer = oauth2_settings.oidc_issuer(None)
    header = {
        "typ": "logout+jwt",
        "alg": "RS256",
        "kid": str(key.thumbprint()),
    }
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": application.client_id,
        "iat": iat_value,
        "jti": jti_value,
        "sub": str(user.pk),
        "events": {_LOGOUT_EVENT_URI: {}},
    }
    token = jw.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return str(token.serialize()), jti_value


def _active_signing_kid() -> str:
    """
    Return the thumbprint of the currently-active signing key.

    Pinned at enqueue time and passed to the worker as a scalar so a
    retry that survives a key rotation can still rebuild the original
    JWT against ``OIDC_RSA_PRIVATE_KEYS_INACTIVE`` instead of silently
    swapping in the new key.
    """
    active_pem: Any = oauth2_settings.OIDC_RSA_PRIVATE_KEY
    return str(jwk_from_pem(active_pem).thumbprint())


def apps_with_active_tokens(user: Any) -> list[Any]:
    """
    Return the distinct list of applications the user currently has
    a refresh-token OR access-token row for.

    Used by every BCL trigger site (revoke command, ``is_active``
    flip, group/state change, account delete) to decide which RPs
    need a logout_token POST. Walking BOTH tables (not just RT) is
    deliberate — short-lived clients without refresh tokens still
    deserve a logout signal while their AT is unexpired.
    """
    from django.utils import timezone
    from oauth2_provider.models import (
        get_access_token_model,
        get_refresh_token_model,
    )

    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    now = timezone.now()
    app_ids: set[int] = set()
    # ``AccessToken`` rows are deleted on ``.revoke()`` (no ``revoked``
    # column), so an unexpired row is the right proxy for "active".
    app_ids.update(
        AccessToken.objects.filter(user=user, expires__gt=now).values_list(
            "application_id", flat=True
        )
    )
    # ``RefreshToken`` keeps a ``revoked`` timestamp after revocation
    # rather than deleting the row, so an explicit
    # ``revoked__isnull=True`` filter is required.
    app_ids.update(
        RefreshToken.objects.filter(
            user=user, revoked__isnull=True
        ).values_list("application_id", flat=True)
    )
    if not app_ids:
        return []
    from oauth2_provider.models import get_application_model

    Application = get_application_model()
    # ``active=False`` is the operator's kill-switch for a compromised
    # or retired client (see ``AllianceAuthApplication.active``
    # help_text). Filtering the fan-out here means a deactivated RP
    # stops receiving signed ``logout_token`` POSTs on subsequent
    # user-lifecycle events — without this filter, the kill-switch
    # contradicts itself (the deactivated client keeps getting
    # ``sub``/``iss``/``aud``/``jti`` deliveries). The
    # ``dispatch_backchannel_logout`` callsite ALSO short-circuits on
    # ``application.is_usable(None)`` as belt-and-suspenders against
    # custom receivers that bypass this helper.
    return list(Application.objects.filter(pk__in=app_ids, active=True))


def dispatch_backchannel_logout(
    sender: Any,
    user: Any,
    application: Any,
    reason: str | None = None,
    **kwargs: Any,
) -> None:
    """
    Default ``oidc_logout_required`` receiver — enqueue one Celery
    task per (user, application) pair.

    Per OIDC BCL 1.0 §2.6, the AS MAY emit multiple logout_tokens
    for the same (user, app); RPs MUST dedup on ``jti``. The
    dispatcher MAY fire twice if two trigger reasons fire in one
    transaction (e.g. ``revoke`` + cascading ``deactivate``) — by
    design. Each fire produces a distinct ``jti``; the RP-side dedup
    is the spec contract.

    Skips silently when ``application.backchannel_logout_uri`` is
    blank — that is the operator's "disabled for this RP" switch.

    Failure paths emit ``oidc_logout_dispatched(success=False)``
    with a stable ``reason`` string instead of raising, so a flaky
    broker / retired signing key never breaks the originating
    trigger transaction.
    """
    import logging

    from django.db import transaction

    from .signals import emit_bcl_failure
    from .utils import app_log, build_logout_debug_meta

    logger = logging.getLogger(f"extensions.{__name__}")

    if not getattr(application, "backchannel_logout_uri", ""):
        return
    # Defence-in-depth against the kill-switch contract being silently
    # bypassed by a custom receiver wired upstream of
    # ``apps_with_active_tokens`` (which already filters
    # ``active=True``). ``is_usable(None)`` returns ``self.active`` on
    # ``AllianceAuthApplication``; the upstream DOT contract calls it
    # the "client usability" check, so a deactivated app correctly
    # short-circuits here without surfacing in the BCL fan-out audit.
    is_usable = getattr(application, "is_usable", None)
    if callable(is_usable) and not is_usable(None):
        return
    # Custom receivers that need to bypass this gate MUST emit
    # ``reason="user_revoked"``; any other reason (including
    # unknown ones from operator-wired triggers) is treated as
    # non-revoke and silently skipped when the flag is True.
    if (
        getattr(application, "backchannel_logout_on_revoke_only", False)
        and reason != "user_revoked"
    ):
        # The literal substring ``"skipped by on_revoke_only flag"``
        # is operator-stable: grep for it to disambiguate this skip
        # from other dispatch failure modes. ``app_log`` routes to
        # INFO when ``debug_mode`` is on, DEBUG otherwise.
        app_log(
            logger,
            application,
            "OIDC BCL: skipped by on_revoke_only flag reason=%s",
            reason,
        )
        return
    try:
        signing_kid = _active_signing_kid()
    except Exception:
        logger.warning(
            "OIDC BCL: cannot resolve active signing key; skipping logout dispatch meta=%s",  # noqa: E501
            build_logout_debug_meta(
                application=application, reason="signing_kid_resolve_failed"
            ),
        )
        emit_bcl_failure(
            application=application,
            user_pk=getattr(user, "pk", None),
            jti="",
            attempt_count=0,
            reason="signing_kid_resolve_failed",
        )
        return
    jti_value = uuid.uuid4().hex
    iat_value = int(time.time())

    def _enqueue() -> None:
        # Late import — ``tasks`` imports back from ``logout`` for
        # ``SigningKeyRetiredError`` / ``build_logout_token``, so a
        # module-level import here would deadlock the import graph.
        # ``Any``-bind keeps pyright from collapsing the import-cycle
        # symbol into ``list[str]``.
        from . import tasks as _tasks

        task: Any = _tasks.send_logout_token
        try:
            task.apply_async(
                args=(
                    user.pk,
                    application.pk,
                    jti_value,
                    signing_kid,
                    iat_value,
                ),
            )
        except Exception:
            logger.warning(
                "OIDC BCL: broker unavailable, dropping logout meta=%s",
                build_logout_debug_meta(
                    application=application,
                    jti=jti_value,
                    reason="broker_unavailable",
                ),
            )
            emit_bcl_failure(
                application=application,
                user_pk=getattr(user, "pk", None),
                jti=jti_value,
                attempt_count=0,
                reason="broker_unavailable",
            )

    transaction.on_commit(_enqueue)
