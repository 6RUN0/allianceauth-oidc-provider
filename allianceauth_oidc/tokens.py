"""
RFC 9068 JWT access-token generation and format dispatching.

The dispatcher (:func:`dispatching_access_token_generator`) is what
operators wire into ``OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR']``.
Per-app and global ``access_token_format`` settings drive the
per-request decision between JWT and opaque (DOT-default) generation.

Wiring is via dotted-path string because ``ACCESS_TOKEN_GENERATOR`` IS
in DOT's ``IMPORT_STRINGS`` tuple (``oauth2_provider/settings.py``):
the resolver calls :func:`oauth2_provider.settings.perform_import` and
turns the string into a callable at startup. This contrasts with
``PKCE_REQUIRED``, which is NOT in ``IMPORT_STRINGS`` and therefore
needs the function reference (see :mod:`allianceauth_oidc.pkce`).
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Final, Literal

from django.conf import settings
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.utils import jwk_from_pem

# DOT does not ship a default access-token generator (the
# ``ACCESS_TOKEN_GENERATOR`` setting defaults to ``None``); when None,
# DOT delegates to oauthlib's ``random_token_generator`` (see
# ``oauth2_provider/settings.py:server_kwargs`` and
# ``oauthlib/oauth2/rfc6749/tokens.py:216``). Using the same callable
# keeps "opaque mode" byte-identical to upstream behavior.
from oauthlib.oauth2.rfc6749.tokens import (
    random_token_generator as _opaque_generator,
)

from .security import DEFAULT_POLICY

logger = logging.getLogger(f"extensions.{__name__}")

# Conservative default. Apache LimitRequestFieldSize defaults to 8190;
# nginx ``large_client_header_buffers`` to 8 KB; HAProxy ``tune.bufsize``
# to 16 KB. 4096 leaves headroom for cookies and other Authorization
# overhead, and is operator-overridable via
# ``OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES']``.
_DEFAULT_SIZE_WARN_BYTES: Final[int] = 4096


def dispatching_access_token_generator(request: Any) -> str:
    """
    Pluggable access-token generator wired into DOT.

    Resolves ``access_token_format`` for the request's ``client_id``
    and either builds an RFC 9068 JWT (:func:`_build_jwt`) or falls
    back to DOT's opaque random-string generator. Unknown / empty
    ``client_id`` and DB-miss both fail-safe to opaque (mirrors the
    PKCE adapter contract; see :mod:`allianceauth_oidc.pkce`).

    ``request.expires_in`` is set by oauthlib on the inbound request
    BEFORE the generator runs. See
    ``oauthlib/oauth2/rfc6749/tokens.py:305-310``: line 307 assigns
    ``request.expires_in`` from the bearer-token configuration, line
    310 invokes ``token_generator(request)``. We rely on that
    ordering when computing ``exp`` in :func:`_required_claims`.
    """
    client_id = (
        getattr(getattr(request, "client", None), "client_id", "") or ""
    )
    fmt = _resolve_access_token_format(client_id)
    if fmt == "jwt":
        token = _build_jwt(request)
        threshold = _size_warn_threshold()
        if len(token) > threshold:
            logger.warning(
                "OIDC JWT access token size %d bytes exceeds %d (client_id=%a); review group membership and upstream proxy Authorization header limits",  # noqa: E501
                len(token),
                threshold,
                client_id,
            )
        return token
    # ``random_token_generator`` is from ``oauthlib`` (no type stubs);
    # wrap the call in ``str(...)`` so the static checker sees a
    # concrete return type instead of ``Any``.
    return str(_opaque_generator(request))


def _resolve_access_token_format(
    client_id: str,
) -> Literal["opaque", "jwt"]:
    """
    Adapter: resolve ``client_id`` to an app row + delegate to policy.

    Mirrors :func:`allianceauth_oidc.pkce.per_app_pkce_required` —
    fail-safe-strict logging on unknown / empty ``client_id``, ORM
    column-bounded via ``.only(...)``. Unknown clients fall back to
    ``"opaque"`` (the safe-by-default of the two formats).

    The unknown-client log uses ``%a`` (ASCII repr) rather than
    ``%r`` because ``client_id`` arrives unsanitised from an HTTP
    parameter; ``%r`` would let stray newline / ANSI escapes flow
    into log storage.
    """
    from .models import AllianceAuthApplication

    if not client_id:
        logger.warning("OIDC AT format: empty client_id -> fail-safe opaque")
        return "opaque"
    try:
        app = AllianceAuthApplication.objects.only("access_token_format").get(
            client_id=client_id
        )
    except AllianceAuthApplication.DoesNotExist:
        logger.warning(
            "OIDC AT format: unknown client_id=%a -> fail-safe opaque",
            client_id,
        )
        return "opaque"
    return DEFAULT_POLICY.access_token_format(app)


def _size_warn_threshold() -> int:
    """Read the configurable size-guard threshold from settings."""
    provider = getattr(settings, "OAUTH2_PROVIDER", {}) or {}
    raw = provider.get(
        "ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES",
        _DEFAULT_SIZE_WARN_BYTES,
    )
    try:
        return int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_SIZE_WARN_BYTES


def _build_jwt(request: Any) -> str:
    """
    Build an RFC 9068 JWT access token.

    Header: ``typ="at+jwt"`` (RFC 9068 §2.1), ``alg="RS256"``,
    ``kid`` from RFC 7638 thumbprint of the signing key (DOT idiom
    at ``oauth2_provider/views/oidc.py``).

    Payload: required claims via :func:`_required_claims` plus
    scope-gated identity claims via :func:`_identity_claims`. The
    union order is RFC-framing first, identity overlay last — so
    when ``sub`` (or any other claim) appears in both maps the
    identity value wins. This matches the spec's "AT and id_token
    claim sets byte-equivalent for the same scope" guarantee
    (id_token comes from ``get_oidc_claims`` directly, so AT must
    too — see ``.omc/specs/deep-interview-jwt-access-tokens.md``
    §"Non-Goals" line 85). Identity never emits the RFC 9068
    framing keys (``typ`` / ``exp`` / ``iat`` / ``jti`` / ``scope`` /
    ``client_id``) so the union cannot break required-claim
    presence.

    Local imports for ``jwcrypto`` and ``django.utils.dateformat``
    keep the module's module-level import surface minimal — these
    only matter when JWT mode is active.
    """
    from jwcrypto import jwt  # type: ignore[import-untyped]

    # ``OIDC_RSA_PRIVATE_KEY`` is typed as a wide IMPORT_STRINGS union
    # by DOT, but at runtime it is always the PEM ``str`` we passed
    # in via settings. Cast keeps ``jwk_from_pem``'s narrow
    # ``Hashable`` parameter happy without a runtime check.
    private_key_pem: Any = oauth2_settings.OIDC_RSA_PRIVATE_KEY
    key = jwk_from_pem(private_key_pem)
    header = {
        "typ": "at+jwt",
        "alg": "RS256",
        # ``jwcrypto`` is untyped; ``thumbprint()`` is documented to
        # return ``str`` (RFC 7638 base64url-encoded fingerprint).
        "kid": str(key.thumbprint()),
    }
    claims = _required_claims(request)
    claims.update(_identity_claims(request))
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return str(token.serialize())


def _required_claims(request: Any) -> dict[str, Any]:
    """
    Build the RFC 9068 §2.2 required claim set.

    Emits ``iss / sub / aud / client_id / exp / iat / jti / scope``.
    For ``client_credentials`` (``request.user is None`` or
    ``user.is_authenticated`` is False) ``sub`` falls back to
    ``client_id`` per RFC 9068 §3 + OAuth 2.0 §4.4 convention.
    ``auth_time`` is emitted only when there is an authenticated
    user with a non-``None`` ``last_login`` (mirrors DOT's id_token
    pattern at ``oauth2_validators.py``); silently omitted in the
    machine-to-machine and never-logged-in branches.
    """
    now = int(time.time())
    issuer = oauth2_settings.oidc_issuer(request)
    user = getattr(request, "user", None)
    client_id = (
        getattr(getattr(request, "client", None), "client_id", "") or ""
    )
    is_authenticated = user is not None and getattr(
        user, "is_authenticated", False
    )
    sub = str(getattr(user, "pk", "") or "") if is_authenticated else client_id
    expires_in_raw: Any = (
        getattr(request, "expires_in", None)
        or oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
    )
    expires_in = int(expires_in_raw)
    scopes = getattr(request, "scopes", None) or []
    scope_str = (
        " ".join(scopes) if isinstance(scopes, (list, tuple)) else str(scopes)
    )
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "client_id": client_id,
        "exp": now + expires_in,
        "iat": now,
        "jti": uuid.uuid4().hex,
        "scope": scope_str,
    }
    last_login = (
        getattr(user, "last_login", None) if is_authenticated else None
    )
    if last_login is not None:
        from django.utils import dateformat

        claims["auth_time"] = int(dateformat.format(last_login, "U"))
    return claims


def _identity_claims(request: Any) -> dict[str, Any]:
    """
    Reuse DOT's canonical scope-gated claim mapper.

    DOT's ``get_oidc_claims`` (``oauth2_validators.py``) iterates
    ``self.oidc_claim_scope.items()`` and emits only claims whose
    required scope is in ``request.scopes`` (a list — no
    substring-match bugs). Our
    :class:`allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator`
    extends that map with EVE / state claims, so reuse is automatic
    and complete; spec line 85's "no claim divergence between AT
    and id_token" is enforced by construction, not by a handwritten
    filter.
    """
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return {}
    # ``OAUTH2_VALIDATOR_CLASS`` is typed as a wide IMPORT_STRINGS union
    # by DOT; at runtime ``perform_import`` always resolves it to the
    # validator class. Cast through ``Any`` so the static checker
    # accepts the call without forcing every call site to assert the
    # narrowed shape.
    validator_cls: Any = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    validator = validator_cls()
    claims: dict[str, Any] = validator.get_oidc_claims(
        token=None, token_handler=None, request=request
    )
    return claims
