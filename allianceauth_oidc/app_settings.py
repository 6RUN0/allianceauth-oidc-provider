"""
Resolved Django settings for the OIDC provider with safe defaults.

Accessors are functions, not module-level constants — Django's
``@override_settings`` rebinds ``django.conf.settings`` per test, but
import-time ``getattr(settings, ...)`` snapshots the value before the
override runs and never sees changes. Reading via a function call keeps
the runtime tunable from tests and from operator hot-reloads.

For dependency-injection-friendly use, ``OIDCSettings.from_django()``
wraps every OIDC-provider scalar setting in a frozen dataclass; pass
it in where you would otherwise call ``app_settings.foo()`` so tests
can hand-craft a config without ``@override_settings``.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Final, Literal

from django.conf import settings

# ``setting_changed`` is imported lazily inside ``connect_invalidator``
# below: it lives under ``django.test.signals``, and pulling a
# test-package symbol at the top level of a production module would
# couple the runtime to Django's test infrastructure. The signal
# itself is a documented public hook (Django uses it to power
# ``@override_settings``), but its import path is internal and may
# shift across Django majors.

# Setting keys: pin each name in one place so the docstring, the
# ``getattr`` lookup, and any test using ``override_settings`` cannot
# silently diverge from a typo. Co-located with the accessors rather
# than in ``constants.py`` because they are an implementation detail
# of this module.
_KEY_LOG_MASKED_SECRETS: Final[str] = "ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS"
_KEY_LOG_MASK_HEAD: Final[str] = "ALLIANCEAUTH_OIDC_LOG_MASK_HEAD"
_KEY_LOG_MASK_TAIL: Final[str] = "ALLIANCEAUTH_OIDC_LOG_MASK_TAIL"
_KEY_PORTRAIT_URL_TEMPLATE: Final[str] = (
    "ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE"
)
_KEY_PORTRAIT_SIZE: Final[str] = "ALLIANCEAUTH_OIDC_PORTRAIT_SIZE"
_KEY_EVE_CLAIM_PREFIX: Final[str] = "ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX"
_KEY_EVE_CLAIM_SCOPE: Final[str] = "ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE"
# Source of truth for the OIDC ``email_verified`` claim: when
# Alliance Auth is configured to require email confirmation at
# registration (``REGISTRATION_VERIFY_EMAIL=True``, the AA default),
# every user that reaches us has already proven control of their
# email address; we forward that as ``email_verified=True``. When
# the operator disabled the confirmation step
# (``REGISTRATION_VERIFY_EMAIL=False``) we fall back to ``False`` —
# claiming verification AA never performed would mislead RPs about
# the trust level of the address.
_KEY_REGISTRATION_VERIFY_EMAIL: Final[str] = "REGISTRATION_VERIFY_EMAIL"
# Operator escape hatch for the OIDC ``email_verified`` claim. Tri-state:
# ``True`` / ``False`` force the claim regardless of placeholder
# detection or AA's ``REGISTRATION_VERIFY_EMAIL``; ``None`` (default)
# defers to the auto decision tree (placeholder → False; otherwise the
# AA setting). Use with care — forcing ``True`` while AA does not
# actually verify enables address-spoofing attacks downstream (the
# account-takeover scenario described in the security model).
_KEY_FORCE_EMAIL_VERIFIED: Final[str] = (
    "ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED"
)
# Nested under ``OAUTH2_PROVIDER`` (not at the Django settings root) —
# both keys arrive through DOT's settings dict because the operator-
# facing wire-up flows alongside ``ACCESS_TOKEN_GENERATOR`` and
# ``PKCE_REQUIRED``. ``_cached_snapshot`` pulls them via
# ``getattr(settings, "OAUTH2_PROVIDER", {}).get(...)`` and the
# ``setting_changed`` invalidator also fires on the parent
# ``OAUTH2_PROVIDER`` key so ``override_settings`` round-trips
# correctly.
_KEY_DEFAULT_ACCESS_TOKEN_FORMAT: Final[str] = (
    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"
)
_KEY_JWT_SIZE_WARN_BYTES: Final[str] = "ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES"
_KEY_OAUTH2_PROVIDER: Final[str] = "OAUTH2_PROVIDER"


# Defaults — Django setting absent → these values land in the snapshot.
# Kept here next to the keys so the override-or-default pair is one
# scroll away.
_DEFAULT_LOG_MASKED_SECRETS: Final[bool] = False
_DEFAULT_LOG_MASK_HEAD: Final[int] = 2
_DEFAULT_LOG_MASK_TAIL: Final[int] = 2
_DEFAULT_PORTRAIT_URL_TEMPLATE: Final[str] = (
    "https://images.evetech.net/characters/{character_id}/portrait?size={size}"
)
_DEFAULT_PORTRAIT_SIZE: Final[int] = 128
# EVE-domain claim prefix (e.g. ``eve_character_id`` vs ``character_id``
# vs ``corp_character_id``). Default ``eve_`` keeps the AA-specific
# claims out of the standard OIDC namespace so RP code can distinguish
# them at a glance and is unlikely to collide with other OIDC providers
# the same RP federates against.
_DEFAULT_EVE_CLAIM_PREFIX: Final[str] = "eve_"
# Scope under which EVE claims are emitted. Read on every snapshot
# build, so ``@override_settings`` flips at runtime; production
# operator changes pick it up at the next ``setting_changed`` cache
# invalidation.
_DEFAULT_EVE_CLAIM_SCOPE: Final[str] = "profile"
# Mirrors AA's own ``REGISTRATION_VERIFY_EMAIL`` default — see
# allianceauth/authentication/views.py:RegistrationView. AA itself
# treats absent setting as "verification required".
_DEFAULT_REGISTRATION_VERIFY_EMAIL: Final[bool] = True
# ``None`` keeps the auto decision tree authoritative; operators opt
# into forcing by setting True or False explicitly.
_DEFAULT_FORCE_EMAIL_VERIFIED: Final[bool | None] = None
# Opaque-by-default keeps the AS feature-flagged off: operators
# explicitly opt into JWT access tokens via the OAUTH2_PROVIDER dict.
_DEFAULT_ACCESS_TOKEN_FORMAT: Final[Literal["opaque", "jwt"]] = "opaque"
# Conservative size threshold for the JWT-access-token size warning.
# Apache LimitRequestFieldSize defaults to 8190; nginx
# large_client_header_buffers to 8 KB; HAProxy tune.bufsize to 16 KB.
# 4096 leaves headroom for cookies + other Authorization overhead;
# operators override via OAUTH2_PROVIDER dict.
_DEFAULT_JWT_SIZE_WARN_BYTES: Final[int] = 4096


# EVE Online's image server only serves portraits at fixed sizes;
# constructing a URL with a different ``size=`` query parameter
# returns a 400. The set is part of the validator contract for
# ``OIDCSettings`` so a misconfigured ``ALLIANCEAUTH_OIDC_PORTRAIT_SIZE``
# fails fast at start-up instead of silently breaking the ``picture``
# claim at runtime.
EVE_PORTRAIT_VALID_SIZES: Final[frozenset[int]] = frozenset(
    {32, 64, 128, 256, 512, 1024}
)


@dataclass(frozen=True, slots=True)
class OIDCSettings:
    """
    Snapshot of every OIDC-provider Django setting in one typed object.

    Constructed via ``OIDCSettings.from_django()`` — that classmethod
    reads ``django.conf.settings`` lazily at call time, so the snapshot
    survives ``@override_settings`` correctly. Tests can also build an
    instance directly: ``OIDCSettings(log_masked_secrets=True, ...)``.

    Frozen + slots: cheap to pass around (no __dict__), and accidental
    mutation in a request path becomes an ``FrozenInstanceError`` at
    edit time rather than a silent bug.
    """

    log_masked_secrets: bool
    log_mask_head: int
    log_mask_tail: int
    portrait_url_template: str
    portrait_size: int
    eve_claim_prefix: str
    eve_claim_scope: str
    # Default value emitted in the OIDC ``email_verified`` claim. Read
    # from AA's ``REGISTRATION_VERIFY_EMAIL`` rather than a separate
    # OIDC-side setting so a single source of truth governs the trust
    # level: if AA actually validated the address, we report it; if
    # AA did not, we cannot honestly claim verification. Per-user
    # state (e.g. a future "this specific user is unverified" flag)
    # would override at the ``ClaimsBuilder`` layer.
    email_verified_default: bool
    # Operator override for the ``email_verified`` claim. ``None``
    # means "auto" (the decision tree in ``ClaimsBuilder.build``);
    # ``True`` / ``False`` force the claim regardless of placeholder
    # detection or REGISTRATION_VERIFY_EMAIL. Reserved for deployments
    # where the AA workflow is not the source of truth — e.g. users
    # imported from an external IdP that already verified addresses,
    # or sites that knowingly accept the trade-off.
    force_email_verified: bool | None
    # Global default access-token wire format (``"opaque"`` or
    # ``"jwt"``), pulled from ``OAUTH2_PROVIDER`` because the
    # opt-in lives alongside ``ACCESS_TOKEN_GENERATOR`` in the
    # operator's DOT settings dict. ``AccessPolicy.access_token_format``
    # reads this when the per-app override is absent. Wire format is
    # ``Literal[...]``-typed so a typo at the settings layer is
    # coerced to ``"opaque"`` by ``_normalise_at_format`` before
    # construction — the dataclass field type stays as the post-
    # normalisation contract.
    default_access_token_format: Literal["opaque", "jwt"]
    # Operator-facing size guard threshold for issued JWT access
    # tokens. ``dispatching_access_token_generator`` logs WARNING
    # when ``len(jwt) > jwt_size_warn_bytes``. Stored as the
    # already-normalised positive integer so the field reflects what
    # the code actually uses, not the raw operator value.
    jwt_size_warn_bytes: int

    def __post_init__(self) -> None:
        """
        Validate the snapshot and fail fast on bad operator config.

        ``mask_secret`` would clamp negative head/tail to zero anyway,
        but raising at construction time pushes the misconfiguration
        back to whoever set the Django setting instead of letting it
        surface in a request-path logger. Likewise for portrait_size
        — emitting a 400-response URL into the ``picture`` claim is
        worse than failing at boot.
        """
        if self.log_mask_head < 0:
            msg = (
                "ALLIANCEAUTH_OIDC_LOG_MASK_HEAD must be >=0, "
                f"got {self.log_mask_head}"
            )
            raise ValueError(msg)
        if self.log_mask_tail < 0:
            msg = (
                "ALLIANCEAUTH_OIDC_LOG_MASK_TAIL must be >=0, "
                f"got {self.log_mask_tail}"
            )
            raise ValueError(msg)
        if self.portrait_size not in EVE_PORTRAIT_VALID_SIZES:
            valid = sorted(EVE_PORTRAIT_VALID_SIZES)
            msg = (
                f"ALLIANCEAUTH_OIDC_PORTRAIT_SIZE must be one of {valid}, "
                f"got {self.portrait_size}"
            )
            raise ValueError(msg)
        if self.default_access_token_format not in {"opaque", "jwt"}:
            msg = (
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT must be "
                "one of {'opaque', 'jwt'}, got "
                f"{self.default_access_token_format!r}"
            )
            raise ValueError(msg)
        if self.jwt_size_warn_bytes <= 0:
            msg = (
                "ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES must be >0, "
                f"got {self.jwt_size_warn_bytes}"
            )
            raise ValueError(msg)

    @classmethod
    def from_django(cls) -> OIDCSettings:
        """
        Return a cached snapshot built from the live
        ``django.conf.settings``.

        Delegates to a process-global ``lru_cache`` so the bundled
        ``getattr`` reads + ``__post_init__`` validation only run on
        the first call (and after every cache invalidation).
        ``connect_invalidator`` wires a ``setting_changed`` receiver
        that clears the cache when any ``ALLIANCEAUTH_OIDC_*``
        setting flips, which keeps ``@override_settings`` honest in
        tests while production benefits from "compute once".
        """
        return _cached_snapshot()


# Process-wide cache for ``OIDCSettings.from_django()``. Module-level
# rather than ``classmethod``-decorated because ``functools.lru_cache``
# on a bound method silently leaks ``cls``-typed entries across
# subclasses and test reloads. A bare cache keyed on no arguments is
# the simplest correct shape.
@functools.lru_cache(maxsize=1)
def _cached_snapshot() -> OIDCSettings:
    return OIDCSettings(
        log_masked_secrets=bool(
            getattr(
                settings, _KEY_LOG_MASKED_SECRETS, _DEFAULT_LOG_MASKED_SECRETS
            )
        ),
        log_mask_head=int(
            getattr(settings, _KEY_LOG_MASK_HEAD, _DEFAULT_LOG_MASK_HEAD)
        ),
        log_mask_tail=int(
            getattr(settings, _KEY_LOG_MASK_TAIL, _DEFAULT_LOG_MASK_TAIL)
        ),
        portrait_url_template=str(
            getattr(
                settings,
                _KEY_PORTRAIT_URL_TEMPLATE,
                _DEFAULT_PORTRAIT_URL_TEMPLATE,
            )
        ),
        portrait_size=int(
            getattr(settings, _KEY_PORTRAIT_SIZE, _DEFAULT_PORTRAIT_SIZE)
        ),
        eve_claim_prefix=str(
            getattr(settings, _KEY_EVE_CLAIM_PREFIX, _DEFAULT_EVE_CLAIM_PREFIX)
        ),
        eve_claim_scope=str(
            getattr(settings, _KEY_EVE_CLAIM_SCOPE, _DEFAULT_EVE_CLAIM_SCOPE)
        ),
        email_verified_default=bool(
            getattr(
                settings,
                _KEY_REGISTRATION_VERIFY_EMAIL,
                _DEFAULT_REGISTRATION_VERIFY_EMAIL,
            )
        ),
        force_email_verified=_resolve_force_email_verified(),
        default_access_token_format=_normalise_at_format(),
        jwt_size_warn_bytes=_normalise_jwt_size_warn_bytes(),
    )


def _provider_dict() -> dict[str, Any]:
    """Return the ``OAUTH2_PROVIDER`` settings dict, or empty if unset."""
    value = getattr(settings, _KEY_OAUTH2_PROVIDER, None)
    return value if isinstance(value, dict) else {}


def _normalise_at_format() -> Literal["opaque", "jwt"]:
    """
    Coerce ``OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT']``
    to the strict ``{"opaque", "jwt"}`` set.

    A typo or unexpected value (``"JWT"``, ``"oauth"``, ``42``) falls
    back to ``"opaque"`` — the safe-by-default of the two formats.
    Mirrors the pre-refactor ``security.AccessPolicy.access_token_format``
    truth table so behaviour is byte-identical.
    """
    raw = _provider_dict().get(
        _KEY_DEFAULT_ACCESS_TOKEN_FORMAT, _DEFAULT_ACCESS_TOKEN_FORMAT
    )
    if raw == "jwt":
        return "jwt"
    return "opaque"


def _normalise_jwt_size_warn_bytes() -> int:
    """
    Coerce ``OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES']``
    to a positive ``int``.

    Non-numeric / zero / negative values fall back to
    :data:`_DEFAULT_JWT_SIZE_WARN_BYTES` — mirrors the pre-refactor
    ``tokens._size_warn_threshold`` semantics so an operator
    misconfiguring the threshold gets a usable default instead of a
    ``ValueError`` at boot.
    """
    raw = _provider_dict().get(
        _KEY_JWT_SIZE_WARN_BYTES, _DEFAULT_JWT_SIZE_WARN_BYTES
    )
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_JWT_SIZE_WARN_BYTES
    if value <= 0:
        return _DEFAULT_JWT_SIZE_WARN_BYTES
    return value


def _resolve_force_email_verified() -> bool | None:
    """
    Read the tri-state ``ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED``.

    Returns ``None`` when the setting is absent or explicitly ``None``;
    coerces any other value to ``bool`` so an operator who set
    ``"true"`` (string) or ``1`` (int) gets a normalised flag instead
    of a confusing partial pass-through.
    """
    value = getattr(
        settings,
        _KEY_FORCE_EMAIL_VERIFIED,
        _DEFAULT_FORCE_EMAIL_VERIFIED,
    )
    if value is None:
        return None
    return bool(value)


# ``dispatch_uid`` for the ``setting_changed`` receiver. Tests that
# disconnect/reconnect the invalidator reuse this; production code
# never disconnects.
_INVALIDATOR_DISPATCH_UID: Final[str] = (
    "allianceauth_oidc.app_settings.invalidate_cached_snapshot"
)


def _invalidate_cached_snapshot(
    sender: object, setting: str, **kwargs: Any
) -> None:
    """
    Drop the cached snapshot on any AA-OIDC setting flip.

    ``OAUTH2_PROVIDER`` is included because two nested keys
    (:data:`_KEY_DEFAULT_ACCESS_TOKEN_FORMAT` and
    :data:`_KEY_JWT_SIZE_WARN_BYTES`) live under that dict — Django's
    ``setting_changed`` signal fires on the parent key when the dict
    is replaced via ``@override_settings(OAUTH2_PROVIDER={...})``,
    not on the nested entries, so the invalidator needs the parent
    name to round-trip correctly in tests.
    """
    if setting.startswith("ALLIANCEAUTH_OIDC_") or setting in {
        _KEY_REGISTRATION_VERIFY_EMAIL,
        _KEY_OAUTH2_PROVIDER,
    }:
        _cached_snapshot.cache_clear()


def connect_invalidator() -> None:
    """
    Wire the ``setting_changed`` invalidator to the snapshot cache.

    Called from ``AllianceAuthOIDC.ready()`` so the cache is honest
    under ``@override_settings`` in tests; production never emits
    ``setting_changed`` so the cache lives for the process lifetime.

    ``setting_changed`` is imported here (not at module level) to
    avoid pulling a symbol from ``django.test.signals`` into the
    production import graph — see the module-level note.
    """
    from django.test.signals import setting_changed

    setting_changed.connect(
        _invalidate_cached_snapshot,
        dispatch_uid=_INVALIDATOR_DISPATCH_UID,
    )
