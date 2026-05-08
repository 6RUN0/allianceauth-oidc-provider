"""
Resolved Django settings for the OIDC provider with safe defaults.

Accessors are functions, not module-level constants — Django's
``@override_settings`` rebinds ``django.conf.settings`` per test, but
import-time ``getattr(settings, ...)`` snapshots the value before the
override runs and never sees changes. Reading via a function call keeps
the runtime tunable from tests and from operator hot-reloads.

For dependency-injection-friendly use, ``OIDCSettings.from_django()``
wraps the seven scalar accessors in a frozen dataclass; pass it in
where you would otherwise call ``app_settings.foo()`` so tests can
hand-craft a config without ``@override_settings``.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Final

from django.conf import settings
from django.test.signals import setting_changed

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

    @classmethod
    def from_django(cls) -> OIDCSettings:
        """
        Return a cached snapshot built from the live
        ``django.conf.settings``.

        Delegates to a process-global ``lru_cache`` so the seven
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
    )


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
    """Drop the cached snapshot on any AA-OIDC setting flip."""
    if (
        setting.startswith("ALLIANCEAUTH_OIDC_")
        or setting == _KEY_REGISTRATION_VERIFY_EMAIL
    ):
        _cached_snapshot.cache_clear()


def connect_invalidator() -> None:
    """
    Wire the ``setting_changed`` invalidator to the snapshot cache.

    Called from ``AllianceAuthOIDC.ready()`` so the cache is honest
    under ``@override_settings`` in tests; production never emits
    ``setting_changed`` so the cache lives for the process lifetime.
    """
    setting_changed.connect(
        _invalidate_cached_snapshot,
        dispatch_uid=_INVALIDATOR_DISPATCH_UID,
    )
