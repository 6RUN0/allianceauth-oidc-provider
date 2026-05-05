"""
Resolved Django settings for the OIDC provider with safe defaults.

Accessors are functions, not module-level constants — Django's
``@override_settings`` rebinds ``django.conf.settings`` per test, but
import-time ``getattr(settings, ...)`` snapshots the value before the
override runs and never sees changes. Reading via a function call keeps
the runtime tunable from tests and from operator hot-reloads.
"""

from typing import Final

from django.conf import settings

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


def log_masked_secrets() -> bool:
    """
    Whether ``redact_secret`` returns a masked fragment instead of
    ``"<redacted>"``.

    Default: False (safest — never leaks length or
    prefix/suffix).
    """
    return bool(getattr(settings, _KEY_LOG_MASKED_SECRETS, False))


def log_mask_head() -> int:
    """
    Number of leading characters of a secret to show when masking is
    enabled.

    Default: 2.
    """
    return int(getattr(settings, _KEY_LOG_MASK_HEAD, 2))


def log_mask_tail() -> int:
    """
    Number of trailing characters of a secret to show when masking is
    enabled.

    Default: 2.
    """
    return int(getattr(settings, _KEY_LOG_MASK_TAIL, 2))


# Defaults match the official EVE Online image server. Operators can
# override via Django settings if they front the CDN through a mirror or
# want a different portrait size for the `picture` claim.
_DEFAULT_PORTRAIT_URL_TEMPLATE: Final[str] = (
    "https://images.evetech.net/characters/{character_id}/portrait?size={size}"
)
_DEFAULT_PORTRAIT_SIZE: Final[int] = 128


def portrait_url_template() -> str:
    """
    Template for the ``picture`` claim URL.

    ``{character_id}`` and ``{size}`` are substituted via ``str.format``.
    Override via ``ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE``.
    """
    return str(
        getattr(
            settings,
            _KEY_PORTRAIT_URL_TEMPLATE,
            _DEFAULT_PORTRAIT_URL_TEMPLATE,
        )
    )


def portrait_size() -> int:
    """
    Portrait size (px) substituted into the URL template.

    EVE's image server supports 32/64/128/256/512/1024. Default: 128. Override
    via ``ALLIANCEAUTH_OIDC_PORTRAIT_SIZE``.
    """
    return int(getattr(settings, _KEY_PORTRAIT_SIZE, _DEFAULT_PORTRAIT_SIZE))
