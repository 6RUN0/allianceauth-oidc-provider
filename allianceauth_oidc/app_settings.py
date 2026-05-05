"""
Resolved Django settings for the OIDC provider with safe defaults.

Accessors are functions, not module-level constants — Django's
``@override_settings`` rebinds ``django.conf.settings`` per test, but
import-time ``getattr(settings, ...)`` snapshots the value before the
override runs and never sees changes. Reading via a function call keeps
the runtime tunable from tests and from operator hot-reloads.
"""

from django.conf import settings


def log_masked_secrets() -> bool:
    """
    Whether ``redact_secret`` returns a masked fragment instead of
    ``"<redacted>"``.

    Default: False (safest — never leaks length or
    prefix/suffix).
    """
    return bool(
        getattr(settings, "ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS", False)
    )


def log_mask_head() -> int:
    """
    Number of leading characters of a secret to show when masking is enabled.

    Default: 2.
    """
    return int(getattr(settings, "ALLIANCEAUTH_OIDC_LOG_MASK_HEAD", 2))


def log_mask_tail() -> int:
    """
    Number of trailing characters of a secret to show when masking is enabled.

    Default: 2.
    """
    return int(getattr(settings, "ALLIANCEAUTH_OIDC_LOG_MASK_TAIL", 2))
