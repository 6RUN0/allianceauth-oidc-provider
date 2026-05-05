"""
Cross-module string identifiers — single source of truth.

Only values that appear in more than one place AND would silently break
if they diverged (Django permission codenames, Celery task names, signal
dispatch UIDs) live here. Module-local magic numbers / format strings
stay next to their consumer.
"""

from typing import Final

# Permission codename + dotted label.
#
# - ``PERM_ACCESS_OIDC_CODENAME`` is what ``Meta.permissions`` registers
#   on ``AllianceAuthApplication``.
# - ``PERM_ACCESS_OIDC`` is what ``user.has_perm(...)`` expects.
#
# They MUST stay in sync; the dotted form is derived from the codename
# so any rename happens in one place.
PERM_ACCESS_OIDC_CODENAME: Final[str] = "access_oidc"
PERM_ACCESS_OIDC: Final[str] = f"allianceauth_oidc.{PERM_ACCESS_OIDC_CODENAME}"

# dispatch_uid for the default audit receiver of ``oidc_token_issued``.
# Tests that swap receivers in/out reuse this to avoid double-connecting.
AUDIT_DISPATCH_UID: Final[str] = "allianceauth_oidc.audit_oidc_token_issued"

# Celery task name. Operators reference this verbatim in
# ``CELERYBEAT_SCHEDULE``; the README documents the same string.
TASK_CLEAR_EXPIRED_TOKENS: Final[str] = (
    "allianceauth_oidc.clear_expired_tokens"
)
