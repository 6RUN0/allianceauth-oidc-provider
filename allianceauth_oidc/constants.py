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

# Celery task name for the OIDC Back-Channel Logout 1.0 fan-out
# dispatcher. ``dispatch_backchannel_logout`` queues one call per RP
# under this name; the worker rebuilds the logout_token JWT and POSTs
# it to ``application.backchannel_logout_uri``. Reference value for
# anything that needs to grep the task across the codebase / docs.
TASK_SEND_LOGOUT_TOKEN: Final[str] = "allianceauth_oidc.send_logout_token"

# dispatch_uid for the default ``oidc_logout_required`` receiver.
# Mirrors ``AUDIT_DISPATCH_UID``: tests that connect a custom logout
# dispatcher reuse this constant to disconnect the default first,
# preventing duplicate POSTs to RPs.
DEFAULT_LOGOUT_DISPATCH_UID: Final[str] = (
    "allianceauth_oidc.default_logout_dispatcher"
)
