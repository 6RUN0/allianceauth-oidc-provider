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

# dispatch_uid for the default audit receiver of
# ``oidc_code_reuse_detected``. Symmetry with :data:`AUDIT_DISPATCH_UID`
# — operator-facing receivers (SIEM forwarders, alerting hooks)
# connect with their own UID; this constant is the in-tree default so
# tests can disconnect/replace without re-deriving the string.
CODE_REUSE_AUDIT_DISPATCH_UID: Final[str] = (
    "allianceauth_oidc.audit_oidc_code_reuse_detected"
)

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

# dispatch_uid for the dead-letter recorder
# (``receivers.record_backchannel_logout_attempt``) connected to
# ``oidc_logout_dispatched``. Separate from the trigger UID above
# because this is the audit-sink path; tests that disable the
# recorder (e.g. to inspect raw signal payloads) reuse this constant
# to ``disconnect`` cleanly without affecting the dispatcher.
BCL_AUDIT_DISPATCH_UID: Final[str] = (
    "allianceauth_oidc.record_backchannel_logout_attempt"
)


# Closed value-sets for Prometheus metric labels — see
# ``docs/METRICS.md`` for the convention rule "label value sets are
# module-level Final[frozenset] constants, never inline literals".
# Promoting them out of ``_metrics.py`` / ``tasks.py`` / ``signals.py``
# eliminates the three-place drift that lets a new failure mode slip
# past one of the call sites and silently disappear from operator
# dashboards.

# Outcomes for ``aa_oidc_bcl_delivery_seconds`` (histogram, observed
# per HTTP attempt in ``tasks.send_logout_token``). Derived from the
# RP status code: 2xx → success, 3xx → redirect_blocked,
# 4xx → rp_client_error, 5xx → rp_server_error. Note this is the
# per-attempt vocabulary; the terminal-dispatch counter
# (:data:`BCL_DISPATCH_OUTCOMES`) is a different set because some
# terminal events never produce an HTTP exchange.
BCL_HISTOGRAM_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "success",
        "redirect_blocked",
        "rp_client_error",
        "rp_server_error",
    }
)

# Outcomes for ``aa_oidc_bcl_dispatches_total`` (counter, fires once
# per terminal ``oidc_logout_dispatched`` audit). Derived from the
# ``(success, reason)`` signature: ``success=True`` → ``"success"``,
# ``success=False`` → the literal ``reason`` kwarg. Keep in sync with
# the values emitted from ``tasks.send_logout_token`` and
# ``logout.dispatch_backchannel_logout`` — a value that fires the
# audit signal but is NOT in this set will produce a counter sample
# with an unrecognised label, which Grafana queries will silently
# miss.
BCL_DISPATCH_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "success",
        "redirect_blocked",
        "rp_client_error",
        "retries_exhausted",
        "signing_kid_retired",
        "signing_kid_resolve_failed",
        "broker_unavailable",
    }
)

# Subset of :data:`BCL_DISPATCH_OUTCOMES` classified as terminal
# failure for alerting. Operators compute the dead-letter rate as
# ``sum(rate(aa_oidc_bcl_dispatches_total{outcome=~"...|..."}[5m]))``
# joining these names; canonicalised here so the set ships with the
# module rather than being baked into individual Grafana dashboards.
# ``redirect_blocked`` and ``rp_client_error`` are included even
# though they originate from RP behaviour rather than infrastructure
# — both indicate the RP has refused (configuration drift on their
# side) and the AS will not retry. ``rp_server_error`` is NOT here:
# it only appears in the per-attempt histogram, and its terminal
# audit signal carries ``reason="retries_exhausted"`` instead.
BCL_DEAD_LETTER_OUTCOMES: Final[frozenset[str]] = frozenset(
    {
        "retries_exhausted",
        "signing_kid_retired",
        "signing_kid_resolve_failed",
        "broker_unavailable",
        "redirect_blocked",
        "rp_client_error",
    }
)

# Reasons for ``aa_oidc_authorize_denied_total`` (counter, fires
# from ``AuthAuthorizationView.dispatch``). Mirrors the
# ``Decision`` discriminated union in ``security.py``:
# ``GlobalDeny`` → ``"global"``, ``AppDeny`` → ``"app"``. Anonymous
# requests are NOT a denial (they redirect to ``LOGIN_URL``) and do
# not contribute to this counter.
AUTHORIZE_DENY_REASONS: Final[frozenset[str]] = frozenset({"global", "app"})
