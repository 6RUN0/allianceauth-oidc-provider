"""
Cross-module string identifiers — single source of truth.

Only values that appear in more than one place AND would silently break
if they diverged (Django permission codenames, Celery task names, signal
dispatch UIDs) live here. Module-local magic numbers / format strings
stay next to their consumer.
"""

from enum import Enum
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
# ``oidc_token_introspected``. RFC 7662 introspection is the
# resource-server side of the trust boundary — every check is a
# probe by an RS for a token's validity, valuable signal for SIEM
# correlations ("RS X is enumerating tokens against AS"). Same  # noqa: ERA001
# disconnect / re-connect contract as :data:`AUDIT_DISPATCH_UID`.
INTROSPECT_AUDIT_DISPATCH_UID: Final[str] = (
    "allianceauth_oidc.audit_oidc_token_introspected"
)

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

# ``str, Enum`` mixin (not ``StrEnum`` — that landed in 3.11 and the
# project floor is 3.10) so each member equals its ``.value`` for
# free, label-emit sites can pass a member where Prometheus expects
# a string, and ``isinstance(x, str)`` keeps working. Mirrors the
# proven pattern in ``security.DenyReason``. Existing frozensets
# (:data:`BCL_HISTOGRAM_OUTCOMES` etc.) are rebuilt from the enum
# members so the value-set has one source of truth and Grafana
# queries keep matching the same strings.


class BCLHistogramOutcome(str, Enum):
    """
    Per-HTTP-attempt outcomes for ``aa_oidc_bcl_delivery_seconds``.

    Derived from the RP status code by ``_bcl_outcome_for_status``:
    2xx → SUCCESS, 3xx → REDIRECT_BLOCKED,
    4xx → RP_CLIENT_ERROR, 5xx → RP_SERVER_ERROR. Per-attempt
    vocabulary; the terminal-dispatch counter (:class:`BCLDispatchOutcome`)
    has its own set because some terminal events never produce an
    HTTP exchange.
    """

    SUCCESS = "success"
    REDIRECT_BLOCKED = "redirect_blocked"
    RP_CLIENT_ERROR = "rp_client_error"
    RP_SERVER_ERROR = "rp_server_error"


class BCLDispatchOutcome(str, Enum):
    """
    Terminal outcomes for ``aa_oidc_bcl_dispatches_total``.

    Fires once per terminal ``oidc_logout_dispatched`` audit. Derived
    from the ``(success, reason)`` signature: ``success=True`` →
    ``SUCCESS``, ``success=False`` → the ``reason`` kwarg. Keep in
    sync with the values emitted from ``tasks.send_logout_token``
    and ``logout.dispatch_backchannel_logout`` — a value that fires
    the audit signal but is NOT a member here will produce a
    counter sample with an unrecognised label, which Grafana
    queries will silently miss.
    """

    SUCCESS = "success"
    REDIRECT_BLOCKED = "redirect_blocked"
    RP_CLIENT_ERROR = "rp_client_error"
    RETRIES_EXHAUSTED = "retries_exhausted"
    # C-2: network-level exhaustion (ConnectionError / Timeout /
    # ssl errors). Distinct from the 5xx-driven ``RETRIES_EXHAUSTED``
    # so dashboards can separate "RP returned 5xx repeatedly"
    # (RP-application problem) from "RP unreachable" (network /
    # firewall / RP down). Both share the autoretry envelope.
    RETRIES_EXHAUSTED_NETWORK = "retries_exhausted_network"
    SIGNING_KID_RETIRED = "signing_kid_retired"
    SIGNING_KID_RESOLVE_FAILED = "signing_kid_resolve_failed"
    BROKER_UNAVAILABLE = "broker_unavailable"
    DNS_RESOLVE_FAILED = "dns_resolve_failed"
    UNSAFE_TARGET_IP = "unsafe_target_ip"


# Outcomes for ``aa_oidc_bcl_delivery_seconds`` — built from the
# enum so the frozenset cannot drift from the typed source of
# truth. Frozenset form preserved for callers iterating on it
# (Prometheus label-set validators in tests).
BCL_HISTOGRAM_OUTCOMES: Final[frozenset[str]] = frozenset(
    m.value for m in BCLHistogramOutcome
)

# Outcomes for ``aa_oidc_bcl_dispatches_total`` — built from the
# typed enum source. DNS_RESOLVE_FAILED and UNSAFE_TARGET_IP joined
# the set when the request-time SSRF gate started emitting them
# (see ``tasks._request_time_ssrf_gate_passes``).
BCL_DISPATCH_OUTCOMES: Final[frozenset[str]] = frozenset(
    m.value for m in BCLDispatchOutcome
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
        BCLDispatchOutcome.RETRIES_EXHAUSTED.value,
        BCLDispatchOutcome.SIGNING_KID_RETIRED.value,
        BCLDispatchOutcome.SIGNING_KID_RESOLVE_FAILED.value,
        BCLDispatchOutcome.BROKER_UNAVAILABLE.value,
        BCLDispatchOutcome.REDIRECT_BLOCKED.value,
        BCLDispatchOutcome.RP_CLIENT_ERROR.value,
        BCLDispatchOutcome.DNS_RESOLVE_FAILED.value,
        BCLDispatchOutcome.UNSAFE_TARGET_IP.value,
    }
)

# Reasons for ``aa_oidc_authorize_denied_total`` (counter, fires
# from ``AuthAuthorizationView.dispatch``). Mirrors the
# ``Decision`` discriminated union in ``security.py``:
# ``GlobalDeny`` → ``"global"``, ``AppDeny`` → ``"app"``. Anonymous
# requests are NOT a denial (they redirect to ``LOGIN_URL``) and do
# not contribute to this counter.
AUTHORIZE_DENY_REASONS: Final[frozenset[str]] = frozenset({"global", "app"})


# OIDC Back-Channel Logout 1.0 ``logout_token`` JWT lifetime (``exp -
# iat``) in seconds. Spec §2.4 lists ``exp`` as one of the standard
# claims a logout_token may carry; many RP libraries reject tokens
# without an ``exp`` when treating them like ``id_token`` (mod_auth_
# openidc, oidc-client-ts). The window must stay larger than the
# Celery retry envelope of :func:`tasks.send_logout_token`
# (5+10+20+40+80 = 155 s with jitter) so a retried JWT does not race
# its own expiry — 300 s gives ~2x headroom without re-introducing a
# meaningful replay window. RPs MUST still dedup on ``jti`` per spec
# §2.6, so ``exp`` is defence-in-depth against log-extracted JWT
# replay, not a primary control.
LOGOUT_TOKEN_LIFETIME_SECONDS: Final[int] = 300


# Reasons for ``aa_oidc_code_audit_skipped_total`` (counter, fires
# from ``_record_code_issuance`` when the audit row insert is
# skipped). One value today; named constant keeps Grafana queries
# stable if future skip paths are added.
class CodeAuditSkippedReason(str, Enum):
    """
    Why an authorization_code audit row was not recorded.

    ``NO_CLIENT`` — ``save_bearer_token`` ran without a resolvable
    client on the oauthlib request. Documented as a degraded path
    (the SHOULD overlay for RFC 6749 §10.5 silently drops for this
    exchange); the counter makes it observable instead of invisible.
    """

    NO_CLIENT = "no_client"


CODE_AUDIT_SKIPPED_REASONS: Final[frozenset[str]] = frozenset(
    m.value for m in CodeAuditSkippedReason
)
