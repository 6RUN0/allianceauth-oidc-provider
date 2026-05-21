"""
Optional Prometheus metrics layer.

Cooperate-don't-depend pattern: when ``django-prometheus`` is
installed — via the ``[metrics]`` extra or pulled in by another AA
module's dependency chain — our ``Counter`` / ``Histogram`` /
``Gauge`` calls register into the default
:data:`prometheus_client.REGISTRY`, and ``django-prometheus``'
``/metrics`` endpoint exports them alongside its own HTTP, cache,
migration, and Celery metrics. Without it, every metric reference
resolves to a :class:`_NoOpMetric` stub at near-zero runtime cost.

Naming
------
All metric names use the ``aa_oidc_*`` prefix so a Grafana panel
filtering ``{__name__=~"aa_.*"}`` pulls metrics from every AA
module that adopts the same convention. ``Counter`` sample names
inherit the ``_total`` suffix from prometheus_client's modern
constructor — passing ``aa_oidc_tokens_issued`` to ``Counter(...)``
emits a sample called ``aa_oidc_tokens_issued_total`` regardless
of whether the constructor argument carried the suffix.

Wiring
------
:func:`connect_metrics_receivers` is called unconditionally from
``AllianceAuthOIDC.ready()`` — the receiver registers either way,
so the no-op branch is exercised on every Django startup, not just
when metrics are enabled. Receivers connect under stable
``dispatch_uid`` strings so tests can ``disconnect`` cleanly without
collateral damage.
"""

from __future__ import annotations

import logging
from typing import Any, Final

logger = logging.getLogger(f"extensions.{__name__}")


def _detect_django_prometheus() -> bool:
    """
    Probe for ``django_prometheus`` without leaving an import alias.

    ``django_prometheus`` exposes no API surface we call directly —
    its presence is the cooperate-don't-depend gate, nothing more.
    Isolating the ``try`` / ``except ImportError`` inside a function
    keeps the module body free of conditional aliases that would
    confuse static analysers (``Counter`` / ``Histogram`` possibly
    unbound, ``django_prometheus`` reported as an unused module
    import). The actual ``prometheus_client`` symbols are imported
    inside the factory functions below, gated on the same boolean.
    """
    try:
        import django_prometheus  # noqa: F401  # pyright: ignore[reportUnusedImport]
    except ImportError:
        logger.debug(
            "django-prometheus not installed; OIDC metrics resolve to no-ops"
        )
        return False
    return True


_ENABLED: Final[bool] = _detect_django_prometheus()


class _NoOpMetric:
    """
    Chain-friendly stub mirroring the Counter/Histogram/Gauge API.

    Returns ``self`` from :meth:`labels` so chained ``.inc()`` /
    ``.observe()`` calls keep working on the returned object.
    :meth:`set_function` is a no-op so a scrape-time gauge silently
    disables itself when metrics are unavailable. Parameter names
    carry a leading underscore so static-analysis tools that flag
    unused arguments (vulture) recognise the deliberate stub
    pattern; the public signatures still mirror
    ``prometheus_client.Counter.inc(amount)`` and friends at the
    runtime call site (kwarg names are not part of the API surface
    callers exercise).
    """

    def labels(self, *_: object, **__: object) -> _NoOpMetric:
        return self

    def inc(self, _amount: float = 1.0) -> None:
        pass

    def observe(self, _amount: float) -> None:
        pass

    def set(self, _value: float) -> None:
        pass

    def set_function(self, _fn: Any) -> None:
        pass


def _counter(name: str, doc: str, labelnames: tuple[str, ...] = ()) -> Any:
    if not _ENABLED:
        return _NoOpMetric()
    # Lazy-imported inside the gate so the unguarded module body
    # never references ``prometheus_client`` — and so static
    # analysers never see ``Counter`` as a possibly-unbound name
    # in an unrelated control-flow branch.
    from prometheus_client import Counter

    return Counter(name, doc, labelnames=labelnames)


def _histogram(
    name: str,
    doc: str,
    labelnames: tuple[str, ...] = (),
    buckets: tuple[float, ...] | None = None,
) -> Any:
    if not _ENABLED:
        return _NoOpMetric()
    from prometheus_client import Histogram

    kw: dict[str, Any] = {"labelnames": labelnames}
    if buckets is not None:
        kw["buckets"] = buckets
    return Histogram(name, doc, **kw)


# Stable public-API metric instances. Call sites import these by
# name (``from allianceauth_oidc._metrics import tokens_issued``)
# and call ``.labels(...).inc()`` / ``.observe(...)`` — never
# replace the module-level objects, that breaks every consumer.
tokens_issued = _counter(
    "aa_oidc_tokens_issued",
    "OIDC tokens issued, split by grant type and registered client.",
    labelnames=("grant_type", "client_id"),
)

# Discrete denial reasons mirror the ``Decision`` variants enforced by
# :class:`AuthAuthorizationView.dispatch`:
# - ``"global"`` — caller failed the global ``access_oidc`` permission
#   gate (no per-app check ran).
# - ``"app"`` — caller has global access but failed the state/groups
#   whitelist for the specific application.
# Anonymous callers do NOT contribute here: they are redirected to
# ``LOGIN_URL`` rather than denied, and counting redirects would
# conflate "user needs to log in" with "user denied access". Operators
# who want a login-required counter can read django-prometheus'
# ``django_http_responses_total_by_status_view_method{status="302"}``.
authorize_denied = _counter(
    "aa_oidc_authorize_denied",
    "OIDC authorization requests refused by policy.",
    labelnames=("reason",),
)

# Back-Channel Logout 1.0 delivery latency, observed at the call
# site in ``tasks.send_logout_token`` around the ``requests.post``
# round-trip. ``outcome`` labels are drawn from
# :data:`constants.BCL_HISTOGRAM_OUTCOMES` (per-HTTP-attempt
# vocabulary) so the per-attempt histogram joins the terminal
# :data:`bcl_dispatches` counter via a single Grafana query.
#
# Bucket choices: BCL targets are typically sub-second on a healthy
# RP, with the long tail dominated by SSL handshake + first-byte on
# cold connections. ``(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
# 15.0)`` covers normal traffic at fine resolution and still
# separates the timeout floor (10 s read timeout — see
# ``_HTTP_TIMEOUT`` in ``tasks.py``) from the timeout ceiling.
# ``+Inf`` is auto-appended by prometheus_client.
bcl_delivery_seconds = _histogram(
    "aa_oidc_bcl_delivery_seconds",
    "Back-channel logout HTTP delivery latency, by outcome.",
    labelnames=("client_id", "outcome"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0),
)

# Terminal BCL dispatches — fires once per ``oidc_logout_dispatched``
# audit event from the receiver below. ``outcome`` is derived from
# the ``(success, reason)`` signature: ``"success"`` when
# ``success=True``, otherwise the literal ``reason`` kwarg. Values
# are drawn from :data:`constants.BCL_DISPATCH_OUTCOMES`. Operators
# computing dead-letter rate sum this counter over the failure
# subset declared in :data:`constants.BCL_DEAD_LETTER_OUTCOMES`,
# rather than reading a dedicated counter — this avoids redundant
# metrics while keeping the dead-letter alerting recipe in one place
# (``docs/METRICS.md``).
bcl_dispatches = _counter(
    "aa_oidc_bcl_dispatches",
    "Back-channel logout terminal dispatches, by outcome.",
    labelnames=("client_id", "outcome"),
)

# Cross-stage view of policy rejections. Complements the older
# :data:`authorize_denied` (which only sees the authorize endpoint) by
# also tracking layer-2/3 rejections at ``validate_code``,
# ``validate_refresh_token``, ``validate_bearer_token`` and
# ``save_bearer_token`` — the four sites where an end-user who lost
# state/groups (or whose app went inactive) still attempts to exchange
# or refresh a token.
#
# Labels:
# - ``stage`` — one of ``"authorize"``, ``"validate_silent_auth"``,
#   ``"validate_code"``, ``"validate_refresh"``, ``"validate_bearer"``,
#   ``"save_bearer"``. Matches the value set callers pass at the emit
#   site, so a Grafana panel can rate-limit to specific stages (e.g.
#   "spike in ``validate_refresh`` after a group rename").
# - ``reason`` — one of ``DenyReason`` values
#   (``"global"`` / ``"app"``) plus the validator-specific
#   ``"app_unusable"`` (app row has ``active=False``) and
#   ``"no_client"`` (``save_bearer`` path with no resolved client).
#   ``"unknown"`` is a defensive fallback for partially-mocked
#   decisions in integration tests; production paths always populate
#   a real reason.
#
# Why not extend ``authorize_denied`` with a ``stage`` label: that
# counter is part of the public METRICS.md contract since 0.1; adding
# a label would invalidate every existing series and break recording
# rules. Side-by-side emission keeps backward compatibility and lets
# operators migrate dashboards at their own pace.
policy_rejections = _counter(
    "aa_oidc_policy_rejections",
    "OIDC policy rejections across all enforcement stages.",
    labelnames=("stage", "reason"),
)


# Reuse-detection observability for the RFC 6749 §10.5 SHOULD
# overlay. ``_handle_potential_code_reuse`` walks the
# ``IssuedCodeAudit`` table to find the linked tokens to revoke on a
# reuse hit. When the audit row is absent — exclusively for
# never-issued codes after the atomic wrap below closed the
# race-window source — this counter fires.
#
# ``save_bearer_token`` wraps the parent call and the audit-row
# insert in a single ``transaction.atomic``, so the prior race-window
# source — audit row missing for a code this provider DID issue — is
# closed: AT/RT writes and the audit row commit together. The only
# surviving source is therefore **never-issued codes** (fuzzers
# probing ``/o/token/`` with random ``code=...`` values; replays
# against an unrelated provider; clock-skewed Grant-expiry hits that
# DOT rejected before the audit lookup). The counter remains useful
# as a "did anyone hit the reuse path without us having issued the
# code" signal — operators correlate against the
# ``oidc_code_reuse_detected`` Django signal to confirm zero overlap
# (the two metrics are disjoint by construction).
code_reuse_audit_misses = _counter(
    "aa_oidc_code_reuse_audit_misses",
    (
        "Reuse-detection attempts where the audit row was absent — "
        "exclusively never-issued codes (fuzzer noise / "
        "wrong-provider replays); the race-window source is closed "
        "by the save_bearer_token atomic wrap. Operators correlate "
        "against the oidc_code_reuse_detected signal — the two "
        "should be disjoint."
    ),
    labelnames=("client_id",),
)


# Code-issuance audit rows skipped at ``_record_code_issuance``. The
# row insert is the audit-side anchor for the RFC 6749 §10.5 SHOULD
# overlay; a skip means the SHOULD path is silently degraded for
# that exchange. The only skip reason today is ``"no_client"`` (the
# oauthlib request reached ``save_bearer_token`` without a
# resolvable client — a state the validator stack should not allow,
# but the early-return is defensive). A non-zero rate here is an
# operator alert: either the validator stack changed, or a DOT
# grant type stopped populating ``request.client``. Drawn from
# :data:`constants.CODE_AUDIT_SKIPPED_REASONS`.
code_audit_skipped = _counter(
    "aa_oidc_code_audit_skipped",
    (
        "Code-issuance audit rows skipped because save_bearer_token "
        "could not resolve a client. Non-zero rate degrades the RFC "
        "6749 §10.5 SHOULD overlay for the affected exchanges; "
        "investigate the upstream validator stack."
    ),
    labelnames=("reason",),
)


# AccessToken rows removed by the periodic ``clear_expired_tokens``
# Celery task. The counter increments by the per-run delta, so
# ``rate(aa_oidc_tokens_cleaned_total[5m])`` matches the observed
# cleanup throughput. No labels — DOT's ``clear_expired()`` does
# not surface application or grant_type information. Combined with
# ``rate(aa_oidc_tokens_issued_total[5m])`` this lets operators
# approximate an "active tokens" derivative without a Gauge — the
# Gauge ``set_function`` pattern is incompatible with
# ``prometheus_client``'s multiprocess collector, which is the
# canonical production deployment for any non-trivial gunicorn AA
# install.
tokens_cleaned = _counter(
    "aa_oidc_tokens_cleaned",
    "Expired AccessTokens removed by the periodic cleanup task.",
)


# Receiver-failure observability for the audit signal pipeline.
# Every audit signal (``oidc_token_issued``,
# ``oidc_code_reuse_detected``, ``oidc_token_introspected``,
# ``oidc_logout_dispatched``) is dispatched via ``send_robust`` so a
# failing SIEM forwarder or external receiver cannot break the others
# — without this counter the only trace of a silently-broken audit
# pipeline would live in log lines operators rarely watch. One counter covers
# all four audit signals: ``signal`` is the signal name (matches the
# Python attribute), ``receiver_dispatch_uid`` is the receiver's
# ``dispatch_uid`` when set, else the receiver's ``__qualname__``
# or repr — a stable label across worker processes for SIEM
# correlation. ``rate(aa_oidc_audit_receiver_failures_total[5m])`` is
# the canonical alert: any non-zero rate means the audit pipeline is
# silently dropping events for at least one downstream consumer.
audit_receiver_failures = _counter(
    "aa_oidc_audit_receiver_failures",
    (
        "Audit-signal receivers that raised during dispatch. "
        "Non-zero rate means the audit pipeline is silently dropping "
        "events for at least one downstream consumer (SIEM, "
        "Prometheus collector, custom hook)."
    ),
    labelnames=("signal", "receiver_dispatch_uid"),
)


def _on_token_issued(
    sender: object,  # noqa: ARG001
    request: Any | None = None,  # noqa: ARG001
    token: Any | None = None,
    body: Any | None = None,
    **_: Any,
) -> None:
    """
    Increment ``aa_oidc_tokens_issued_total`` per issued token.

    Defensive on label resolution: an ``"unknown"`` fallback for
    both ``grant_type`` and ``client_id`` keeps the audit signal
    chain unbroken when a partially-mocked token reaches the
    receiver — a missed metric is acceptable, a crashed receiver
    is not (other audit/SIEM sinks share the same dispatch).
    """
    if not _ENABLED:
        return
    grant_type = "unknown"
    if isinstance(body, dict):
        grant_type = body.get("grant_type") or "unknown"
    client_id = "unknown"
    app = getattr(token, "application", None)
    if app is not None:
        client_id = getattr(app, "client_id", None) or "unknown"
    tokens_issued.labels(grant_type=grant_type, client_id=client_id).inc()


def _on_logout_dispatched(
    sender: object,  # noqa: ARG001
    application: Any | None = None,
    jti: str | None = None,  # noqa: ARG001
    success: bool = False,
    attempt_count: int = 0,  # noqa: ARG001
    user_pk: int | None = None,  # noqa: ARG001
    reason: str | None = None,
    **_: Any,
) -> None:
    """
    Increment ``aa_oidc_bcl_dispatches_total`` per terminal event.

    ``outcome`` is ``"success"`` when ``success=True``, otherwise
    the literal ``reason`` kwarg. A blank ``reason`` on a failure
    audit (the dispatcher contract guarantees one, but mocked
    senders in tests may omit it) falls back to ``"unknown"`` so
    the counter remains observable instead of silently dropping
    the event.
    """
    if not _ENABLED:
        return
    outcome = "success" if success else (reason or "unknown")
    client_id = "unknown"
    if application is not None:
        client_id = getattr(application, "client_id", None) or "unknown"
    bcl_dispatches.labels(client_id=client_id, outcome=outcome).inc()


def connect_metrics_receivers() -> None:
    """
    Wire the metric-emitting receivers to OIDC signals.

    Idempotent: each receiver connects under a stable
    ``dispatch_uid`` so a second call (e.g. test reset, app reload)
    replaces rather than duplicates the wiring. Lazy import of
    :mod:`.signals` keeps this module importable from ``apps.py``
    before Django's app registry is fully ready.
    """
    from .signals import oidc_logout_dispatched, oidc_token_issued

    oidc_token_issued.connect(
        _on_token_issued,
        dispatch_uid="allianceauth_oidc.metrics.tokens_issued",
    )
    oidc_logout_dispatched.connect(
        _on_logout_dispatched,
        dispatch_uid="allianceauth_oidc.metrics.bcl_dead_letters",
    )
