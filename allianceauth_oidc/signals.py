"""
``oidc_token_issued`` audit signal and the default audit receiver.

Also defines the OIDC Back-Channel Logout 1.0 signal pair —
``oidc_logout_required`` (a trigger raised by any of the five v1 sites:
revoke command, ``is_active`` flip, group/state change, account
delete) and ``oidc_logout_dispatched`` (an audit signal fired by the
Celery task on every fan-out attempt). Wiring of the default
``oidc_logout_required`` dispatcher lives in ``apps.py:ready()``
alongside the audit receiver wiring.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, TypedDict

from django.dispatch import Signal
from typing_extensions import NotRequired

from .constants import (
    AUDIT_DISPATCH_UID,
    CODE_REUSE_AUDIT_DISPATCH_UID,
    DEFAULT_LOGOUT_DISPATCH_UID,
    INTROSPECT_AUDIT_DISPATCH_UID,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest

    from .security import TokenLike

logger = logging.getLogger(f"extensions.{__name__}")


class OIDCAuditBody(TypedDict):
    """
    Curated, secret-free payload of the ``oidc_token_issued`` signal.

    Only the OAuth2 request fields safe for audit forwarding —
    ``grant_type`` and ``scope``. NEVER add raw token strings,
    ``client_secret``, ``code``, or any other authentication material:
    receivers may forward this dict to SIEM/log sinks, and the
    "no-secrets-in-audit" guarantee depends on the sender contract.
    Use ``token`` (the persisted ``AccessToken`` model) for anything
    derivable from the issued token; receivers can read ``token.scope``,
    ``token.user``, ``token.application`` directly.

    Each field is ``NotRequired`` (PEP 655) so a sender can omit a key
    rather than emitting it as ``None``, while still letting future
    additions mark themselves required without churning the existing
    optional ones.
    """

    grant_type: NotRequired[str | None]
    scope: NotRequired[str | None]
    # Wire format of the issued ``access_token`` — ``"opaque"``,
    # ``"jwt"``, or ``None`` if the dispatcher could not classify the
    # token (e.g. hashed-at-rest storage). Exposed for SIEM receivers
    # that route differently for JWT vs opaque issuance; never used
    # for security decisions.
    format: NotRequired[str | None]


# Custom signal instead of direct logging inside TokenView:
# - TokenView is responsible for protocol/response, while auditing
#   is a separate concern.
# - signals make it easier to swap handlers, test, and/or forward events
#   to SIEM/audit sinks without changing the core token issuance logic.
# - use_caching=True helps when emitting frequently: Django caches
#   the receiver list.
#
# Receiver contract (READ BEFORE WIRING NEW RECEIVERS):
#
#     def my_receiver(sender, request, token, body=None, **kwargs):
#         ...
#
# - ``body`` is the curated, secret-free :class:`OIDCAuditBody` —
#   safe to forward to SIEM/log sinks unchanged.
# - ``token`` is the persisted :class:`oauth2_provider.AccessToken`
#   model. Reading ``token.scope``, ``token.user``, ``token.application``,
#   ``token.expires``, ``token.id`` is safe.
#   *NEVER forward, log, repr, or otherwise serialise the
#   ``token.token`` attribute or the model as a whole* — it carries
#   the raw bearer token (including a JWT with embedded identity
#   claims when the dispatcher issued in JWT mode). Forwarding it
#   to an external sink leaks a credential that is valid for the
#   token's full TTL. The default receiver
#   :func:`audit_oidc_token_issued` is hand-written to read only
#   non-sensitive fields; new receivers should follow that pattern.
oidc_token_issued = Signal(use_caching=True)


def audit_oidc_token_issued(
    sender: object,
    request: HttpRequest | None,
    token: TokenLike,
    body: OIDCAuditBody | None = None,
    *args: Any,
    **kwargs: Any,
) -> None:
    """
    Default audit receiver — log minimal, secret-free metadata.

    Security note: do NOT log OAuth token responses (access/refresh/id
    tokens). Only minimal, non-secret metadata is logged here.

    Why we never log tokens, even in debug_mode:
    - access_token/refresh_token/id_token are effectively passwords
      for their lifetime.
    - logs often end up in centralized systems/backups and outlive
      the token itself, which increases compromise risk.
    """
    try:
        app = getattr(token, "application", None)
        user = getattr(token, "user", None)
        meta = None
        if body:
            meta = {k: body.get(k) for k in ("grant_type", "scope")}
            meta = {k: v for k, v in meta.items() if v is not None} or None
        logger.info(
            "OIDC token issued client_id=%s app_id=%s user_id=%s username=%s scope=%s meta=%s",  # noqa: E501
            getattr(app, "client_id", None),
            getattr(app, "id", None),
            getattr(user, "id", None),
            getattr(user, "username", None),
            getattr(token, "scope", None),
            meta,
        )
    except (AttributeError, TypeError, ValueError, KeyError):
        # Narrow except: the only failure modes inside the body above
        # are partially-mocked tokens (AttributeError), bad meta types
        # (TypeError), bad string formatting (ValueError), or
        # body.get(...) misuse (KeyError). Keep MemoryError /
        # RecursionError / KeyboardInterrupt propagating so genuine
        # bugs surface in tests instead of getting silently logged.
        # Include the token's type and any non-secret identifiers
        # extracted before the failure — operators grep these to
        # figure out which receiver/path is broken.
        logger.exception(
            "Failed to audit OIDC token issuance (token_type=%s, application_id=%s, user_id=%s)",  # noqa: E501
            type(token).__name__,
            getattr(getattr(token, "application", None), "id", None),
            getattr(getattr(token, "user", None), "id", None),
        )


def connect_default_receiver() -> None:
    """
    Wire ``audit_oidc_token_issued`` to ``oidc_token_issued``.

    Called from ``AllianceAuthOIDC.ready()`` rather than at module
    import — Django's documented signal-handling idiom — so that
    importing names from this module (e.g. ``OIDCAuditBody``) does
    not have the side effect of connecting the default receiver.
    Tests that need a clean signal can ``oidc_token_issued.disconnect``
    by ``dispatch_uid`` and re-call this function in cleanup.
    """
    oidc_token_issued.connect(
        audit_oidc_token_issued,
        dispatch_uid=AUDIT_DISPATCH_UID,
    )


# RFC 6749 §10.5 reuse-detection signal. Fired by
# ``AllianceAuthOAuth2Validator.validate_code`` when a previously-issued
# authorization code is presented again. By the time this fires the
# validator has already revoked the linked AccessToken / RefreshToken;
# the signal exists so operators can fan the event out to SIEM /
# alerting independently of the WARNING log line.
#
# Receiver contract:
#
#     def my_receiver(
#         sender, application, code_hash, access_token_id,
#         refresh_token_id, reuse_count, **kwargs,
#     ):
#         ...
#
# - ``application`` is the :class:`AllianceAuthApplication` instance
#   the reuse attempt targeted. May be ``None`` if reuse was detected
#   against a deleted application row (the audit table preserves the
#   ``application_id`` FK as SET_NULL, so this is rare but possible).
# - ``code_hash`` is the sha256 hex of the replayed authorization
#   code. Storing the hash (not the plaintext code) keeps audit logs
#   forensically useful without re-introducing the secret.
# - ``access_token_id`` / ``refresh_token_id`` are the PKs of the
#   tokens that were revoked, or ``None`` if the audit row pointed at
#   tokens that had already been cleaned up by
#   :func:`tasks.clear_expired_tokens`.
# - ``reuse_count`` is the post-increment count of replays observed
#   for this code (>=1). Receivers can route higher counts to a more
#   aggressive alert path.
oidc_code_reuse_detected = Signal(use_caching=True)


def audit_oidc_code_reuse_detected(
    sender: object,
    application: Any,
    code_hash: str,
    access_token_id: int | None,
    refresh_token_id: int | None,
    reuse_count: int,
    *args: Any,
    **kwargs: Any,
) -> None:
    """
    Default audit receiver — log the reuse event at WARNING.

    The code hash is the only token-derived value on the wire, and
    sha256 is one-way: receivers may forward this payload to SIEM
    unchanged. Token PKs are integers (not the bearer strings) so
    they too are safe to forward.
    """
    logger.warning(
        "OIDC code-reuse detected client_id=%s app_id=%s code_hash=%s "
        "revoked_access_token_id=%s revoked_refresh_token_id=%s "
        "reuse_count=%s",
        getattr(application, "client_id", None),
        getattr(application, "id", None),
        code_hash,
        access_token_id,
        refresh_token_id,
        reuse_count,
    )


def connect_default_code_reuse_receiver() -> None:
    """
    Wire ``audit_oidc_code_reuse_detected`` to
    ``oidc_code_reuse_detected``.

    Mirror of :func:`connect_default_receiver` — wired from
    :meth:`AllianceAuthOIDC.ready` so importing this module does not
    have the side effect of connecting receivers.
    """
    oidc_code_reuse_detected.connect(
        audit_oidc_code_reuse_detected,
        dispatch_uid=CODE_REUSE_AUDIT_DISPATCH_UID,
    )


class OIDCIntrospectionAuditBody(TypedDict):
    """
    Curated, secret-free payload of the ``oidc_token_introspected``
    signal.

    RFC 7662 introspection is a probe by a resource server for a
    token's validity; the audit answers "which RS asked, about
    whose token, was it active". Discipline mirrors
    :class:`OIDCAuditBody`: no raw bearer values, ever. Identity
    of the introspected token is carried as its sha256 hex
    (``token_sha256``) so SIEM receivers can correlate against
    ``IssuedCodeAudit`` rows and ``oidc_token_issued`` payloads
    without a fresh leak surface.
    """

    # RFC 7662 §2.2 ``active`` field as the AS resolved it.
    active: NotRequired[bool | None]
    # ``client_id`` of the application that ORIGINALLY issued the
    # introspected token (i.e. the audit subject). Absent when the
    # token was invalid / unknown.
    client_id: NotRequired[str | None]
    # sha256(token) hex. Matches DOT's persisted ``token_checksum``
    # column on ``AccessToken`` so correlations with
    # ``IssuedCodeAudit`` and ``oidc_token_issued`` are first-class.
    token_sha256: NotRequired[str | None]


# RFC 7662 introspection audit signal. Fired by
# ``AllianceAuthIntrospectTokenView.dispatch`` on every introspect
# request (active or not), AFTER the JSON response is built but
# BEFORE it leaves the view. Receivers MUST NOT depend on the
# response body — they receive the same metadata via ``body``.
#
# Receiver contract:
#
#     def my_receiver(
#         sender, request, introspector,
#         body: OIDCIntrospectionAuditBody, **kwargs,
#     ):
#         ...
#
# - ``introspector`` is the Django ``User`` whose bearer token was
#   used to authenticate to ``/o/introspect/`` (NOT the user
#   whose token was introspected — that one is implied by the
#   ``client_id`` field in ``body``). Use it to attribute the
#   probe ("which RS account is enumerating tokens").
# - ``body`` is the curated, secret-free :class:`OIDCIntrospectionAuditBody`.
#   Safe to forward to SIEM unchanged. The raw introspected token
#   value is NOT carried — only its sha256.
oidc_token_introspected = Signal(use_caching=True)


def audit_oidc_token_introspected(
    sender: object,
    request: HttpRequest | None,
    introspector: Any,
    body: OIDCIntrospectionAuditBody | None = None,
    *args: Any,
    **kwargs: Any,
) -> None:
    """
    Default audit receiver — log minimal, secret-free metadata.

    Logs at INFO. Operators who want introspection logged at WARNING
    (e.g. for "every probe matters" deployments) connect a
    second receiver under a different ``dispatch_uid``; this default
    keeps the noise floor low for the common case where introspect
    fires on every request the RS handles.
    """
    try:
        meta = None
        if body:
            meta = {
                k: body.get(k) for k in ("active", "client_id", "token_sha256")
            }
            meta = {k: v for k, v in meta.items() if v is not None} or None
        logger.info(
            "OIDC token introspected introspector_id=%s "
            "introspector_username=%s meta=%s",
            getattr(introspector, "id", None),
            getattr(introspector, "username", None),
            meta,
        )
    except (AttributeError, TypeError, ValueError, KeyError):
        # Same narrow-except discipline as
        # :func:`audit_oidc_token_issued` — let real bugs surface
        # rather than swallowing them under a bare ``Exception``.
        logger.exception(
            "Failed to audit OIDC token introspection (introspector_id=%s)",
            getattr(introspector, "id", None),
        )


def connect_default_introspect_receiver() -> None:
    """
    Wire ``audit_oidc_token_introspected`` to ``oidc_token_introspected``.

    Mirror of :func:`connect_default_receiver` — wired from
    :meth:`AllianceAuthOIDC.ready`.
    """
    oidc_token_introspected.connect(
        audit_oidc_token_introspected,
        dispatch_uid=INTROSPECT_AUDIT_DISPATCH_UID,
    )


class LogoutAuditBody(TypedDict):
    """
    Curated, secret-free payload of the ``oidc_logout_dispatched``
    signal.

    Discipline mirrors :class:`OIDCAuditBody`: only fields safe for
    SIEM forwarding. ``application_id`` is the integer PK (an
    operator can resolve ``client_id`` / ``name`` from it without
    putting either string on the wire). ``reason`` is one of the
    stable strings emitted by the dispatcher
    (``"user_revoked"``, ``"user_deactivated"``, ``"groups_changed"``,
    ``"state_changed"``, ``"user_deleted"``, ``"retries_exhausted"``,
    ``"redirect_blocked"``, ``"signing_kid_retired"``,
    ``"broker_unavailable"``).  ``jti`` is the per-attempt UUID4 hex
    of the issued ``logout_token`` and is the spec-defined
    idempotency key — RPs MUST dedup on it (OIDC BCL 1.0 §2.6), so
    exposing it for audit/correlation is safe and useful.
    ``user_pk`` is the integer PK of the user whose session is being
    terminated; carried as a scalar (not a model instance) so the
    ``user_deleted`` path can still report which user the fan-out
    was for after the row is gone.

    No ``sid`` key in v1 (sub-only logout per plan v5).
    """

    application_id: NotRequired[int | None]
    user_pk: NotRequired[int | None]
    reason: NotRequired[str | None]
    jti: NotRequired[str | None]


# OIDC Back-Channel Logout 1.0 trigger. Raised by the five v1 sites
# (revoke command, ``is_active`` flip, m2m_changed on User.groups,
# AA ``state_changed``, ``post_delete`` on User). Receiver signature:
#
#     def dispatcher(sender, user, application, reason=None, **kwargs):
#         ...
#
# ``reason`` is one of ``user_revoked`` / ``user_deactivated`` /
# ``groups_changed`` / ``state_changed`` / ``user_deleted`` — see
# plan v5 §5.2 AC-8 for the closed set. The default dispatcher
# (``logout.dispatch_backchannel_logout``) computes a ``jti``, pins
# ``iat`` at enqueue time, and submits one Celery task per RP via
# ``transaction.on_commit`` so a rolled-back trigger does not page out
# logout_tokens.
oidc_logout_required = Signal(use_caching=True)

# OIDC Back-Channel Logout 1.0 audit signal. Fired by
# ``tasks.send_logout_token`` on every fan-out attempt (success or
# final failure) AND by the dispatcher when the broker is down or
# the signing key has rotated out. Receiver signature:
#
#     def auditor(
#         sender, application, jti, success, attempt_count,
#         user_pk=None, reason=None, **kwargs,
#     ):
#         ...
#
# ``user_pk`` is an integer PK rather than a model instance so the
# ``user_deleted`` trigger can still report which user the fan-out
# was for after the User row has been deleted. Receivers that need
# the model can ``User.objects.filter(pk=user_pk).first()``.
#
# Default receivers: the structured logger inside ``logout.py`` /
# ``tasks.py`` AND the dead-letter recorder
# (``receivers.record_backchannel_logout_attempt``). SIEM forwarders
# can connect a custom receiver under a different ``dispatch_uid``.
# Spec §2.6 makes the RP responsible for ``jti`` idempotency, so the
# AS may emit multiple ``oidc_logout_dispatched`` events for the
# same ``(user, application)`` pair — receivers MUST tolerate that.
oidc_logout_dispatched = Signal(use_caching=True)


class BackChannelLogoutSender:
    """
    Stable ``sender`` for ``oidc_logout_dispatched.send`` from both
    the dispatcher (``logout.dispatch_backchannel_logout``) and the
    Celery worker (``tasks.send_logout_token``).

    ``Signal(use_caching=True)`` keys receivers via
    ``WeakValueDictionary``; module-level functions and Celery's
    ``PromiseProxy`` task object are NOT reliably weak-ref'able, so
    a class object — always hashable AND weak-ref'able — is the
    stable handle the whole BCL audit pipeline shares. Receivers
    filtering on ``sender=BackChannelLogoutSender`` route every BCL
    audit event in one match; the ``reason`` kwarg disambiguates
    the specific failure mode (``"broker_unavailable"`` /
    ``"signing_kid_retired"`` / ``"retries_exhausted"`` / ...).
    """


def connect_default_logout_receiver(receiver: Callable[..., Any]) -> None:
    """
    Wire ``receiver`` (typically ``logout.dispatch_backchannel_logout``)
    to ``oidc_logout_required`` under :data:`DEFAULT_LOGOUT_DISPATCH_UID`.

    Indirection-via-callable mirrors :func:`connect_default_receiver`,
    but takes the dispatcher as an argument: at ``apps.py:ready()``
    time the receiver lives in ``logout.py``, which has its own
    initialisation order considerations (jwcrypto import, key load).
    Letting ``apps.py`` pass the function in keeps the import graph
    one-way (``apps -> logout``, never ``signals -> logout``).

    ``weak=False`` because the dispatcher is a module-level function
    that must outlive any GC pass — weak-ref disconnects from module
    reloads in test runners would silently drop logouts.
    """
    oidc_logout_required.connect(
        receiver,
        dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID,
        weak=False,
    )
