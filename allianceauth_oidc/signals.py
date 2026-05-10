"""``oidc_token_issued`` audit signal and the default audit receiver."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, TypedDict

from django.dispatch import Signal
from typing_extensions import NotRequired

from .constants import AUDIT_DISPATCH_UID

if TYPE_CHECKING:
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
