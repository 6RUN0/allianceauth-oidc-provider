import logging
from typing import Any

from oauth2_provider import signals

logger = logging.getLogger(__name__)


def audit_oidc_token_issued(
    sender: Any,
    request: Any,
    token: Any,
    body: dict | None = None,
    *args: Any,
    **kwargs: Any,
) -> None:
    """
    Security note:
    Do NOT log OAuth token responses (access/refresh/id tokens).
    Only log minimal metadata for auditing.
    """
    try:
        app = getattr(token, "application", None)
        user = getattr(token, "user", None)
        meta = None
        if isinstance(body, dict):
            meta = {
                k: body.get(k) for k in ("grant_type", "scope") if k in body
            }
        logger.info(
            "OIDC token issued client_id=%s app_id=%s user_id=%s username=%s scope=%s meta=%s",  # noqa 501
            getattr(app, "client_id", None),
            getattr(app, "id", None),
            getattr(user, "id", None),
            getattr(user, "username", None),
            getattr(token, "scope", None),
            meta,
        )
    except Exception:
        # Never fail the auth flow because of logging.
        logger.exception("Failed to audit OIDC token issuance")


signals.app_authorized.connect(
    audit_oidc_token_issued,
    dispatch_uid="allianceauth_oidc.audit_oidc_token_issued",
)
