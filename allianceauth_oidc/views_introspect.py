"""
Introspect endpoint: emit the ``oidc_token_introspected`` audit signal.

DOT's stock :class:`IntrospectTokenView` performs the RFC 7662 lookup
and renders ``{"active": true/false, ...}`` but produces no audit
trail — the resource server that probes the AS for token validity
goes unobserved. The override below preserves DOT's contract byte-for-
byte (status / headers / body) and adds one audit signal emit after
the response is rendered.

Security discipline mirrors :mod:`allianceauth_oidc.signals`:

* Never log the raw bearer value of the introspected token. The
  signal carries the sha256 hex (matching DOT's persisted
  ``AccessToken.token_checksum``) so SIEM joins remain possible
  without a leak surface.
* ``request.user`` here is the **introspector** — the Django user
  whose bearer reached the endpoint, NOT the user whose token was
  asked about. RFC 7662 introspection uses the
  ``required_scopes = ["introspection"]`` gate on
  ``ClientProtectedScopedResourceView``, so by the time
  ``dispatch`` returns ``request.user`` is the authenticated
  introspector.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, cast

from oauth2_provider.views.introspect import IntrospectTokenView

from .signals import (
    OIDCIntrospectionAuditBody,
    dispatch_audit_signal,
    oidc_token_introspected,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

logger = logging.getLogger(f"extensions.{__name__}")


class AllianceAuthIntrospectTokenView(IntrospectTokenView):
    """
    RFC 7662 introspection with one extra audit emit.

    The hot-path response (``get_token_response``) is inherited
    verbatim from DOT. Override sits in ``dispatch`` so that BOTH
    GET (``?token=...``) and POST (form-encoded) paths fan into the
    same signal — leaving the audit on one verb would miss the
    other (DOT clients are split between the two roughly evenly).
    """

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        """Run DOT's introspect, then emit ``oidc_token_introspected``."""
        # ``super().dispatch`` is typed ``Any`` upstream — DOT's
        # ``View`` ancestor lacks a stub for the method, so mypy
        # narrows to ``Any``. ``cast`` makes the contract explicit:
        # at runtime DOT always returns an :class:`HttpResponseBase`,
        # but the cast is the only way to satisfy ``no-any-return``
        # without relaxing project-wide mypy strictness.
        response = cast(
            "HttpResponseBase", super().dispatch(request, *args, **kwargs)
        )
        try:
            self._emit_introspect_audit(request, response)
        except Exception:  # noqa: BLE001
            # An audit failure MUST NOT break introspection — the
            # protocol response is the contract operators rely on,
            # the signal is observability scaffolding. ``BLE001`` is
            # acknowledged: a narrower catch would risk masking a
            # new dispatch-time exception class we did not predict
            # (e.g. a future django.http addition). Log loudly with
            # ``exc_info=True`` so the failure does surface to the
            # operator without crashing the request.
            logger.warning(
                "OIDC introspect audit emit failed",
                exc_info=True,
            )
        return response

    @staticmethod
    def _extract_token_value(request: HttpRequest) -> str | None:
        """
        Read the introspected token value off the request.

        Mirrors DOT's own retrieval order in ``get`` / ``post``:
        GET ``?token=...`` first (RFC 7662 §2.1 "MAY"), POST body
        ``token=...`` second (RFC 7662 §2.1 "MUST"). Either may be
        absent — DOT renders a 400 in that case, and the audit
        still fires with ``token_sha256=None`` to record the
        malformed probe.
        """
        return request.GET.get("token") or request.POST.get("token") or None

    @staticmethod
    def _parse_response_metadata(
        response: HttpResponseBase,
    ) -> tuple[bool | None, str | None]:
        """
        Pull ``(active, client_id)`` out of DOT's JSON response.

        Defensive: the response body is small JSON the parent view
        just produced, but a 4xx error path (missing token, malformed
        JSON) may carry a body that does not deserialise. Both
        return slots fall through to ``None`` on any failure — the
        audit emit must always succeed, even when the introspect
        response itself is degraded.
        """
        content = getattr(response, "content", None)
        if not content:
            return None, None
        try:
            data = json.loads(content)
        except (ValueError, TypeError):
            return None, None
        if not isinstance(data, dict):
            return None, None
        active_raw = data.get("active")
        active: bool | None = (
            bool(active_raw) if isinstance(active_raw, bool) else None
        )
        client_id_raw = data.get("client_id")
        client_id: str | None = (
            client_id_raw if isinstance(client_id_raw, str) else None
        )
        return active, client_id

    def _emit_introspect_audit(
        self, request: HttpRequest, response: HttpResponseBase
    ) -> None:
        """
        Compose the :class:`OIDCIntrospectionAuditBody` and emit.

        ``token_sha256`` is the same hex DOT writes to
        ``AccessToken.token_checksum`` — receivers can join the
        audit stream against issued tokens without ever seeing a
        raw bearer.
        """
        token_value = self._extract_token_value(request)
        token_sha256: str | None
        if token_value:
            token_sha256 = hashlib.sha256(
                token_value.encode("utf-8")
            ).hexdigest()
        else:
            token_sha256 = None
        active, client_id = self._parse_response_metadata(response)
        body: OIDCIntrospectionAuditBody = {
            "active": active,
            "client_id": client_id,
            "token_sha256": token_sha256,
        }
        dispatch_audit_signal(
            oidc_token_introspected,
            signal_name="oidc_token_introspected",
            sender=type(self),
            request=request,
            introspector=getattr(request, "user", None),
            body=body,
        )
