"""
Token endpoint: ``TokenView`` plus the audit pipeline.

Split off from the original single-file ``views.py`` (kept as a thin
re-export shim) because the token endpoint, the authorize endpoint
and the discovery view are three independent HTTP entry points that
never share code with each other. Tests targeting this module pin
``extensions.allianceauth_oidc.views_token`` for log assertions.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Final

from django.http import HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View
from oauth2_provider.models import get_access_token_model
from oauth2_provider.views.mixins import OAuthLibMixin

from .signals import dispatch_audit_signal, oidc_token_issued
from .utils import build_oidc_debug_meta

if TYPE_CHECKING:
    from .security import TokenLike
    from .signals import OIDCAuditBody

logger = logging.getLogger(f"extensions.{__name__}")


# Defence-in-depth cap on the body we'll JSON-parse. A correctly
# behaving DOT response is ~1KB; this leaves three orders of magnitude
# of headroom while preventing a misconfigured upstream from feeding
# an unbounded payload to json.loads.
_DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE: Final[int] = 64 * 1024


# A compact JWS has exactly three base64url segments (header,
# payload, signature). Used by ``classify_token_format`` to
# distinguish JWT-shaped tokens from opaque random strings.
_JWS_COMPACT_SEGMENT_COUNT: Final[int] = 3


def classify_token_format(token_str: object) -> str | None:
    """
    Heuristic format classification for an issued access token.

    Returns ``"jwt"`` if the token looks like a 3-segment JWS with
    a header that includes ``"typ": "at+jwt"`` (RFC 9068 §2.1);
    ``"opaque"`` otherwise; ``None`` if the input is not a string at
    all (hashed-at-rest storage exposes ``None`` for the raw value).

    Used only by the audit signal pipeline — the value flows through
    ``OIDCAuditBody["format"]`` to receivers that route differently
    on issued format. Never used for security decisions.
    """
    if not isinstance(token_str, str):
        return None
    parts = token_str.split(".")
    if len(parts) != _JWS_COMPACT_SEGMENT_COUNT:
        return "opaque"
    try:
        pad = "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + pad))
    except (ValueError, TypeError, binascii.Error):
        return "opaque"
    if isinstance(header, dict) and header.get("typ") == "at+jwt":
        return "jwt"
    return "opaque"


@dataclass
class TokenAudit:
    """
    Build and emit the ``oidc_token_issued`` audit pipeline for one
    successful token response.

    Lives next to ``TokenView`` because that's the only consumer, but
    splits the audit pipeline (size-cap + parse → DB lookup →
    optional debug log → signal dispatch) into methods so each can be
    unit-tested in isolation. Each step is wrapped in its own narrow
    ``try`` so a misbehaving component (malformed body, hashed-token
    storage, broken receiver) never poisons the others;
    ``send_robust`` is used so a failing SIEM/audit receiver is logged
    but does not propagate to the OAuth client.
    """

    # ``request`` is ``HttpRequest`` in production (TokenView.post hands
    # it in) but ``Optional`` so parser-only test paths can construct a
    # ``TokenAudit`` without a real request — ``parse_body`` and
    # ``_body_byte_length`` never read it. ``_log_debug`` /
    # ``_dispatch_signal`` do, but those are only reachable after a
    # successful ``_find_token`` lookup.
    request: HttpRequest | None
    body: str | bytes | None
    sender: type[View]
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE
    log: logging.Logger = field(default=logger)

    def emit(self) -> None:
        """Run the full audit pipeline; never raises."""
        payload = self.parse_body()
        if payload is None:
            return
        access_token = payload.get("access_token")
        if not access_token:
            return
        token = self._find_token(access_token)
        if token is None:
            return
        self._log_debug(token, payload)
        self._dispatch_signal(token)

    def parse_body(self) -> dict[str, Any] | None:
        """
        Validate the body length, JSON-parse it, return the dict.

        Returns ``None`` if the body is empty, oversized, non-JSON, or
        not a JSON object — every failure mode the pipeline must
        survive without raising.
        """
        body = self.body
        if not body:
            return None
        body_len = self._body_byte_length(body)
        if body_len is not None and body_len > self.max_body_bytes:
            self.log.warning(
                "OIDC audit: token response body is %d bytes (over %d-byte cap), skipping audit parse",  # noqa: E501
                body_len,
                self.max_body_bytes,
            )
            return None
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            self.log.exception(
                "OIDC audit: token response body is not valid JSON"
            )
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _body_byte_length(body: Any) -> int | None:
        """
        Return the byte length of ``body`` or ``None`` if unmeasurable.

        Comparing against a byte-count (not a code-point count) keeps
        ``str`` and ``bytes`` bodies under the same cap when the
        payload contains multi-byte characters.
        """
        if isinstance(body, str):
            return len(body.encode("utf-8", errors="replace"))
        if hasattr(body, "__len__"):
            return len(body)
        return None

    def _find_token(self, access_token_str: str) -> TokenLike | None:
        """
        Look up the persisted ``AccessToken`` by SHA256 checksum.

        DOT 3.x stores a SHA256 of the raw token in
        ``AccessToken.token_checksum`` (indexed) and persists the
        raw value in the unindexed ``token`` TextField. The
        introspect, revoke and refresh paths in DOT itself all key
        off ``token_checksum`` — going through the same column here
        gives O(1) index lookups on default storage and also works
        on hashed-at-rest deployments where the raw value never
        reaches the ``token`` column.
        """
        import hashlib

        access_token_model = get_access_token_model()
        checksum = hashlib.sha256(access_token_str.encode("utf-8")).hexdigest()
        try:
            return access_token_model.objects.get(token_checksum=checksum)
        except access_token_model.DoesNotExist:
            # The audit pipeline is best-effort — a missing row is
            # not an error worth surfacing to the OAuth client.
            self.log.debug(
                "OIDC audit: access_token not found in DB (checksum miss)"
            )
            return None

    def _log_debug(self, token: TokenLike, payload: dict[str, Any]) -> None:
        """Emit the per-app debug-mode log line, if applicable."""
        if self.request is None:
            return
        app = getattr(token, "application", None)
        if not getattr(app, "debug_mode", False):
            return
        if not self.log.isEnabledFor(logging.INFO):
            return
        # build_oidc_debug_meta reads sanitised fields from request.POST
        # only — it never logs raw tokens or secrets.
        self.log.info(
            "OIDC DEBUG token issued app_id=%s client_id=%s user_id=%s meta=%s",  # noqa: E501
            getattr(app, "id", None),
            getattr(app, "client_id", None),
            getattr(getattr(token, "user", None), "id", None),
            build_oidc_debug_meta(self.request, payload),
        )

    def _dispatch_signal(self, token: TokenLike) -> None:
        """Fan out to ``oidc_token_issued`` receivers, logging failures."""
        if self.request is None:
            return
        audit_body: OIDCAuditBody = {
            "grant_type": self.request.POST.get("grant_type"),
            "scope": self.request.POST.get("scope"),
            "format": classify_token_format(getattr(token, "token", None)),
        }
        # ``dispatch_audit_signal`` wraps ``send_robust`` with the
        # receiver-failure counter so SIEM-forwarder outages surface
        # as a non-zero Prometheus rate per affected signal.
        dispatch_audit_signal(
            oidc_token_issued,
            signal_name="oidc_token_issued",
            sender=self.sender,
            request=self.request,
            token=token,
            body=audit_body,
        )


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens for anyone who meets the
    requirements of the application.

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials

    Why csrf_exempt:
    - this is a machine-to-machine endpoint; authentication happens via OAuth2
      parameters/headers, not via browser cookie sessions.
    - CSRF protection targets browser form submissions with cookies.
      Still, we must NOT log secrets and must not mix cookie auth with token
      issuance.
    """

    # Every OAuth2 / OIDC secret the token endpoint may receive must
    # be marked sensitive so Django's debug-error rendering and any
    # post-mortem error reporter that honours the marker
    # (Sentry, Rollbar) redact it before the body is captured. With
    # ``DEBUG=True`` (operator error) a 500-page would otherwise echo
    # the raw credential in plaintext on the technical 500 page.
    #
    # * ``password``           — RFC 6749 §4.3 Resource Owner Password
    # * ``client_secret``      — RFC 6749 §2.3.1 Client Authentication
    # * ``code``                — RFC 6749 §4.1 single-use code (still
    #                              hot until exchanged)
    # * ``code_verifier``       — RFC 7636 §4.5 PKCE proof-of-possession;
    #                              leaking this together with the code
    #                              defeats PKCE entirely
    # * ``refresh_token``      — RFC 6749 §6 long-lived rotation token
    # * ``assertion``          — RFC 7521 client / RFC 7522 SAML / RFC
    #                              7523 JWT assertion grants (DOT may
    #                              register grant handlers that consume
    #                              this body field)
    @method_decorator(
        sensitive_post_parameters(
            "password",
            "client_secret",
            "code",
            "code_verifier",
            "refresh_token",
            "assertion",
        )
    )
    def post(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        """Issue an OAuth2/OIDC token and emit the audit signal on success."""
        _, headers, body, status = self.create_token_response(request)
        # Access enforcement is handled in the OAuth2 validator before
        # token persistence; here we only emit a safe audit signal.
        if status == HTTPStatus.OK:
            TokenAudit(
                request=request, body=body, sender=self.__class__
            ).emit()

        response = HttpResponse(content=body, status=status)
        for k, v in headers.items():
            response[k] = v
        return response
