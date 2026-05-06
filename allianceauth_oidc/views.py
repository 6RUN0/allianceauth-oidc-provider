"""HTTP views: policy-aware AuthorizationView and audit-emitting TokenView."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Final

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View
from oauth2_provider.models import (
    AbstractApplication,
    get_access_token_model,
    get_application_model,
)
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.mixins import OAuthLibMixin

from .security import DEFAULT_POLICY, DenyReason
from .signals import OIDCAuditBody, oidc_token_issued
from .utils import app_log, build_oidc_debug_meta

logger = logging.getLogger(f"extensions.{__name__}")


# Defence-in-depth cap on the body we'll JSON-parse. A correctly
# behaving DOT response is ~1KB; this leaves three orders of magnitude
# of headroom while preventing a misconfigured upstream from feeding
# an unbounded payload to json.loads.
_DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE: Final[int] = 64 * 1024


@dataclass
class TokenAudit:
    """
    Build and emit the ``oidc_token_issued`` audit pipeline for one
    successful token response.

    Lives next to ``TokenView`` because that's the only consumer, but
    splits the five distinct steps (size-cap → parse → DB lookup →
    optional debug log → signal dispatch) into methods so each can be
    unit-tested in isolation. Each step is wrapped in its own narrow
    ``try`` so a misbehaving component (malformed body, hashed-token
    storage, broken receiver) never poisons the others;
    ``send_robust`` is used so a failing SIEM/audit receiver is logged
    but does not propagate to the OAuth client.
    """

    request: HttpRequest
    body: Any  # str | bytes | None — DOT returns whatever oauthlib hands back
    sender: type
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

    def _find_token(self, access_token_str: str) -> object | None:
        """Look up the persisted ``AccessToken`` by raw token value."""
        access_token_model = get_access_token_model()
        try:
            return access_token_model.objects.get(token=access_token_str)
        except access_token_model.DoesNotExist:
            # Hashed-token storage configurations don't expose the raw
            # token in the response body (it's already hashed at
            # rest), so this lookup misses. Fall back to a debug-level
            # log; the operator can plug a custom audit hook in
            # deployments that use such storage.
            self.log.debug(
                "OIDC audit: access_token not found in DB (hashed-token storage?)"  # noqa: E501
            )
            return None

    def _log_debug(self, token: object, payload: dict[str, Any]) -> None:
        """Emit the per-app debug-mode log line, if applicable."""
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

    def _dispatch_signal(self, token: object) -> None:
        """Fan out to ``oidc_token_issued`` receivers, logging failures."""
        # send_robust returns [(receiver, response_or_exception), ...]
        # without propagating; one bad receiver can't break the others
        # or token issuance.
        audit_body: OIDCAuditBody = {
            "grant_type": self.request.POST.get("grant_type"),
            "scope": self.request.POST.get("scope"),
        }
        for receiver, response_or_exc in oidc_token_issued.send_robust(
            sender=self.sender,
            request=self.request,
            token=token,
            body=audit_body,
        ):
            # ``send_robust`` itself only catches ``Exception``, but
            # matching on ``BaseException`` here keeps the branch
            # correct for future subclasses (e.g. 3.11+
            # ``ExceptionGroup``) without relying on implementation
            # details of Django's signal layer.
            if isinstance(response_or_exc, BaseException):
                self.log.error(
                    "OIDC audit receiver %r failed",
                    receiver,
                    exc_info=response_or_exc,
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

    @method_decorator(sensitive_post_parameters("password"))
    def post(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        """Issue an OAuth2/OIDC token and emit the audit signal on success."""
        _, headers, body, status = self.create_token_response(request)
        # Access enforcement is handled in the OAuth2 validator before
        # token persistence; here we only emit a safe audit signal.
        if status == 200:
            TokenAudit(
                request=request, body=body, sender=self.__class__
            ).emit()

        response = HttpResponse(content=body, status=status)
        for k, v in headers.items():
            response[k] = v
        return response


@method_decorator(login_required, name="dispatch")
class AuthAuthorizationView(AuthorizationView):
    """OIDC authorization endpoint with global + per-app access policy."""

    template_name = "allianceauth_oidc/authorize.html"

    def _get_app(self, request: HttpRequest) -> AbstractApplication | None:
        """
        Retrieve the active OAuth2 Application by ``client_id``.

        Disabled applications (``active=False``) intentionally return None so
        the policy gate doesn't render their name into the 403 page; DOT's
        ``AuthorizationView`` then handles the missing-client_id case with
        its generic error response. This keeps the per-tenant denial reason
        consistent regardless of whether the app exists, is disabled, or
        the user simply lacks access.

        Args:
            request (HttpRequest): The user's HTTP request.

        Returns:
            AbstractApplication | None: Active application, or None.
        """
        client_id = request.GET.get("client_id") or request.POST.get(
            "client_id"
        )
        if not client_id:
            return None
        # prefetch states/groups: check_user_state_and_groups() does
        # `app_states.exists()` + `app_states.filter(...).exists()` (and
        # the same for groups), which is 3-4 queries per authorize without
        # prefetching. With prefetch the related sets are loaded once and
        # the per-request DB cost drops to a single multi-join query.
        return (
            get_application_model()
            .objects.filter(client_id=client_id, active=True)
            .prefetch_related("states", "groups")
            .first()
        )

    def _access_denied_response(
        self,
        request: HttpRequest,
        *,
        username: str,
        error_message: str,
        app_name: str | None = None,
    ) -> HttpResponseBase:
        """
        Render the 403 denied page.

        Values are passed to the template as separate context keys so the
        template can format them under Django's auto-escape — no f-string
        composition in Python keeps `app_name` (admin-controlled) from
        becoming an XSS vector if a future template change introduces a
        ``|safe`` filter.
        """
        return render(
            request,
            "allianceauth_oidc/denied.html",
            context={
                "username": username,
                "app_name": app_name,
                "error_code": f"(403 - {error_message})",
            },
            status=403,
        )

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        """
        Run the access policy gate on every request, GET or POST.

        Centralising the check here closes the POST-bypass that arises if the
        gate lives in ``get()``/``post()`` separately.
        """
        # IMPORTANT: must run for BOTH GET and POST to prevent POST-bypass.
        # Why in dispatch():
        # - Django OAuth Toolkit AuthorizationView may handle GET/POST
        #   differently.
        # - if checks are only in get()/post(), it's easy to miss a code path.
        user = getattr(request, "user", None)
        app = self._get_app(request)
        decision = DEFAULT_POLICY.decide(user, app)

        if decision.allowed:
            app_log(
                logger,
                decision.app,
                "OIDC ALLOWED: user=%s app=%s path=%s method=%s",
                user,
                decision.app,
                getattr(request, "path", None),
                getattr(request, "method", None),
            )
            return super().dispatch(request, *args, **kwargs)

        if decision.deny_reason is DenyReason.GLOBAL:
            logger.warning(
                "OIDC DENIED: global access user=%s path=%s method=%s",
                user,
                getattr(request, "path", None),
                getattr(request, "method", None),
            )
            return self._access_denied_response(
                request,
                username=str(user),
                error_message=_("User not allowed global OIDC access"),
            )

        # DenyReason.APP — decision.app is non-None when reason is APP.
        denied_app = decision.app
        logger.warning(
            "OIDC DENIED: app restrictions user=%s app=%s client_id=%s path=%s method=%s",  # noqa: E501
            user,
            denied_app,
            getattr(denied_app, "client_id", None),
            getattr(request, "path", None),
            getattr(request, "method", None),
        )
        return self._access_denied_response(
            request,
            username=str(user),
            app_name=str(denied_app),
            error_message=_("User not allowed for this application"),
        )
