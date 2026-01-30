import json
import logging
from typing import Any

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View
from oauth2_provider.models import (
    AbstractApplication,
    get_access_token_model,
    get_application_model,
)
from oauth2_provider.signals import app_authorized
from oauth2_provider.views.base import AuthorizationView
from oauth2_provider.views.mixins import OAuthLibMixin

from .security import (
    check_user_global_oidc_access,
    check_user_state_and_groups,
)

log = logging.getLogger(__name__)


@method_decorator(csrf_exempt, name="dispatch")
class TokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens
    for anyone who meets the requirements of the application

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials
    """

    @method_decorator(
        sensitive_post_parameters(
            "password",
            "client_secret",
            "code",
            "refresh_token",
            "assertion",
        )
    )
    def post(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponse:
        url, headers, body, status = self.create_token_response(request)
        # Access enforcement is handled in the OAuth2 validator
        # before token persistence.
        # Here we only emit a safe audit signal (no token strings in logs).
        if status == 200:
            try:
                access_token = json.loads(body).get("access_token")
                if access_token:
                    token = get_access_token_model().objects.get(
                        token=access_token
                    )
                    app_authorized.send(
                        sender=self,
                        request=request,
                        token=token,
                        body={
                            "grant_type": request.POST.get("grant_type"),
                            "scope": request.POST.get("scope"),
                        },
                    )
            except Exception:
                log.exception(
                    "Failed to emit OIDC audit signal for token issuance"
                )

        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class AuthAuthorizationView(AuthorizationView):
    template_name = "allianceauth_oidc/authorize.html"

    def _get_app(self, request: HttpRequest) -> AbstractApplication | None:
        """
        Retrieve the OAuth2 Application object by client_id
        from GET or POST parameters.

        Args:
            request (HttpRequest): The user's HTTP request.

        Returns:
            AbstractApplication | None: Application instance if found,
            otherwise None.
        """
        client_id = request.GET.get("client_id") or request.POST.get(
            "client_id"
        )
        if not client_id:
            return None
        return (
            get_application_model().objects.filter(client_id=client_id).first()
        )

    def _access_denied_response(
        self, request: HttpRequest, reason: str, error_message: str
    ) -> HttpResponseBase:
        return render(
            request,
            "allianceauth_oidc/denied.html",
            context={
                "reason": reason,
                "error_code": f"(403 - {error_message})",
            },
        )

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        # IMPORTANT: must run for BOTH GET and POST to prevent POST-bypass.
        try:
            check_user_global_oidc_access(request.user)
        except PermissionDenied:
            log.warning("OAUTH - %s - global - Access Denied", request.user)
            return self._access_denied_response(
                request,
                "External OAuth Denied",
                "Global Permission Denied",
            )

        app = self._get_app(request)
        if app is not None:
            try:
                check_user_state_and_groups(request.user, app)
            except PermissionDenied:
                log.warning(
                    "OAUTH - %s - %s - Access Denied", request.user, app
                )
                return self._access_denied_response(
                    request,
                    f"{app} Access Denied",
                    "Application Permission Denied",
                )
        return super().dispatch(request, *args, **kwargs)
