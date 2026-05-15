"""
Authorize endpoint: policy-aware ``AuthAuthorizationView``.

Split off from the original single-file ``views.py`` (kept as a thin
re-export shim). Carries the OIDC ``prompt`` / ``max_age`` reauth
gate, the cross-origin POST → GET body promotion, and the global +
per-app access policy enforcement.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.http import HttpRequest, HttpResponseBase, QueryDict
from django.shortcuts import render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.models import get_application_model
from oauth2_provider.views.base import AuthorizationView
from typing_extensions import assert_never

from ._metrics import authorize_denied, policy_rejections
from .security import (
    DEFAULT_POLICY,
    AllowedDecision,
    AppDeny,
    GlobalDeny,
    UserLike,
)
from .utils import app_log

if TYPE_CHECKING:
    from .models import AllianceAuthApplication

logger = logging.getLogger(f"extensions.{__name__}")


class _ForceConsentRequired(Exception):  # noqa: N818
    """
    Sentinel raised from
    :meth:`AuthAuthorizationView.create_authorization_response`
    when ``prompt=consent`` is in the request and DOT is about to
    fast-path past the consent screen.

    OIDC Core 1.0 §3.1.2.1 mandates that ``prompt=consent`` force
    the consent prompt even when the AS would otherwise auto-approve
    (operator's ``skip_authorization=True``, or the user already
    granted consent for the requested scopes). DOT funnels both
    fast paths through ``create_authorization_response(allow=True)``;
    raising this sentinel there propagates out of DOT's
    ``except OAuthToolkitError`` (it only catches OAuthToolkit
    errors) and is caught one frame up in
    :meth:`AuthAuthorizationView.get`, which re-routes to the
    consent-form render path. No suffix ``Error`` because this is a
    control-flow signal, not an error condition — ``noqa: N818``
    silences the naming convention.
    """


@method_decorator(csrf_exempt, name="dispatch")
class AuthAuthorizationView(AuthorizationView):
    """
    OIDC authorization endpoint with global + per-app access policy.

    ``csrf_exempt`` is required to satisfy OIDC Core 1.0 §3.1.2.1
    ("Authorization Servers MUST support the use of the HTTP GET and
    POST methods at the Authorization Endpoint"): an OIDC initial
    authorize POST comes from a third-party client cross-origin, so a
    Django CSRF token is fundamentally impossible. The same-origin
    consent-form POST also flows through this view; CSRF on it is
    redundant with the OAuth ``state`` parameter and the per-client
    ``redirect_uri`` whitelist (which together rule out the
    OAuth-login-CSRF class of attacks). Major OIDC providers
    (Keycloak, Auth0, Okta) all csrf-exempt their authorize endpoints
    for the same reason.

    Anonymous-user redirect to login flows through DOT's
    ``BaseAuthorizationView`` ``LoginRequiredMixin``, which calls
    ``handle_no_permission()`` from inside ``super().dispatch()`` —
    i.e. after our POST→GET promotion has run, so the redirect's
    ``next`` parameter carries the promoted query string. Wrapping
    this view in an additional ``@login_required`` decorator would
    bypass that ordering and bind ``next`` to the original
    (param-less) POST URL, dropping all OIDC parameters across the
    login round-trip.
    """

    template_name = "allianceauth_oidc/authorize.html"

    @staticmethod
    def _promote_post_body_to_query(request: HttpRequest) -> None:
        """
        Promote a cross-origin POST authorize body to a GET-shaped
        request.

        DOT's ``AuthorizationView`` was written for the same-origin
        consent flow only — its ``post()`` runs ``AllowForm``
        validation expecting an ``allow`` field. For a cross-origin
        OIDC initial-request POST (no ``allow``, x-www-form-urlencoded
        body carrying the same parameters a GET would put in the
        query string), copy the body to ``request.GET`` and re-label
        the method so DOT's ``get`` path renders consent / redirects
        identically to the GET case.

        Synchronisation invariants (a regression in any of these
        re-introduces the previously-fixed bugs):

        * ``request.method`` *and* ``request.META["REQUEST_METHOD"]``
          must both flip to ``"GET"``. Downstream middleware
          (request-id, audit, error logging) consults ``META`` rather
          than the Python attribute, so a partial flip leaves the
          request visible as a fabricated POST that the view never
          actually executed as a POST.
        * ``QUERY_STRING`` is updated so any subsequent call to
          ``get_full_path()`` (login redirect, DOT's oauthlib URI
          extraction) reflects the promoted parameters.
        * The POST body is cleared so DOT's ``_extract_params`` (which
          feeds ``request.POST.items()`` into oauthlib as the request
          body) does not surface the same parameters twice — once in
          the URL, once in the body — which oauthlib rejects with
          ``invalid_request: duplicate parameter``.

        A POST that carries the ``allow`` field is the same-origin
        consent submit and is left untouched.
        """
        if request.method != "POST" or "allow" in request.POST:
            return
        promoted = request.POST
        request.GET = promoted
        request.META["QUERY_STRING"] = promoted.urlencode()
        request.POST = QueryDict("", mutable=False)
        request.method = "GET"
        request.META["REQUEST_METHOD"] = "GET"

    def _get_app(self, request: HttpRequest) -> AllianceAuthApplication | None:
        """
        Retrieve the active OAuth2 Application by ``client_id``.

        Disabled applications (``active=False``) intentionally return None so
        the policy gate doesn't render their name into the 403 page; DOT's
        ``AuthorizationView`` then handles the missing-client_id case with
        its generic error response. This keeps the per-tenant denial reason
        consistent regardless of whether the app exists, is disabled, or
        the user simply lacks access.

        Returns the concrete ``AllianceAuthApplication`` rather than DOT's
        ``AbstractApplication`` so the caller's static checks see
        ``debug_mode`` / ``states`` / ``groups`` (and so the app
        satisfies the ``AppLike`` Protocol used by the policy).

        Args:
            request (HttpRequest): The user's HTTP request.

        Returns:
            AllianceAuthApplication | None: Active application, or None.
        """
        client_id = request.GET.get("client_id") or request.POST.get(
            "client_id"
        )
        if not client_id:
            return None
        # prefetch states/groups: AccessPolicy._check_app materialises both
        # via ``list(...)``, which hits the prefetch cache (zero queries)
        # instead of two ``exists()`` round-trips per manager.
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

    @staticmethod
    def _enforce_reauth(
        request: HttpRequest, user: UserLike | None
    ) -> HttpResponseBase | None:
        """
        OIDC Core 1.0 §3.1.2.1 reauthentication gate.

        Returns an HTTP redirect to ``LOGIN_URL`` when the
        authenticated end-user must reauthenticate before the
        authorize request can proceed; returns ``None`` to let the
        normal flow continue.

        Triggers:

        * ``prompt=login`` — RP explicitly demands a fresh
          authentication event. The user is logged out and bounced
          to login with ``next`` pointing back to the authorize
          endpoint. ``prompt=login`` is stripped from the ``next``
          URL so the post-login replay does not retrigger the
          gate; any other ``prompt`` values
          (e.g. ``prompt=consent``) survive the strip.
        * ``max_age=N`` — RP caps the acceptable age (seconds) of
          the End-User's last authentication. When
          ``now - user.last_login > N`` (or ``last_login`` is
          missing entirely), the gate behaves identically to
          ``prompt=login`` except that ``max_age`` is preserved in
          the ``next`` URL: after re-auth ``last_login`` is fresh,
          so the next-iteration check passes naturally.
          Conformance: dropping ``max_age`` from the replay would
          remove the spec-mandated requirement that
          ``auth_time`` be present in the id_token, so it MUST
          survive the round-trip.

        Malformed ``max_age`` (non-integer, negative) is ignored
        rather than treated as ``0`` — never bouncing a user to
        login based on an unparseable, attacker-controlled value.
        """
        prompt_raw = str(request.GET.get("prompt") or "")
        prompt_values = prompt_raw.split()
        prompt_login = "login" in prompt_values
        max_age_expired = AuthAuthorizationView._max_age_expired(request, user)
        if not (prompt_login or max_age_expired):
            return None
        next_url = AuthAuthorizationView._reauth_next_url(
            request, strip_prompt_login=prompt_login
        )
        logout(request)
        return redirect_to_login(next_url)

    @staticmethod
    def _max_age_expired(request: HttpRequest, user: UserLike | None) -> bool:
        """
        Return True when ``max_age`` is present and the End-User's
        authentication is older than the requested cap.

        ``max_age=0`` is the spec's "always reauthenticate"
        sentinel: any non-zero elapsed time exceeds it.
        Malformed values (non-integer or negative) parse to
        ``None`` and short-circuit to False — see
        :meth:`_enforce_reauth` for the security rationale.
        """
        raw = request.GET.get("max_age")
        if raw is None:
            return False
        try:
            max_age = int(raw)
        except (TypeError, ValueError):
            return False
        if max_age < 0:
            return False
        last_login = getattr(user, "last_login", None)
        if last_login is None:
            # Authenticated user without a ``last_login`` row is a
            # corner case (e.g. created-but-never-logged-in service
            # accounts); treating it as "infinitely old" matches
            # the spec's "elapsed time since last authentication"
            # semantics — the elapsed time is undefined, so any
            # finite cap is exceeded.
            return True
        elapsed = (timezone.now() - last_login).total_seconds()
        return elapsed > max_age

    @staticmethod
    def _reauth_next_url(
        request: HttpRequest, *, strip_prompt_login: bool
    ) -> str:
        """
        Compose the ``next`` URL used by the LOGIN_URL redirect.

        Mutates a copy of ``request.GET`` rather than the live
        QueryDict (Django guards live request data against
        accidental edits). When ``strip_prompt_login`` is True,
        the ``"login"`` token is removed from the space-delimited
        ``prompt`` parameter; if it was the only value, the
        parameter is dropped entirely. The path is taken from
        ``request.path`` so the same builder works for both the
        GET and the (post-promotion) POST authorize endpoints.
        """
        query = request.GET.copy()
        if strip_prompt_login and "prompt" in query:
            # ``QueryDict.__getitem__`` is typed as ``str`` in
            # django-stubs but basedpyright reads it through the
            # untyped MultiValueDict baseline; the explicit ``str(...)``
            # cast settles the static-analyser narrowing without
            # changing runtime behaviour — a missing or empty value
            # still produces an empty token list.
            prompt_raw = str(query.get("prompt") or "")
            remaining = [p for p in prompt_raw.split() if p != "login"]
            if remaining:
                query["prompt"] = " ".join(remaining)
            else:
                del query["prompt"]
        encoded = query.urlencode()
        return f"{request.path}?{encoded}" if encoded else request.path

    def create_authorization_response(
        self,
        request: Any,
        scopes: Any,
        credentials: Any,
        allow: Any = True,
    ) -> Any:
        """
        Pre-empt DOT's auto-approval on ``prompt=consent`` requests.

        Both DOT auto-approve paths (``skip_authorization=True`` and
        ``approval_prompt=auto`` + existing-token shortcut) funnel
        through this method on the way to redirecting back to the
        RP with a freshly minted code. We intercept on GET — i.e.
        the initial authorize request, before the consent form has
        been shown — and raise :class:`_ForceConsentRequired` so
        :meth:`get` can re-route to the consent template. Sentinel
        does NOT fire on POST (the user clicking "Allow" on the
        consent form), so the post-consent flow still issues a
        code normally.
        """
        prompts = str(self.request.GET.get("prompt") or "").split()
        if "consent" in prompts and self.request.method == "GET":
            raise _ForceConsentRequired()
        return super().create_authorization_response(
            request, scopes, credentials, allow
        )

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        """
        Run the access policy gate on every request, GET or POST.

        Centralising the check here closes the POST-bypass that arises if the
        gate lives in ``get()``/``post()`` separately.
        """
        # OIDC Core 1.0 §3.1.2.1 mandates POST support at the
        # authorize endpoint. The promotion logic is extracted to a
        # static method so it is unit-testable in isolation (see
        # ``tests/test_authorize.py::TestAuthAuthorizationViewPromotion``).
        self._promote_post_body_to_query(request)

        # Anonymous users go straight to ``super().dispatch()`` so
        # DOT's ``LoginRequiredMixin`` redirects them to ``LOGIN_URL``
        # with ``next`` carrying the (now promoted) query string. The
        # access policy is meaningless for an unauthenticated request
        # — running it would surface ``DenyReason.GLOBAL`` (the
        # global ``access_oidc`` permission gate) and render the 403
        # denied page instead of letting the user log in.
        user: UserLike | None = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False):
            return super().dispatch(request, *args, **kwargs)

        # OIDC Core 1.0 §3.1.2.1 ``prompt=login`` / ``max_age``
        # enforcement. Force re-authentication when the client
        # requested it, regardless of the existing session — runs
        # AFTER ``_promote_post_body_to_query`` so the next-URL we
        # build off ``request.GET`` reflects the canonical OIDC
        # parameters even on the cross-origin POST initial path.
        reauth_response = self._enforce_reauth(request, user)
        if reauth_response is not None:
            return reauth_response

        # IMPORTANT: must run for BOTH GET and POST to prevent POST-bypass.
        # Why in dispatch():
        # - Django OAuth Toolkit AuthorizationView may handle GET/POST
        #   differently.
        # - if checks are only in get()/post(), it's easy to miss a code path.
        app = self._get_app(request)
        decision = DEFAULT_POLICY.decide(user, app)

        # Discriminated union via ``match``: each ``case`` narrows the
        # union to one variant; ``case _`` with ``assert_never`` makes a
        # future fourth variant a type-check error rather than a silent
        # fall-through. ``decision.app`` collapses from
        # ``AppLike | None`` to ``AppLike`` on the ``AppDeny`` branch
        # via the same narrowing, with no runtime ``assert`` required.
        match decision:
            case AllowedDecision():
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

            case GlobalDeny():
                authorize_denied.labels(reason="global").inc()
                # Cross-stage view alongside the legacy authorize-only
                # counter. See ``_metrics.policy_rejections`` for the
                # contract; the two counters intentionally double-emit
                # on this stage so dashboards can migrate without a
                # flag-day cutover.
                policy_rejections.labels(
                    stage="authorize", reason="global"
                ).inc()
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

            case AppDeny():
                authorize_denied.labels(reason="app").inc()
                policy_rejections.labels(stage="authorize", reason="app").inc()
                denied_app = decision.app  # AppLike (non-None)
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

            case _:
                assert_never(decision)

    def get(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        """
        Catch :class:`_ForceConsentRequired` raised by our
        ``create_authorization_response`` override and re-route to
        the consent form.

        DOT's ``AuthorizationView.get`` populates ``self.oauth2_data``
        (the kwargs dict consumed by the consent template) BEFORE
        invoking ``create_authorization_response``, so by the time
        the sentinel propagates back here every piece of context the
        render needs is already attached to ``self``. We simply
        bypass DOT's redirect path and render the consent template
        with the saved kwargs.
        """
        try:
            return super().get(request, *args, **kwargs)
        except _ForceConsentRequired:
            return self.render_to_response(
                self.get_context_data(**self.oauth2_data)
            )
