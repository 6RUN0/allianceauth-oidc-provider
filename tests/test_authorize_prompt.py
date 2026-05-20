"""
Tests for /o/authorize/ — the authorization-code grant entry point.

Covers anonymous redirects to the login page, the global OIDC permission gate,
and per-application state/group access policy as evaluated on the authorize
request itself (i.e. before the user reaches the consent screen). Full code-
exchange flows belong in test_token.py.
"""

from django.conf import settings
from django.shortcuts import resolve_url

from ._factories import make_app
from ._jwt_helpers import forge_unsigned_jwt, split_jwt
from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_OPENID,
    OIDCTestCase,
)


class TestAuthorizePromptNoneAuthenticated(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1: with ``prompt=none``, the AS MUST NOT
    display authentication or consent UI. For an authenticated user
    on an app with ``skip_authorization=True`` (the configuration the
    conformance suite drives), DOT auto-approves and redirects back
    to ``redirect_uri`` carrying the authorization ``code`` and the
    supplied ``state``. Pin this so a future override of ``dispatch``
    or the consent-skip logic does not silently regress.

    Limitation: the spec also requires returning an
    ``interaction_required`` / ``consent_required`` error redirect
    when the user is logged in but the client is NOT pre-approved
    (``skip_authorization=False`` and no prior grant). DOT renders
    the consent UI in that case instead of erroring out — a real
    spec gap that the conformance basic-cert plan does not exercise
    (the suite's seeded client uses ``skip_authorization=True``).
    Documented in tests/conformance/README.md and tracked
    separately; not pinned here.
    """

    def test_prompt_none_skip_authorization_redirects_with_code(self):
        self.grant_oidc_access(self.user1)
        skip_app = make_app(
            owner=self.user1,
            skip_authorization=True,
            pkce_required=False,
        )
        self.client.force_login(self.user1)
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": skip_app.client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "prompt-none-auth",
                "nonce": "nonce-auth",
                "prompt": "none",
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertIn("code", qs)
        self.assertEqual(["prompt-none-auth"], qs.get("state"))
        self.assertNotIn("error", qs)

    def test_prompt_none_consent_required_for_unapproved_client(self):
        """
        OIDC Core 1.0 §3.1.2.1 / §3.1.2.6: when ``prompt=none`` is
        sent and the client is NOT pre-approved
        (``skip_authorization=False``, no prior grant), the AS MUST
        return ``error=consent_required`` instead of rendering the
        consent UI. ``validate_silent_authorization`` returns False
        for non-skip-auth clients, oauthlib raises ``ConsentRequired``,
        DOT translates that into a 302 to ``redirect_uri`` carrying
        the error code and the supplied ``state``.
        """
        self.grant_oidc_access(self.user1)
        creds = make_app(
            owner=self.user1,
            skip_authorization=False,
            pkce_required=False,
        )
        self.client.force_login(self.user1)
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": creds.client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "prompt-none-needs-consent",
                "nonce": "nonce-needs-consent",
                "prompt": "none",
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertEqual(["consent_required"], qs.get("error"))
        self.assertEqual(["prompt-none-needs-consent"], qs.get("state"))


class TestAuthorizePromptNoneAnonymous(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.6: when ``prompt=none`` is sent and the
    end-user is not authenticated, the authorization server MUST
    redirect to ``redirect_uri`` with ``error=login_required``
    instead of displaying a login or consent UI. The behaviour is
    inherited from DOT's
    ``BaseAuthorizationView.handle_no_permission``; this test pins
    it down so a future override here does not silently regress to
    the generic ``LOGIN_URL`` redirect.
    """

    def test_anonymous_prompt_none_redirects_with_login_required(self):
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "prompt-none-anon",
                "nonce": "nonce-anon",
                "prompt": "none",
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(
            loc.startswith(REDIRECT_URI),
            f"redirect must point at registered redirect_uri, got {loc!r}",
        )
        self.assertEqual(["login_required"], qs.get("error"))
        self.assertEqual(["prompt-none-anon"], qs.get("state"))


class TestValidateSilentAuthorizationTrustedClient(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.4 — ``prompt=none`` succeeds only via
    operator-declared trust (``skip_authorization=True``).

    A prior implementation attempted a "prior-AT proves prior consent"
    branch, but oauthlib does not propagate ``request.user`` to the
    validate-authorization-request callsite (verified at
    ``oauth2_provider/oauth2_backends.py``), so the branch was dead
    in production while passing under synthetic ``SimpleNamespace``
    request stubs — the canonical test-theatre footgun. The N-2
    removal collapses the function to the honest contract: only
    operator-declared trust grants silent consent. Non-trusted SPAs
    must accept ``error=consent_required`` and prompt the user for
    an interactive authorize round-trip.
    """

    def test_skip_authorization_short_circuits_to_true(self) -> None:
        """
        Regression: the legacy ``skip_authorization=True`` path must
        remain a pure short-circuit. This is the path the
        conformance basic-cert suite exercises.
        """
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        user = self.users[0]
        skip_app = make_app(
            owner=user, skip_authorization=True, pkce_required=False
        ).app
        from types import SimpleNamespace

        request = SimpleNamespace(client=skip_app, user=user, scopes=[])
        validator = AllianceAuthOAuth2Validator()
        self.assertTrue(validator.validate_silent_authorization(request))


class TestPromptLoginEnforcement(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1 ``prompt=login`` — when an authenticated
    user reaches the authorize endpoint with ``prompt=login`` in the
    request, the AS MUST force re-authentication. Implemented as
    "logout + redirect to LOGIN_URL with next pointing back to the
    authorize endpoint, but with ``prompt=login`` stripped from the
    next URL so the post-login round-trip does not re-trigger
    indefinitely".
    """

    def test_authenticated_user_with_prompt_login_redirects_to_login(
        self,
    ) -> None:
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "prompt-login-test",
                "prompt": "login",
            },
        )
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)
        self.assertIn("/o/authorize/", qs["next"][0])

    def test_next_url_strips_prompt_login_to_prevent_infinite_loop(
        self,
    ) -> None:
        """
        After re-authentication the user lands on the authorize
        endpoint via ``next``. If ``next`` still carried
        ``prompt=login``, the dispatch gate would immediately
        bounce them to login again — an infinite redirect loop.
        Stripping the ``login`` token from ``prompt`` (and preserving
        any other prompt values) breaks that loop.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "loop-guard",
                "prompt": "login",
            },
        )
        _, _, qs = self.parse_redirect(resp, (302,))
        next_url = qs["next"][0]
        self.assertNotIn("prompt=login", next_url)

    def test_next_url_preserves_other_oidc_params(self) -> None:
        """
        Stripping ``prompt=login`` must not collateral-damage
        ``client_id`` / ``state`` / ``response_type`` / ``scope``,
        otherwise the post-login authorize replay fails with
        ``invalid_request``.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "preserve-test",
                "prompt": "login",
            },
        )
        _, _, qs = self.parse_redirect(resp, (302,))
        next_url = qs["next"][0]
        self.assertIn(f"client_id={self.oauth_id}", next_url)
        self.assertIn("response_type=code", next_url)
        self.assertIn("state=preserve-test", next_url)

    def test_prompt_login_combined_with_other_prompts_preserves_them(
        self,
    ) -> None:
        """
        ``prompt`` is a space-delimited multi-value parameter.
        ``prompt=login consent`` after stripping ``login`` must
        leave ``prompt=consent`` intact — both for spec
        correctness and so a future ``prompt=consent`` handler can
        rely on the value surviving the redirect.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "multi-prompt",
                "prompt": "login consent",
            },
        )
        _, _, qs = self.parse_redirect(resp, (302,))
        next_url = qs["next"][0]
        self.assertIn("prompt=consent", next_url)
        self.assertNotIn("login+consent", next_url)
        self.assertNotIn("login%20consent", next_url)


class TestMaxAgeEnforcement(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1 ``max_age`` — the AS MUST force
    re-authentication when the elapsed time since the End-User's
    last authentication exceeds the value of ``max_age`` (in
    seconds). The source of truth for "last authentication" is
    ``User.last_login``, set by Django on every successful login.
    """

    def test_max_age_within_window_proceeds(self) -> None:
        """
        A fresh ``force_login`` sets ``last_login`` to now; a
        ``max_age=3600`` (one hour) request must NOT redirect to
        login. The exact downstream response is either 200 (consent
        page) or 302 to the RP redirect_uri; what matters here is
        that the response is NOT a redirect to ``LOGIN_URL``.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "max-age-fresh",
                "max_age": "3600",
            },
        )
        if resp.status_code == 302:
            from urllib.parse import urlparse

            loc = resp.headers["Location"]
            self.assertNotEqual(
                resolve_url(settings.LOGIN_URL),
                urlparse(loc).path,
                f"unexpected redirect to login: {loc}",
            )

    def test_max_age_expired_redirects_to_login(self) -> None:
        """
        Backdate ``last_login`` by one hour, request with
        ``max_age=300`` (5 minutes). Elapsed time (~3600s) exceeds
        the cap (300s) → the AS MUST force re-authentication →
        redirect to ``LOGIN_URL``.
        """
        from datetime import timedelta

        from django.utils import timezone

        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        # ``force_login`` sets ``last_login=now``; backdate it after
        # the fact so the request looks like "user authenticated an
        # hour ago, session still valid".
        self.user1.last_login = timezone.now() - timedelta(hours=1)
        self.user1.save()

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "max-age-expired",
                "max_age": "300",
            },
        )
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        # ``max_age`` survives in next: after re-login,
        # last_login is fresh, so the next-iteration check
        # passes and the user proceeds. Stripping max_age would
        # weaken conformance (the spec requires auth_time in the
        # id_token when max_age is requested).
        self.assertIn("max_age=300", qs["next"][0])

    def test_max_age_zero_always_redirects_to_login(self) -> None:
        """
        ``max_age=0`` is the spec's "always reauthenticate"
        sentinel — even a user who logged in this very second
        must re-authenticate before the AS can issue a token.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "max-age-zero",
                "max_age": "0",
            },
        )
        _, path, _ = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)

    def test_max_age_invalid_value_is_ignored(self) -> None:
        """
        ``max_age=notanumber`` is malformed per the spec. The AS
        SHOULD reject malformed authorize parameters with
        ``invalid_request``; absent that, the safest practical
        choice is to ignore the parameter and proceed — never
        bouncing a user to login based on an unparseable input
        attacker-controlled value.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "max-age-bogus",
                "max_age": "notanumber",
            },
        )
        if resp.status_code == 302:
            from urllib.parse import urlparse

            loc = resp.headers["Location"]
            self.assertNotEqual(
                resolve_url(settings.LOGIN_URL),
                urlparse(loc).path,
                f"unexpected redirect to login on malformed max_age: {loc}",
            )


class TestPromptConsentEnforcement(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1 ``prompt=consent`` enforcement.

    The AS MUST prompt the End-User for consent before issuing a
    code, even when:

    1. The Application has ``skip_authorization=True`` (operator
       trust marker — normally bypasses the consent screen).
    2. The user already granted consent (a non-expired token
       covers the requested scopes — DOT's
       ``approval_prompt=auto`` fast path).

    Both bypasses are suppressed by an override on
    ``create_authorization_response`` raising a sentinel
    exception that ``AuthAuthorizationView.get`` catches and
    converts into a consent-form render. The post-submit
    ``allow=true`` POST is unaffected (sentinel only fires on the
    initial GET path), so the user's "Allow" click continues to
    issue a code normally.
    """

    def test_prompt_consent_with_skip_authorization_renders_consent_form(
        self,
    ) -> None:
        creds = make_app(
            owner=self.user1, skip_authorization=True, pkce_required=False
        )
        self.grant_oidc_access(self.user1)

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="consent-skip-auth",
            extra={"client_id": creds.client_id, "prompt": "consent"},
        )
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, "allianceauth_oidc/authorize.html")

    def test_prompt_consent_with_prior_token_renders_consent_form(
        self,
    ) -> None:
        """
        Pre-existing access token covering the requested scopes
        normally trips DOT's ``approval_prompt=auto`` short-circuit.
        ``prompt=consent`` must override that and force the
        consent screen anyway.
        """
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import get_access_token_model

        self.grant_oidc_access(self.user1)
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="prior-consent-token",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope=SCOPE_OPENID,
        )

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="consent-prior-token",
            extra={"prompt": "consent"},
        )
        self.assertEqual(200, resp.status_code)
        self.assertTemplateUsed(resp, "allianceauth_oidc/authorize.html")

    def test_post_allow_after_consent_form_completes_normally(self) -> None:
        """
        Regression — once the user clicks "Allow" on the consent
        form, the POST (``allow=true``) must NOT re-trigger the
        sentinel and must issue a code redirect. Sentinel fires
        only on GET; the consent-form submit is POST.
        """
        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "consent-allow",
            "prompt": "consent",
            "allow": True,
        }
        resp = self.authorize_post(self.user1, data=data)
        _, path, qs = self.parse_redirect(resp, (302,))
        # Redirect target is the RP's redirect_uri, not the login URL —
        # the consent flow completed.
        self.assertEqual("/redir/", path)
        self.assertIn("code", qs)

    def test_no_prompt_consent_with_skip_authorization_still_auto_approves(
        self,
    ) -> None:
        """
        Regression — without ``prompt=consent``, an app marked
        ``skip_authorization=True`` must continue to auto-approve.
        The override only fires on the explicit ``prompt=consent``
        opt-in.
        """
        creds = make_app(
            owner=self.user1, skip_authorization=True, pkce_required=False
        )
        self.grant_oidc_access(self.user1)

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="no-consent-skip-auth",
            extra={"client_id": creds.client_id},
        )
        # Auto-approve redirects to the RP's redirect_uri with a code.
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual("/redir/", path)
        self.assertIn("code", qs)


class TestIdTokenHintAuthorizeBinding(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.6 — when ``id_token_hint`` identifies an
    end-user different from the one authenticated in the current
    session, the AS SHOULD return ``login_required`` (or otherwise
    re-prompt).

    Current state of the upstream stack:

    * ``OAuth2Validator.validate_user_match`` is a stub that
      unconditionally returns ``True`` (DOT carries a ``# TODO``
      pointing at oauthlib §556 and OIDC Core's id_token_hint
      section). The hint is therefore *advisory only* — DOT will
      issue a code bound to the authenticated session user even if
      the hint names a different ``sub``.

    The first test documents the gap so a future fix in DOT
    surfaces here (the assertion flips from "code issued" to
    "login_required redirect"). The second test pins the
    **session-binding** safety net: even though the hint is
    ignored, the code is bound to the session user — never to the
    hinted user — so subject confusion cannot leak across users
    through this path.
    """

    def _forge_unsigned_hint_for_user(self, user_pk: object) -> str:
        """Build an ``alg=none`` JWT carrying ``sub=user_pk``."""
        return forge_unsigned_jwt(
            {"sub": str(user_pk), "iss": "https://hint.example/"}
        )

    def test_authorize_with_mismatched_hint_currently_proceeds(self) -> None:
        """
        documents-gap: pass an ``id_token_hint`` whose ``sub`` points
        at user2 while the session is logged in as user1. DOT's stub
        ``validate_user_match`` accepts the request and issues a
        code as the *session* user. When DOT implements §3.1.2.6,
        the expected outcome is a ``login_required`` error redirect;
        flip the assertion below at that point.
        """
        self.grant_oidc_access(self.user1)
        hint = self._forge_unsigned_hint_for_user(self.user2.pk)
        skip_app = make_app(
            owner=self.user1, skip_authorization=True, pkce_required=False
        )
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": skip_app.client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "hint-mismatch",
                "id_token_hint": hint,
            },
        )
        # Current behaviour: code issued, redirect to RP — hint
        # ignored. Spec-strict behaviour: 302 to redirect_uri with
        # ``error=login_required``. Either branch must NOT 5xx.
        self.assertNotEqual(500, resp.status_code)
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual("/redir/", path)
        if "error" in qs:
            # Future-state: DOT honours §3.1.2.6.
            self.assertIn(qs["error"][0], ("login_required",))
        else:
            # Current-state: the hint is silently ignored.
            self.assertIn("code", qs)

    def test_code_is_bound_to_session_user_not_hint(self) -> None:
        """
        Safety-net pin: regardless of DOT's hint-validation policy,
        the code MUST be redeemable as the *session* user. A future
        regression that bound the code to the hint's ``sub`` would
        let an attacker who steals a logged-in cookie + crafts a
        hint silently impersonate the hinted user.
        """
        self.grant_oidc_access(self.user1)
        self.grant_oidc_access(self.user2)
        skip_app = make_app(
            owner=self.user1, skip_authorization=True, pkce_required=False
        )
        hint = self._forge_unsigned_hint_for_user(self.user2.pk)
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": skip_app.client_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "state": "hint-binding-check",
                "id_token_hint": hint,
            },
        )
        _, _, qs = self.parse_redirect(resp, (302,))
        if "error" in qs:
            self.skipTest(
                "DOT now rejects mismatched id_token_hint — gap closed"
            )
        code = qs["code"][0]
        token_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": skip_app.client_id,
                "client_secret": skip_app.client_secret,
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
        )
        self.assertEqual(200, token_resp.status_code, token_resp.content)
        body = self.json_body(token_resp, expected_status=None)
        # id_token payload — unverified, only need ``sub``.
        _, claims = split_jwt(body["id_token"])
        self.assertEqual(
            str(self.user1.pk),
            claims.get("sub"),
            "code/id_token MUST be bound to session user, never to "
            "the id_token_hint sub",
        )
        self.assertNotEqual(str(self.user2.pk), claims.get("sub"))


class TestOfflineAccessScopeSemantics(OIDCTestCase):
    """
    OIDC Core 1.0 §11 — ``offline_access`` scope semantics.

    The spec contract:

    * Requesting ``scope=openid offline_access`` is the documented
      way for an RP to ask for a refresh_token.
    * The OP MUST ensure the end-user is aware of the offline
      grant — either by rendering a consent screen for the scope,
      or by having pre-registered consent (``skip_authorization``
      with explicit operator opt-in to the offline grant).
    * If ``skip_authorization=True`` and ``prompt=consent`` is
      absent, the OP MUST NOT honour the offline grant — i.e. it
      must omit ``refresh_token`` from the response.

    Current state of the upstream stack:

    * DOT's default behaviour is to issue ``refresh_token`` for
      every ``authorization_code`` grant whose client is
      ``CONFIDENTIAL`` and ``ROTATE_REFRESH_TOKEN`` is on (the
      project default). The ``offline_access`` scope is **not**
      special-cased; it's treated as a regular scope and either
      accepted or rejected by the ``scopes_supported`` list.
    * Test settings (``tests/test_settingsAA4.py``) declare
      ``SCOPES = {"openid", "email", "profile"}`` — i.e.
      ``offline_access`` is NOT advertised in
      ``scopes_supported``.

    Pinned contracts (current behaviour, documents-gap with respect
    to §11):

    1. The ``offline_access`` scope is **not** in
       ``scopes_supported`` — RPs that try to request it cannot
       discover the capability.
    2. ``refresh_token`` is issued **regardless** of whether
       ``offline_access`` is in the request — the scope name is
       informational here, not a gate.

    When the project implements §11 properly, the assertions flip:
    (1) becomes ``assertIn("offline_access", scopes)``; (2) splits
    into "with offline_access → refresh_token issued" and "without
    offline_access on skip_authorization=True → refresh_token
    omitted".
    """

    def test_offline_access_not_advertised_in_scopes_supported(self) -> None:
        """
        documents-gap: discovery does not advertise ``offline_access``
        in ``scopes_supported``. RPs that follow OIDC §11 cannot
        discover the capability and will fall back to whatever
        refresh-token behaviour the OP exposes by default.
        """
        scopes = self.discovery().get("scopes_supported") or []
        self.assertNotIn(
            "offline_access",
            scopes,
            "project implemented OIDC §11 offline_access advert — "
            "flip this test to ``assertIn`` and extend the second "
            "test to split on the scope's presence.",
        )

    def test_refresh_token_issued_regardless_of_offline_access(self) -> None:
        """
        documents-gap: refresh_token is issued for any confidential
        authorization_code grant; ``offline_access`` in the scope
        request changes nothing today.

        Pins both branches in one test: without the scope the
        response carries refresh_token; with the scope the response
        also carries refresh_token AND the scope echoed back does
        NOT include ``offline_access`` (it's filtered out as
        unsupported).
        """
        self.grant_oidc_access(self.user1)

        # 1) Baseline — no offline_access in request.
        body = self.run_code_flow(
            self.user1, scope=SCOPE_OPENID, state="oa-baseline"
        )
        self.assertIn("refresh_token", body)

        # 2) Request offline_access. DOT either rejects with
        # invalid_scope OR accepts but drops the unsupported scope.
        # Both outcomes are spec-compliant if §11 is not
        # implemented; the regression we guard against is "scope
        # accepted AND refresh-token semantics change". The
        # ``run_code_flow`` helper raises if status != 200 so we
        # use the lower-level path to handle both branches.
        self.client.force_login(self.user1)
        resp = self.client.post(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid offline_access",
                "state": "oa-requested",
                "allow": True,
            },
        )
        if resp.status_code != 302:
            # DOT rejected the scope outright — nothing more to
            # check; the §11 gap is documented by test 1.
            self.skipTest(
                "DOT rejects offline_access pre-authorize — "
                "behaviour pinned by scopes_supported test"
            )
        _, _, qs = self.parse_redirect(resp, (302,))
        if "error" in qs:
            # Same as above — rejected; test 1 covers the gap.
            self.skipTest(
                "DOT rejects offline_access at authorize — "
                "behaviour pinned by scopes_supported test"
            )
        # Accepted path: code issued, exchange it and assert the
        # echoed scope does NOT carry offline_access (DOT filtered
        # it out as unsupported) and refresh_token is still issued.

        code = qs["code"][0]
        token_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
        )
        self.assertEqual(200, token_resp.status_code, token_resp.content)
        token_body = self.json_body(token_resp, expected_status=None)
        self.assertIn("refresh_token", token_body)
        echoed_scope = (token_body.get("scope") or "").split()
        self.assertNotIn(
            "offline_access",
            echoed_scope,
            "DOT now echoes offline_access in the token scope — "
            "extend this test to assert §11 consent semantics.",
        )
