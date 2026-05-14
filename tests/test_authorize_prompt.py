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


class TestValidateSilentAuthorizationPriorConsent(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.4 — ``prompt=none`` MUST succeed when the
    end-user has already granted consent for the requested scopes,
    even if the client is NOT marked ``skip_authorization=True``.

    The prior implementation returned ``True`` only on the
    ``skip_authorization`` path, breaking the canonical
    silent-refresh-in-iframe pattern for normal apps the user had
    already approved. A non-expired ``AccessToken`` covering the
    requested scopes is the proof-of-prior-consent we accept.
    """

    @classmethod
    def setUpTestData(cls) -> None:  # type: ignore[override]
        super().setUpTestData()
        # ``make_app`` returns ``AppCredentials`` (NamedTuple); the
        # persisted model is on ``.app``. Use the model directly so
        # ``AccessToken.application`` FK accepts it.
        cls.app = make_app(
            owner=cls.users[0],
            skip_authorization=False,
            pkce_required=False,
        ).app

    def _build_request(self, *, user, scopes):
        """Minimal oauthlib-shaped request stand-in for the validator."""
        from types import SimpleNamespace

        return SimpleNamespace(client=self.app, user=user, scopes=list(scopes))

    def _issue_access_token(self, *, user, scope: str, ttl_seconds: int):
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import get_access_token_model

        AccessToken = get_access_token_model()
        return AccessToken.objects.create(
            user=user,
            application=self.app,
            token=f"silent-test-{user.pk}-{scope.replace(' ', '_')}",
            expires=timezone.now() + timedelta(seconds=ttl_seconds),
            scope=scope,
        )

    def test_returns_true_for_active_token_covering_all_scopes(self) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        user = self.users[0]
        self._issue_access_token(
            user=user, scope="openid profile", ttl_seconds=3600
        )
        request = self._build_request(user=user, scopes=["openid", "profile"])
        validator = AllianceAuthOAuth2Validator()
        self.assertTrue(validator.validate_silent_authorization(request))

    def test_returns_false_for_expired_token(self) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        user = self.users[0]
        self._issue_access_token(
            user=user, scope="openid profile", ttl_seconds=-60
        )
        request = self._build_request(user=user, scopes=["openid", "profile"])
        validator = AllianceAuthOAuth2Validator()
        self.assertFalse(validator.validate_silent_authorization(request))

    def test_returns_false_when_token_scope_does_not_cover_request(
        self,
    ) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        user = self.users[0]
        self._issue_access_token(user=user, scope="openid", ttl_seconds=3600)
        # Request asks for ``profile`` too — not covered, no silent.
        request = self._build_request(user=user, scopes=["openid", "profile"])
        validator = AllianceAuthOAuth2Validator()
        self.assertFalse(validator.validate_silent_authorization(request))

    def test_returns_false_when_no_token_exists(self) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        user = self.users[0]
        request = self._build_request(user=user, scopes=["openid"])
        validator = AllianceAuthOAuth2Validator()
        self.assertFalse(validator.validate_silent_authorization(request))

    def test_skip_authorization_still_short_circuits_to_true(self) -> None:
        """
        Regression: the legacy ``skip_authorization=True`` path must
        remain a pure short-circuit — no token lookup required, no
        per-user state can flip it to ``False``. This is the path the
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
