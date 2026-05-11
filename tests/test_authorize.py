"""
Tests for /o/authorize/ — the authorization-code grant entry point.

Covers anonymous redirects to the login page, the global OIDC permission gate,
and per-application state/group access policy as evaluated on the authorize
request itself (i.e. before the user reaches the consent screen). Full code-
exchange flows belong in test_token.py.
"""

from allianceauth.authentication.models import State
from django.conf import settings
from django.shortcuts import resolve_url
from django.test import TestCase

from ._factories import make_app, make_character, make_user
from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    SCOPE_PROFILE,
    OIDCTestCase,
)


class TestAuthorizeGate(OIDCTestCase):
    def test_anonymous_post_is_redirected_to_login_with_next(self):
        """
        Anonymous POST to /o/authorize/ must redirect to the login page with
        a "next" param.

        Only the path is preserved for POST (body params are not).
        """
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "abc",
            "allow": True,
        }

        resp = self.client.post("/o/authorize/", data=data)
        _, path, qs = self.parse_redirect(resp, (302,))

        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)
        self.assertEqual("/o/authorize/", qs["next"][0])

    def test_anonymous_is_redirected_to_login_with_next(self):
        """
        Anonymous GET to /o/authorize/ must redirect to the login page with
        a "next" param.

        Cannot use ``authorize_get_default`` because it calls ``force_login``
        first; this test relies on no session.
        """
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "abc",
            },
        )
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)
        self.assertEqual(resp.wsgi_request.get_full_path(), qs["next"][0])

    def test_no_perms_oauth_u1(self):
        response = self.authorize_get(self.user1)
        self.assertDeniedGlobal(response, self.user1)

    def test_post_no_perms_oauth_u1(self):
        """
        Regression test: POST /o/authorize/ must NOT bypass access
        checks.
        """
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_FULL,
            "state": "post-bypass-test",
            "allow": True,
        }
        response = self.authorize_post(self.user1, data=data)
        self.assertDeniedGlobal(response, self.user1)

    def test_oidc_initial_post_renders_consent(self):
        """
        OIDC Core 1.0 §3.1.2.1: a cross-origin POST authorize from a
        third-party client (no ``allow`` field, parameters in the
        x-www-form-urlencoded body) must reach the consent page just
        like the equivalent GET would.
        """
        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "oidc-post",
            "nonce": "nonce-post",
        }
        response = self.authorize_post(self.user1, data=data)
        self.assertAuthorizePage(response, self.oauth_app, scopes=["openid"])

    def test_oidc_initial_post_with_skip_authorization_redirects(self):
        """
        OIDC Core 1.0 §3.1.2.1 + ``skip_authorization=True``: POST
        authorize without ``allow`` on a pre-approved app skips the
        consent screen and redirects to ``redirect_uri`` carrying the
        authorization ``code`` and the supplied ``state``.
        """
        self.grant_oidc_access(self.user1)
        skip_app = make_app(
            owner=self.user1,
            skip_authorization=True,
            pkce_required=False,
        )
        data = {
            "response_type": "code",
            "client_id": skip_app.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "skipped-consent",
            "nonce": "nonce-skip",
        }
        response = self.authorize_post(self.user1, data=data)
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertIn("code", qs)
        self.assertEqual("skipped-consent", qs["state"][0])

    def test_global_denial_with_valid_client_id_does_not_leak_app_name(self):
        """
        Anti-enumeration: when a logged-in user lacks ``access_oidc`` and hits
        authorize with a *valid* ``client_id``, the global gate runs first and
        the per-app branch never executes.

        Without this guarantee the denied page would render the app name
        (admin-controlled string) into the response, which lets a phisher
        confirm a tenant-display-name → client_id mapping.
        """
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "enum-probe",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedGlobal(response, self.user1)
        self.assertIsNone(response.context["app_name"])
        self.assertNotIn(
            self.oauth_app.name.encode("utf-8"),
            response.content,
            "app name must not appear in body when global gate denies",
        )

    def test_with_perms_oauth_u1_all_scopes(self):
        """Check that all requested scopes are shown when user has access."""
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(self.user1, state="all-scopes")
        self.assertAuthorizePage(
            response, self.oauth_app, ["openid", "email", "profile"]
        )

    def test_with_perms_oauth_u1_email_only(self):
        """Check that only requested scopes are shown when user has access."""
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(
            self.user1, scope="email", state="email-only"
        )
        self.assertAuthorizePage(response, self.oauth_app, ["email"])

    def test_inactive_app_does_not_leak_name_in_denial(self):
        """
        When ``app.active=False``, the policy gate must not render the
        application's name (admin-controlled) in the 403 page.

        The view treats disabled apps as if they didn't exist for client_id
        lookup — DOT then handles the invalid-client_id case with its own
        generic error response, which never mentions the app name.
        """
        self.grant_oidc_access(self.user1)
        self.oauth_app.active = False
        self.oauth_app.save()

        response = self.authorize_get_default(self.user1, state="inactive")

        # Not the authorize/consent page — DOT short-circuits before
        # rendering it. Could be 200 with an error template, 302 to an
        # error page, or 400, depending on the DOT version; the contract
        # is "the app's display name does not appear anywhere in body".
        self.assertNotEqual(
            self.oauth_app.name.encode("utf-8"),
            response.content,
            "Inactive application name must not be rendered in response",
        )
        self.assertNotIn(
            self.oauth_app.name.encode("utf-8"),
            response.content,
            "Inactive application name must not appear in response body",
        )

    def test_with_perms_and_state_oauth_u1(self):
        """Scopes are shown when user has access and matching state."""
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(self.user1, state="state-match")
        self.assertAuthorizePage(
            response, self.oauth_app, ["email", "openid", "profile"]
        )

    # NB: state-mismatch / group-mismatch / neither-match deny scenarios are
    # parametrised in test_token.TestPolicyMatrix; this file keeps the
    # consent-page (allow) cases plus anonymous and global-permission gates.

    # ---------------------------- multi-alt and state-precedence scenarios

    def test_alt_membership_in_member_state_does_not_grant_user_state(self):
        """
        Adversarial multi-alt: user's main has no State affiliation, alt is
        **explicitly** added to ``Member.member_characters``.

        If AA naively used "any owned character is Member ⇒ user is Member",
        this user would gain Member access through the alt. The contract: state
        is decided by main only.
        """
        main_char = make_character("alice-main", self.corp1)
        alt_char = make_character("alice-alt", self.corp2)
        adv_user = make_user(
            "alice-multi-alt", main=main_char, alts=[alt_char]
        )
        # Adversarial step: put the *alt* into Member's member_characters.
        State.objects.get(name="Member").member_characters.add(alt_char)
        adv_user.refresh_from_db()

        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.grant_oidc_access(adv_user)

        response = self.authorize_get_default(
            adv_user, scope=SCOPE_PROFILE, state="alt-state-leak"
        )
        self.assertDeniedApp(response, adv_user, self.oauth_app)

    def test_main_character_state_grants_access_independent_of_alt_alliance(
        self,
    ):
        """
        Positive counterpart: user1's main has Member state, app requires
        Member → access granted regardless of alts.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(
            self.user1, scope=SCOPE_PROFILE, state="main-state-grants"
        )
        self.assertAuthorizePage(
            response, self.oauth_app, ["openid", "profile"]
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


class TestAuthorizeCsrfExemption(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1 mandates POST support at the authorize
    endpoint. The cross-origin caller cannot supply a Django CSRF
    token, so the view must be exempt from ``CsrfViewMiddleware``.

    The default Django test client runs with
    ``enforce_csrf_checks=False``, which silently masks CSRF
    regressions; these tests opt into CSRF enforcement explicitly.
    """

    def test_post_authorize_passes_csrf_middleware(self):
        """
        With ``enforce_csrf_checks=True`` the test client applies
        ``CsrfViewMiddleware``; without ``csrf_exempt`` on the view
        the POST returns ``403`` ahead of any application logic. We
        only assert that the response is not the CSRF rejection,
        leaving downstream rendering / redirect contracts to the
        functional tests above.
        """
        self.grant_oidc_access(self.user1)
        client = self.client_class(enforce_csrf_checks=True)
        client.force_login(self.user1)
        response = client.post(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "csrf-exempt",
                "nonce": "nonce-csrf",
            },
        )
        self.assertNotEqual(
            403,
            response.status_code,
            "POST authorize must not be rejected by CsrfViewMiddleware",
        )


class TestPkceInteractionWithOtherGates(OIDCTestCase):
    """
    Pin the dispatch order between PKCE and the other authorize-gates.

    PKCE is one of several gates around /o/authorize/. These tests
    confirm:

    1. State / group whitelist denial wins over a PKCE check (the
       authorize view runs the policy gate in ``dispatch`` *before*
       DOT inspects the PKCE challenge).
    2. ``active=False`` denial wins over a successful PKCE challenge
       (``is_usable`` runs first; an inactive app cannot issue codes
       even with a perfect PKCE round-trip).
    3. Toggling ``pkce_required`` mid-flow on the admin form does NOT
       affect an already-issued authorization code (the code carries
       its issuance-time PKCE contract through to token-exchange).
    """

    def test_state_group_denial_wins_over_pkce_check(self):
        # App restricted to "Blue" state; user1 is "Member" → denied at
        # the policy stage, not at the PKCE stage.
        creds = make_app(owner=self.user1, pkce_required=True, states=["Blue"])
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="state-vs-pkce",
            extra={"client_id": creds.client_id},
        )
        # ``assertDeniedApp`` checks the rendered denial page (200 with
        # the app name), not a PKCE-related error.
        self.assertDeniedApp(response, self.user1, creds.app)

    def test_active_false_wins_over_pkce_required(self):
        from oauth2_provider.models import get_grant_model

        creds = make_app(owner=self.user1, pkce_required=True, active=False)
        self.grant_oidc_access(self.user1)
        _, challenge = self.make_pkce_pair()
        # Send a perfectly valid PKCE challenge — the active=False gate
        # must still reject the request.
        response = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="active-vs-pkce",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        # ``is_usable=False`` short-circuits before any code is issued.
        # DOT may render the consent page with an error, redirect with
        # an error, or 400 — assert "no code anywhere" both in the
        # response and in the database. The DB check is the strong
        # invariant: a Grant row would mean a usable code reached the
        # storage layer regardless of how the response was rendered.
        body = response.content.decode("utf-8", errors="ignore") + str(
            response.headers
        )
        self.assertNotIn("code=", body)
        Grant = get_grant_model()
        self.assertFalse(
            Grant.objects.filter(application=creds.app).exists(),
            "no Grant row should be persisted for an inactive app",
        )

    def test_admin_toggle_does_not_affect_in_flight_code(self):
        import json
        from urllib.parse import parse_qs, urlparse

        creds = make_app(
            owner=self.user1,
            pkce_required=True,
            skip_authorization=True,
        )
        self.grant_oidc_access(self.user1)

        verifier, challenge = self.make_pkce_pair()

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="race-issue",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(302, resp.status_code)
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]

        # Operator flips the flag to False mid-flight (e.g. via admin).
        # The previously-issued code retains its strict-PKCE contract.
        creds.app.refresh_from_db()
        creds.app.pkce_required = False
        creds.app.save()

        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn("access_token", body)


class TestAuthAuthorizationViewPromotion(TestCase):
    """
    Direct unit tests for the cross-origin POST → GET promotion in
    ``AuthAuthorizationView.dispatch``. Lives at the view level
    rather than the HTTP-client level so we can inspect
    ``request.META`` after promotion — downstream middleware reads
    that mapping, not the ``request.method`` Python attribute, and
    keeping the two in sync is the regression this test pins.
    """

    def test_promote_post_keeps_meta_request_method_in_sync(self) -> None:
        from django.test import RequestFactory

        from allianceauth_oidc.views import AuthAuthorizationView

        factory = RequestFactory()
        request = factory.post(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": "irrelevant",
                "redirect_uri": "https://rp.example/cb",
                "scope": "openid",
            },
        )
        # Sanity: factory wires REQUEST_METHOD == method == "POST".
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.META.get("REQUEST_METHOD"), "POST")

        AuthAuthorizationView._promote_post_body_to_query(request)

        # Python-level attribute and META mapping must agree;
        # middleware (request-id, audit, error logging) reads META.
        self.assertEqual(request.method, "GET")
        self.assertEqual(
            request.META.get("REQUEST_METHOD"),
            "GET",
            (
                "META[REQUEST_METHOD] must be kept in sync with "
                "request.method after the POST→GET promotion, "
                "otherwise downstream middleware sees a desynced "
                "request and records a fabricated POST."
            ),
        )
        # And the OIDC parameters end up in the query string,
        # not duplicated in POST — duplicate-parameter rejection
        # by oauthlib is the original regression.
        self.assertIn("response_type=code", request.META["QUERY_STRING"])
        self.assertEqual(request.POST.urlencode(), "")

    def test_promote_is_a_noop_for_get(self) -> None:
        """GET request must not be touched by the promotion helper."""
        from django.test import RequestFactory

        from allianceauth_oidc.views import AuthAuthorizationView

        factory = RequestFactory()
        request = factory.get(
            "/o/authorize/",
            data={"response_type": "code"},
        )
        AuthAuthorizationView._promote_post_body_to_query(request)
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.META["REQUEST_METHOD"], "GET")

    def test_promote_is_a_noop_when_allow_present(self) -> None:
        """
        Consent-form POST carries an ``allow`` field — that path is
        the same-origin consent flow and must NOT be promoted (it
        would lose the ``allow`` flag and never reach DOT's
        ``AllowForm`` validation).
        """
        from django.test import RequestFactory

        from allianceauth_oidc.views import AuthAuthorizationView

        factory = RequestFactory()
        request = factory.post(
            "/o/authorize/",
            data={"allow": "Authorize", "response_type": "code"},
        )
        AuthAuthorizationView._promote_post_body_to_query(request)
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.META["REQUEST_METHOD"], "POST")
        self.assertEqual(request.POST.get("allow"), "Authorize")

    def test_promote_is_a_noop_for_put(self) -> None:
        """
        Pin ``!=`` against ``<`` on the method-guard.

        ``request.method != "POST"`` is checked with ``!=`` in the
        helper. The GET-only noop test does not distinguish ``!=``
        from ``<`` because ``"GET" < "POST"`` happens to be True
        (same direction as ``!=``). For ``"PUT"`` the two operators
        disagree: ``"PUT" != "POST"`` is True (skip promotion),
        ``"PUT" < "POST"`` is False (the mutant promotes anyway).
        Sending a PUT here pins ``!=`` against the ``<``/``<=``/
        ``is not`` family.
        """
        from django.test import RequestFactory

        from allianceauth_oidc.views import AuthAuthorizationView

        factory = RequestFactory()
        request = factory.put(
            "/o/authorize/",
            data="response_type=code",
            content_type="application/x-www-form-urlencoded",
        )
        AuthAuthorizationView._promote_post_body_to_query(request)
        self.assertEqual(request.method, "PUT")
        self.assertEqual(request.META["REQUEST_METHOD"], "PUT")

    def test_promote_leaves_post_immutable(self) -> None:
        """
        After promotion ``request.POST`` is rebound to a
        ``QueryDict("", mutable=False)`` so downstream code cannot
        accidentally re-insert the parameters it already moved to
        the query string. Flipping ``mutable=False`` to ``True``
        would silently lift the guarantee; a test that mutates the
        post-promotion ``POST`` and observes the change pins it.
        """
        from django.test import RequestFactory

        from allianceauth_oidc.views import AuthAuthorizationView

        factory = RequestFactory()
        request = factory.post(
            "/o/authorize/",
            data={"response_type": "code", "scope": "openid"},
        )
        AuthAuthorizationView._promote_post_body_to_query(request)
        with self.assertRaises(AttributeError):
            request.POST["response_type"] = "tampered"


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
