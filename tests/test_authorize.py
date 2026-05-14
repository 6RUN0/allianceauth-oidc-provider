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


class TestAuthorizeMethodRestriction(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.1 — /o/authorize/ accepts ``GET`` and ``POST``.

    Django's ``FormView`` aliases ``PUT`` to ``POST`` via
    ``ProcessFormView.put`` — that is an upstream design choice, not
    a project bug. We pin the orthogonal verbs ``DELETE`` and
    ``PATCH``, which have no FormView handler and MUST yield 405.

    ``force_login`` first because ``LoginRequiredMixin.dispatch``
    runs before Django's method-not-allowed handler in the MRO; an
    anonymous DELETE would short-circuit to 302→login before ever
    reaching the method check.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

    def _assert_allow_header_lists_get_and_post(self, resp) -> None:
        # RFC 9110 §10.2.1: 405 responses MUST carry an Allow header
        # listing the methods the resource supports.
        allow = resp.headers.get("Allow", "").upper()
        self.assertIn("GET", allow)
        self.assertIn("POST", allow)

    def test_delete_returns_405(self) -> None:
        resp = self.client.delete("/o/authorize/")
        self.assertEqual(405, resp.status_code)
        self._assert_allow_header_lists_get_and_post(resp)

    def test_patch_returns_405(self) -> None:
        resp = self.client.patch("/o/authorize/")
        self.assertEqual(405, resp.status_code)
        self._assert_allow_header_lists_get_and_post(resp)

    def test_put_documents_formview_aliasing(self) -> None:
        """
        ``ProcessFormView.put`` delegates to ``post``. PUT is NOT
        rejected with 405; it runs through the same flow as POST.

        This is a Django/FormView contract, not a security gap — but
        pin it so the next person to read the test file does not
        mis-remember "we 405 every non-GET/POST". If a future
        ``http_method_names = ["get", "post"]`` override is added to
        ``AuthAuthorizationView``, this test flips to assert 405.
        """
        resp = self.client.put("/o/authorize/")
        self.assertNotEqual(
            405,
            resp.status_code,
            "FormView aliases PUT to POST — see ProcessFormView.put",
        )
        self.assertLess(resp.status_code, 500)
