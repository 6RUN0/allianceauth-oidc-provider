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
        import hashlib
        import os
        from base64 import urlsafe_b64encode

        creds = make_app(owner=self.user1, pkce_required=True, active=False)
        self.grant_oidc_access(self.user1)
        verifier = (
            urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        )
        challenge = (
            urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
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
        # an error, or 400 — assert "no code anywhere".
        body = response.content.decode("utf-8", errors="ignore") + str(
            response.headers
        )
        self.assertNotIn("code=", body[:2048])

    def test_admin_toggle_does_not_affect_in_flight_code(self):
        import hashlib
        import json
        import os
        from base64 import urlsafe_b64encode
        from urllib.parse import parse_qs, urlparse

        creds = make_app(
            owner=self.user1,
            pkce_required=True,
            skip_authorization=True,
        )
        self.grant_oidc_access(self.user1)

        verifier = (
            urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        )
        challenge = (
            urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )

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

        token_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": verifier,
            },
        )
        self.assertEqual(200, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn("access_token", body)
