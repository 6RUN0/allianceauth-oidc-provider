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

from ._factories import make_character, make_user
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
        Anonymous POST to /o/authorize/ must redirect to the login page with a
        "next" param.

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
        Anonymous GET to /o/authorize/ must redirect to the login page with a
        "next" param.

        Cannot use ``authorize_get_default`` because it
        calls ``force_login`` first; this test relies on no session.
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
        """Regression test: POST /o/authorize/ must NOT bypass access checks."""
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
        """Adversarial multi-alt: user's main has no State affiliation, alt is
        **explicitly** added to ``Member.member_characters``. If AA naively
        used "any owned character is Member ⇒ user is Member", this user
        would gain Member access through the alt. The contract: state is
        decided by main only.
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
        """Positive counterpart: user1's main has Member state, app requires
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
