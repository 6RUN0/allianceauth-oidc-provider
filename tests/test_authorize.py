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

from ._oidc_testcase import OIDCTestCase


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
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "abc",
            "allow": True,
        }

        resp = self.client.post("/o/authorize/", data=data)
        _, path, qs = self.parse_redirect(resp, (302,))

        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)

        actual_next = qs["next"][0]
        self.assertEqual("/o/authorize/", actual_next)

    def test_anonymous_is_redirected_to_login_with_next(self):
        """Anonymous GET to /o/authorize/ must redirect to the login page with
        a "next" param.
        """
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "abc",
        }

        resp = self.client.get("/o/authorize/", data=params)
        _, path, qs = self.parse_redirect(resp, (302,))
        self.assertEqual(resolve_url(settings.LOGIN_URL), path)
        self.assertIn("next", qs)
        expected_next = resp.wsgi_request.get_full_path()
        actual_next = qs["next"][0]
        self.assertEqual(expected_next, actual_next)

    def test_no_perms_oauth_u1(self):
        response = self.authorize_get(self.user1)
        self.assertDeniedGlobal(response, self.user1)

    def test_post_no_perms_oauth_u1(self):
        """Regression test: POST /o/authorize/ must NOT bypass access checks."""
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "post-bypass-test",
            "allow": True,
        }
        response = self.authorize_post(self.user1, data=data)
        self.assertDeniedGlobal(response, self.user1)

    def test_with_perms_oauth_u1_all_scopes(self):
        """Check that all requested scopes are shown when user has access."""
        self.grant_oidc_access(self.user1)
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(
            response, self.oauth_app, ["openid", "email", "profile"]
        )

    def test_with_perms_oauth_u1_email_only(self):
        """Check that only requested scopes are shown when user has access."""
        self.grant_oidc_access(self.user1)
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(response, self.oauth_app, ["email"])

    def test_with_perms_and_state_oauth_u1(self):
        """Check that scopes are shown when user has access and correct
        state.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "asdfghhjkl",
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertAuthorizePage(
            response, self.oauth_app, ["email", "openid", "profile"]
        )

    def test_authorize_denies_when_app_state_does_not_match_user(self):
        """User has the OIDC permission but app requires a state the user
        doesn't have → 403 denied page.
        """
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "wrong-state",
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)

    def test_authorize_denies_when_app_group_does_not_match_user(self):
        """User has the OIDC permission and a group, but app's required group
        is different → 403 denied page.
        """
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "wrong-group",
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)

    def test_authorize_denies_when_neither_state_nor_group_matches(self):
        """When the app requires both a state AND a group, and the user matches
        neither, the authorize gate denies.
        """
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "neither-matches",
            "allow": True,
        }
        response = self.authorize_get(self.user1, params=params)
        self.assertDeniedApp(response, self.user1, self.oauth_app)
