"""
Tests for /o/token/ — full code-exchange and refresh flows.

The class covers two related concerns:

1. Successful authorization-code → token → refresh chains under various
   combinations of state/group access policy and superuser bypass.
2. Token-policy guards: refusal to exchange or refresh tokens when the
   user no longer matches the app's policy, on redirect_uri mismatch,
   on wrong client_secret, and on inactive applications.

Userinfo claims live in test_userinfo.py; RP-initiated logout in
test_logout.py; debug-logging leak protection in test_logging.py.
"""

import json

from allianceauth.authentication.models import State

from ._oidc_testcase import OIDCTestCase


class TestCodeFlowAndTokenPolicy(OIDCTestCase):
    def _issue_code_user1_with_group_access(self) -> str:
        self.oauth_app.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "policy-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        return code

    # ---------------------------------------------------------------- code-flow

    def test_full_chain_u1_with_perms_and_state(self):
        """Authorization-code flow succeeds when user matches app's required
        state.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_wrong_state_and_group(self):
        """Group match grants access even when app's required state does not
        match the user's state.
        """
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_group_and_state(self):
        """Both state and group match — straightforward success."""
        self.oauth_app.groups.add(self.test_grp)
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_group(self):
        """App requires a group but no state — group match alone grants
        access.
        """
        self.oauth_app.groups.add(self.test_grp)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_group"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_perms_and_wrong_group_and_state(self):
        """State match grants access even when app's required group does not
        match the user's group.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.user_permissions.add(self.access_oauth)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_perms_and_wrong_group_and_state"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    def test_full_chain_u1_with_su(self):
        """Superusers bypass state/group restrictions entirely."""
        # Apply a state restriction the user does NOT match — superuser still
        # gets through.
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.is_superuser = True
        self.user1.save()
        self.user1.refresh_from_db()
        state = "test_full_chain_u1_with_su"
        scopes = "openid profile email"
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scopes,
            "state": state,
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        response = self.exchange_code_for_token(
            code=code, state=state, redirect_uri="http://localhost/redir/"
        )
        self.assertTokenResponse(
            response, expected_scope=scopes, expected_expires_in=60
        )

    # -------------------------------------------------------------- token policy

    def test_token_exchange_denied_if_group_removed_after_code_issued(self):
        """If the user stops matching policy (group/state) after code issuance,
        /o/token/ must fail with invalid_grant.
        """
        code = self._issue_code_user1_with_group_access()

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri="http://localhost/redir/",
            expected_status=400,
        )
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_group_removed(self):
        """Refresh token exchange must enforce policy and deny if access was
        removed.
        """
        code = self._issue_code_user1_with_group_access()

        token_resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        body = self.assertTokenResponse(
            token_resp,
            expected_scope="openid profile email",
            expected_expires_in=60,
        )
        refresh = body["refresh_token"]

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_global_permission_removed(self):
        """If the user loses the global OIDC permission after receiving a
        refresh_token, refresh must fail with invalid_grant.
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "perm-removed-refresh",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        token_resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        body = self.assertTokenResponse(token_resp)
        refresh = body["refresh_token"]

        self.user1.user_permissions.remove(self.access_oauth)
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_token_exchange_denied_if_redirect_uri_mismatch(self):
        """If redirect_uri used in /o/token/ doesn't match the one used in
        /o/authorize/, token exchange must fail (typically invalid_grant).
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "redir-mismatch",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/other/",
            expected_status=400,
        )

        body = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn(body.get("error"), {"invalid_grant", "invalid_request"})

    def test_token_exchange_denied_if_client_secret_invalid(self):
        """Confidential clients must not exchange a code with an invalid
        client_secret.
        """
        self.grant_oidc_access(self.user1)

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "bad-secret",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            client_secret="WRONG_SECRET",  # nosec B106
            expected_status=(400, 401),
        )
        body = json.loads(resp.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn(
            body.get("error"),
            {"invalid_client", "invalid_grant", "invalid_request"},
        )

    def test_inactive_app_cannot_issue_code(self):
        """
        AllianceAuthApplication.active=False must make the app unusable.

        It must not issue a code redirect to redirect_uri.
        """
        self.grant_oidc_access(self.user1)

        self.oauth_app.active = False
        self.oauth_app.save()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "inactive-app",
            "allow": True,
        }
        resp = self.authorize_post(self.user1, data=data)

        if resp.status_code == 302:
            loc, _, qs = self.parse_redirect(resp, (302,))
            self.assertTrue(loc.startswith("http://localhost/redir/"))
            self.assertNotIn("code", qs)
            self.assertIn("error", qs)
            self.assertTrue(qs["error"][0])
        else:
            self.assertNotEqual(302, resp.status_code)
