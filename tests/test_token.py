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

from allianceauth.authentication.models import State

from ._oidc_testcase import (
    DEFAULT_EXPIRES_IN,
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    OIDCTestCase,
)


class TestCodeFlowAndTokenPolicy(OIDCTestCase):
    def _grant_user1_with_test_grp(self) -> None:
        """Common setup: grant OIDC perm, add user1 + app to test_grp."""
        self.oauth_app.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

    # -------------------------------------------------------- code-flow happy paths

    def test_full_chain_u1_with_perms_and_state(self):
        """Authorization-code flow succeeds when user matches app's required
        state.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.grant_oidc_access(self.user1)
        self.run_code_flow(
            self.user1,
            state="full-chain-state",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    def test_full_chain_u1_with_perms_and_wrong_state_and_group(self):
        """Group match grants access even when app's required state does not
        match the user's state.
        """
        self.oauth_app.states.add(State.objects.get(name="Guest"))
        self._grant_user1_with_test_grp()
        self.run_code_flow(
            self.user1,
            state="full-chain-wrong-state-right-group",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    def test_full_chain_u1_with_perms_and_group_and_state(self):
        """Both state and group match — straightforward success."""
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self._grant_user1_with_test_grp()
        self.run_code_flow(
            self.user1,
            state="full-chain-state-and-group",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    def test_full_chain_u1_with_perms_and_group(self):
        """App requires a group but no state — group match grants access."""
        self._grant_user1_with_test_grp()
        self.run_code_flow(
            self.user1,
            state="full-chain-group-only",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    def test_full_chain_u1_with_perms_and_wrong_group_and_state(self):
        """State match grants access even when app's required group does not
        match the user's group.
        """
        self.oauth_app.states.add(State.objects.get(name="Member"))
        self.oauth_app.groups.add(self.test_grp_2)
        self.user1.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.run_code_flow(
            self.user1,
            state="full-chain-right-state-wrong-group",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    def test_full_chain_u1_with_su(self):
        """Superusers bypass state/group restrictions entirely."""
        # State the user does NOT match — superuser still gets through.
        self.oauth_app.states.add(State.objects.get(name="Blue"))
        self.user1.is_superuser = True
        self.user1.save()
        self.user1.refresh_from_db()
        self.run_code_flow(
            self.user1,
            state="full-chain-su-bypass",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )

    # -------------------------------------------------------------- token policy

    def test_token_exchange_denied_if_group_removed_after_code_issued(self):
        """If the user stops matching policy (group/state) after code issuance,
        /o/token/ must fail with invalid_grant.
        """
        self._grant_user1_with_test_grp()
        code = self.authorize_to_code(self.user1, state="policy-test")

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_group_removed(self):
        """Refresh token exchange must enforce policy and deny if access was
        removed.
        """
        self._grant_user1_with_test_grp()
        body = self.run_code_flow(
            self.user1,
            state="refresh-policy-test",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
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
        body = self.run_code_flow(self.user1, state="perm-removed-refresh")
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
        code = self.authorize_to_code(self.user1, state="redir-mismatch")

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/other/",
            expected_status=400,
        )
        self.assertOAuthError(
            resp, expected_error={"invalid_grant", "invalid_request"}
        )

    def test_token_exchange_denied_if_client_secret_invalid(self):
        """Confidential clients must not exchange a code with an invalid
        client_secret.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(
            self.user1, scope=SCOPE_OPENID, state="bad-secret"
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            client_secret="WRONG_SECRET",  # nosec B106
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_client",
                "invalid_grant",
                "invalid_request",
            },
        )

    def test_refresh_token_denied_when_app_becomes_inactive(self):
        """
        A refresh_token minted while the app was active must NOT issue a new
        access_token after the app is flipped to active=False.

        Hardens the gap exposed by AllianceAuthApplication.is_usable(): without
        this guard, deactivating an app would not stop already issued sessions.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(self.user1, state="inactive-after-issue")
        refresh = body["refresh_token"]

        # Flip the app inactive and try to refresh.
        self.oauth_app.active = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        resp = self.refresh_token(
            refresh_token=refresh, expected_status=(400, 401, 403)
        )
        # DOT or our validator may surface this as invalid_grant or
        # invalid_client; either is correct, but it must NOT succeed.
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_grant",
                "invalid_client",
                "invalid_request",
            },
        )

    def test_token_response_omits_id_token_when_scope_lacks_openid(self):
        """
        DOT only emits an `id_token` when the scope contains `openid`.

        For
        OAuth-only flows (scope=`email` or any non-openid set), the token
        response must skip id_token entirely.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(
            self.user1,
            scope="email",
            state="no-openid-scope",
            expect_id_token=False,
            expected_scope="email",
        )
        # access_token still present (OAuth-only flow remains valid).
        self.assertIn("access_token", body)

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
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_FULL,
            "state": "inactive-app",
            "allow": True,
        }
        resp = self.authorize_post(self.user1, data=data)

        if resp.status_code == 302:
            loc, _, qs = self.parse_redirect(resp, (302,))
            self.assertTrue(loc.startswith(REDIRECT_URI))
            self.assertNotIn("code", qs)
            self.assertIn("error", qs)
            self.assertTrue(qs["error"][0])
        else:
            self.assertNotEqual(302, resp.status_code)
