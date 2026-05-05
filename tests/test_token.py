"""
Tests for /o/token/ — full code-exchange and refresh flows.

Two related concerns:

1. Policy matrix (state x group x superuser) parametrized via
   ``parameterized.expand`` — replaces 6 hand-written
   ``test_full_chain_*`` methods plus 3 deny variants previously
   scattered across test_authorize.py.
2. Token-policy guards: refusal to exchange or refresh tokens when
   the user no longer matches the app's policy, on redirect_uri
   mismatch, on wrong client_secret, on inactive applications, and
   on refresh-token rotation invalidation.

Userinfo claims live in test_userinfo.py; RP-initiated logout in
test_logout.py; debug-logging leak protection in test_logging.py.
"""

import json

from allianceauth.authentication.models import State
from parameterized import parameterized

from ._oidc_testcase import (
    DEFAULT_EXPIRES_IN,
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    OIDCTestCase,
)

# (name, app_states, app_groups_required, user_groups_match, is_superuser,
#  expect)
#
# - ``app_states``: list of State names the app restricts to. ``[]`` = no
#   state restriction.
# - ``app_groups_required``: True → app requires the test group; user1 may
#   or may not be in that group depending on ``user_groups_match``.
# - ``user_groups_match``: only meaningful when app_groups_required=True.
# - ``is_superuser``: bypasses all restrictions.
# - ``expect``: "allow" runs the full code-flow + token check; "deny" hits
#   /o/authorize/ and asserts the denial page.
#
# user1 has state=Member by default (set up in OIDCTestCase.setUpTestData).
POLICY_MATRIX = [
    # No restrictions — every authenticated user gets a token.
    ("open_app_no_restrictions", [], False, False, False, "allow"),
    # State-only.
    ("state_only_match", ["Member"], False, False, False, "allow"),
    ("state_only_mismatch_denies", ["Blue"], False, False, False, "deny"),
    # Group-only.
    ("group_only_match", [], True, True, False, "allow"),
    ("group_only_mismatch_denies", [], True, False, False, "deny"),
    # Combined: OR semantics — any single match wins.
    (
        "state_match_overrides_no_group",
        ["Member"],
        True,
        False,
        False,
        "allow",
    ),
    (
        "group_match_overrides_wrong_state",
        ["Blue"],
        True,
        True,
        False,
        "allow",
    ),
    ("neither_matches_denies", ["Blue"], True, False, False, "deny"),
    # Superuser bypasses everything, even neither-match.
    ("superuser_bypasses_restrictions", ["Blue"], True, False, True, "allow"),
]


class TestPolicyMatrix(OIDCTestCase):
    """
    Parametrised access-policy matrix exercised end-to-end.

    `parameterized.expand` synthesises individual test methods named
    ``test_policy_matrix_<index>_<scenario>`` so failure messages point at the
    exact row.
    """

    @parameterized.expand(POLICY_MATRIX)
    def test_policy_matrix(
        self,
        name: str,
        app_states: list[str],
        app_groups_required: bool,
        user_groups_match: bool,
        is_superuser: bool,
        expect: str,
    ) -> None:
        for state_name in app_states:
            self.oauth_app.states.add(State.objects.get(name=state_name))
        if app_groups_required:
            self.oauth_app.groups.add(self.test_grp)
            if user_groups_match:
                self.user1.groups.add(self.test_grp)

        if is_superuser:
            self.user1.is_superuser = True
            self.user1.save()
        self.grant_oidc_access(self.user1)

        if expect == "allow":
            self.run_code_flow(
                self.user1,
                state=f"matrix-{name}",
                expected_scope=SCOPE_FULL,
                expected_expires_in=DEFAULT_EXPIRES_IN,
            )
        elif expect == "deny":
            response = self.authorize_get_default(
                self.user1, state=f"matrix-{name}"
            )
            self.assertDeniedApp(response, self.user1, self.oauth_app)
        else:
            self.fail(f"unknown expect={expect!r}")


class TestTokenPolicyGuards(OIDCTestCase):
    """Refusal paths on /o/token/ and /o/authorize/ when context shifts."""

    def _grant_user1_with_test_grp(self) -> None:
        self.oauth_app.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

    def test_token_exchange_denied_if_group_removed_after_code_issued(self):
        """
        If the user stops matching policy (group/state) after code issuance,
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
        """
        Refresh token exchange must enforce policy and deny if access was
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
        """
        If the user loses the global OIDC permission after receiving a
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
        """
        If redirect_uri at /o/token/ doesn't match the one used at
        /o/authorize/, token exchange must fail.
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
        """
        Confidential clients must not exchange a code with an invalid
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
        access_token after ``active=False``.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(self.user1, state="inactive-after-issue")
        refresh = body["refresh_token"]

        self.oauth_app.active = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        resp = self.refresh_token(
            refresh_token=refresh, expected_status=(400, 401, 403)
        )
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_grant",
                "invalid_client",
                "invalid_request",
            },
        )

    def test_old_refresh_token_invalidated_after_rotation(self):
        """
        ``ROTATE_REFRESH_TOKEN=True`` (test settings): once a refresh is
        consumed and a new one is issued, the old refresh must NOT be reusable.

        Regression for token-rotation contract.
        """
        self.grant_oidc_access(self.user1)
        first = self.run_code_flow(self.user1, state="rotation-1")
        old_refresh = first["refresh_token"]

        # First rotation: old refresh → fresh access + (rotated) refresh.
        rotated = self.refresh_token(refresh_token=old_refresh)
        rotated_body = json.loads(rotated.content.decode("utf-8"))
        self.assertIn("access_token", rotated_body)
        new_refresh = rotated_body["refresh_token"]
        self.assertNotEqual(
            old_refresh,
            new_refresh,
            "ROTATE_REFRESH_TOKEN expected to mint a new refresh value",
        )

        # Reusing the old refresh after rotation must fail.
        resp = self.refresh_token(
            refresh_token=old_refresh,
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp, expected_error={"invalid_grant", "invalid_request"}
        )

    def test_token_response_omits_id_token_when_scope_lacks_openid(self):
        """
        DOT only emits an ``id_token`` when the scope contains ``openid``.

        OAuth-only flows must skip id_token entirely.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(
            self.user1,
            scope="email",
            state="no-openid-scope",
            expect_id_token=False,
            expected_scope="email",
        )
        self.assertIn("access_token", body)

    def test_inactive_app_cannot_issue_code(self):
        """
        ``AllianceAuthApplication.active=False`` must make the app unusable
        — no code redirect to redirect_uri.
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
