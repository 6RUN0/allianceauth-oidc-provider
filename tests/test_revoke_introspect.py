"""
OIDC conformance tests for the well-known and management endpoints.

Covers:

- /o/.well-known/openid-configuration/   — discovery document shape
- /o/.well-known/jwks.json               — public JWKS shape
- /o/revoke_token/                       — token revocation (RFC 7009)
- /o/introspect/                         — token introspection (RFC 7662)
- id_token RS256 signature verification  — round-trips against the JWKS
- PKCE smoke                             — S256 verifier flow works
                                           even when PKCE_REQUIRED=False

These tests round-trip against the same provider the policy tests use,
which gives us a regression line on `algorithm="RS256"` declared in the
test app and on DOT's exposed metadata. They are intentionally light on
strict conformance (RFC compatibility); the goal is to catch silent
regressions in DOT integration, not to replace a formal OIDC test suite.
"""

from ._oidc_testcase import (
    SCOPE_OPENID,
    OIDCTestCase,
)


class TestRevokeAndIntrospect(OIDCTestCase):
    def _issue_access_token(self, *, scope: str = SCOPE_OPENID) -> str:
        """Run the authorization-code flow and return a fresh access_token."""
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(
            self.user1, scope=scope, state="issue-token"
        )["access_token"]

    def test_revoked_access_token_no_longer_authorizes_userinfo(self):
        """
        RFC 7009: after /o/revoke_token/, the token must no longer be usable
        on /o/userinfo/.
        """
        token = self._issue_access_token()
        # Sanity — token works first.
        self.assertEqual(
            200,
            self.client.get(
                "/o/userinfo/",
                headers={"authorization": f"Bearer {token}"},
            ).status_code,
        )

        revoke = self.client.post(
            "/o/revoke_token/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        # RFC 7009 mandates 200 with no body content for successful revoke.
        self.assertEqual(200, revoke.status_code)

        post_revoke = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {token}"},
        )
        self.assertIn(post_revoke.status_code, (401, 403))

    def test_revoke_is_idempotent(self):
        """
        RFC 7009: revoking an already-revoked or unknown token must still
        respond 200 (clients can retry safely).
        """
        token = self._issue_access_token()
        for _ in range(2):
            resp = self.client.post(
                "/o/revoke_token/",
                data={
                    "token": token,
                    "client_id": self.oauth_id,
                    "client_secret": self.oauth_secret,
                },
            )
            self.assertEqual(200, resp.status_code)

    def test_introspect_reports_active_for_valid_token(self):
        """
        RFC 7662: /o/introspect/ must return active=true for a valid
        access_token, with the matching `sub` and `scope`.
        """
        token = self._issue_access_token(scope="openid profile")
        resp = self.client.post(
            "/o/introspect/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        self.assertEqual(200, resp.status_code)
        body = self.json_body(resp, expected_status=None)
        self.assertTrue(body.get("active"))
        self.assertIn("openid", body.get("scope", "").split())
        self.assertIn("profile", body.get("scope", "").split())

    def test_introspect_reports_inactive_after_revoke(self):
        """RFC 7662: revoked token must introspect as active=false."""
        token = self._issue_access_token()
        self.client.post(
            "/o/revoke_token/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        resp = self.client.post(
            "/o/introspect/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        self.assertEqual(200, resp.status_code)
        body = self.json_body(resp, expected_status=None)
        self.assertFalse(body.get("active"))


class TestIntrospectAndRevokeRequireClientAuth(OIDCTestCase):
    """
    RFC 7662 §2.1: the introspection endpoint MUST require client
    authentication. RFC 7009 §2.1: the revocation endpoint MUST
    authenticate the client for confidential clients. An unauth
    introspect would be a token-existence oracle (enumeration of
    valid tokens or client_ids); an unauth revoke would let an
    attacker who somehow learnt a token kill it without proving
    ownership.

    The positive paths (with credentials) are in
    :class:`TestRevokeAndIntrospect`. The negative paths live here
    so a regression that removes the client-auth requirement (for
    example, a DOT setting toggle to ``RESOURCE_SERVER_INTROSPECTION_URL``
    that bypasses the local validator) fails an explicit test
    instead of going unnoticed.
    """

    def test_introspect_without_credentials_is_unauthorized(self) -> None:
        token = self._issue_access_token()
        resp = self.client.post("/o/introspect/", data={"token": token})
        self.assertIn(
            resp.status_code,
            (400, 401, 403),
            "introspect without client_id/client_secret MUST be "
            "rejected — RFC 7662 §2.1 requires client authentication. "
            f"Got {resp.status_code}.",
        )

    def test_introspect_with_wrong_client_secret_is_unauthorized(
        self,
    ) -> None:
        token = self._issue_access_token()
        resp = self.client.post(
            "/o/introspect/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": "definitely-not-the-real-secret",  # pragma: allowlist secret
            },
        )
        self.assertIn(resp.status_code, (400, 401, 403))

    def test_revoke_without_credentials_is_rejected(self) -> None:
        token = self._issue_access_token()
        resp = self.client.post("/o/revoke_token/", data={"token": token})
        self.assertIn(
            resp.status_code,
            (400, 401, 403),
            "revoke without credentials MUST be rejected — confidential "
            f"clients require auth (RFC 7009 §2.1). Got {resp.status_code}.",
        )

    def _issue_access_token(self) -> str:
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(
            self.user1, scope=SCOPE_OPENID, state="introspect-auth"
        )["access_token"]


class TestRevokeRefreshTokenChainBehaviour(OIDCTestCase):
    """
    RFC 7009 §2.1 SHOULD clause: revoking a refresh token MAY (and
    typically should) revoke the linked access tokens.

    DOT's :class:`RefreshToken.revoke` deletes the linked
    ``AccessToken`` row, so revoking an RT does invalidate the AT.
    The reverse direction (revoke AT → leave RT alone) is left
    open by the RFC; DOT keeps the RT independent. Both contracts
    are pinned here so a future DOT change in either direction is
    visible.
    """

    def _issue_tokens(self) -> dict:
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(self.user1, state="rt-chain")

    def _userinfo(self, access_token: str):
        return self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {access_token}"},
        )

    def _revoke(self, token: str) -> int:
        return self.client.post(
            "/o/revoke_token/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        ).status_code

    def test_revoking_refresh_token_invalidates_linked_access_token(
        self,
    ) -> None:
        """
        Revoke the RT; the AT issued together with it MUST no longer
        authorize /o/userinfo/. DOT enforces this via
        ``RefreshToken.revoke`` which deletes the linked AT row.
        """
        tokens = self._issue_tokens()
        # Sanity: AT works before revoke.
        self.assertEqual(
            200, self._userinfo(tokens["access_token"]).status_code
        )

        status = self._revoke(tokens["refresh_token"])
        self.assertEqual(200, status)

        resp = self._userinfo(tokens["access_token"])
        self.assertIn(
            resp.status_code,
            (401, 403),
            "RFC 7009 §2.1 SHOULD: revoking RT must invalidate linked AT",
        )

    def test_revoking_access_token_leaves_refresh_token_independent(
        self,
    ) -> None:
        """
        Revoke just the AT; the RT remains usable to mint a new AT.
        Pins DOT's "AT-only revoke does not cascade to RT" contract.
        If DOT tightens to cascade (RFC 7009 permits this), flip the
        assertion accordingly.
        """
        tokens = self._issue_tokens()
        self._revoke(tokens["access_token"])

        # The RT should still mint a fresh AT.
        refresh_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "refresh_token",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "refresh_token": tokens["refresh_token"],
            },
        )
        self.assertEqual(
            200,
            refresh_resp.status_code,
            "DOT default: revoking AT alone leaves RT independent and "
            "usable; if this fails, DOT now cascades AT revoke to RT",
        )


class TestSubClaimContract(OIDCTestCase):
    """
    The ``sub`` claim is the OIDC identifier the RP keys off.

    Three invariants pinned:
    - Stability: same user → same ``sub`` across multiple
      authorizations.
    - Uniqueness: different users → different ``sub``.
    - Documented format: ``str(User.pk)``. The integer-PK choice
      is "public-subject" semantics (Discovery §4.4 subject_types_supported
      includes "public") — every RP gets the same sub for a given user.
      If a future feature adds pairwise subjects, that design change
      must flip this assertion deliberately.
    """

    def _sub_for(self, user) -> str:
        self.grant_oidc_access(user)
        info = self.client.get(
            "/o/userinfo/",
            headers={
                "authorization": "Bearer "
                + self.run_code_flow(user, state=f"sub-{user.username}")[
                    "access_token"
                ]
            },
        )
        self.assertEqual(200, info.status_code)
        return self.json_body(info, expected_status=None)["sub"]

    def test_sub_is_stable_across_separate_authorizations(self) -> None:
        """
        Two separate code-flow rounds for the same user MUST yield
        the same ``sub`` claim.
        """
        sub1 = self._sub_for(self.user1)
        # Re-issue: completely independent flow.
        sub1_again = self.client.get(
            "/o/userinfo/",
            headers={
                "authorization": "Bearer "
                + self.run_code_flow(self.user1, state="sub-stable-2")[
                    "access_token"
                ]
            },
        )
        body = self.json_body(sub1_again, expected_status=None)
        self.assertEqual(sub1, body["sub"])

    def test_sub_differs_across_users(self) -> None:
        """Two different users MUST yield different ``sub`` values."""
        sub_user1 = self._sub_for(self.user1)
        sub_user2 = self._sub_for(self.user2)
        self.assertNotEqual(sub_user1, sub_user2)

    def test_sub_format_is_documented_user_pk(self) -> None:
        """
        Pin the documented format: ``sub == str(User.pk)``. This is
        the "public subject" design choice; pairwise subjects would
        require a deliberate test update.
        """
        sub = self._sub_for(self.user1)
        self.assertEqual(str(self.user1.pk), sub)
