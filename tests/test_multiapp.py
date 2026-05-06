"""
Multi-app isolation tests.

Documents the actual cross-app behaviour of django-oauth-toolkit so
upgrades that change it are caught:

- ``/o/token/`` (refresh_token grant): DOT enforces that the
  presenting client owns the refresh token. App B's credentials with
  app A's refresh token are rejected. **This is the only hard
  isolation guarantee** the suite asserts, and it's the most
  important one — a regression here would let any confidential
  client in the system mint access tokens for any other client's
  sessions.

- ``/o/introspect/`` (RFC 7662) and ``/o/revoke_token/`` (RFC 7009):
  DOT authenticates the requesting client but does NOT verify that
  the token was issued to that client. Any confidential client can
  see metadata of any token in the same provider, and revoke any
  token. RFC 7662 leaves this up to the implementation; RFC 7009
  §2.1 actually mandates the check, and DOT does not implement it.
  These tests pin down the *current* behaviour so a future DOT
  change in either direction is visible. If you operate untrusted
  co-tenant confidential clients, add a custom OAuth2Validator
  override that compares ``token.application_id`` to
  ``request.client.id``.
"""

import json

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase


class TestMultiAppIsolation(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Second app belonging to the same owner. Different client_id /
        # client_secret — these are the OAuth client identity boundary.
        self.app_b, self.app_b_id, self.app_b_secret = make_app(
            owner=self.user1, pkce_required=False
        )

    def _issue_token_for_app1(self) -> dict:
        """Run the code-flow against the default app and return tokens."""
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(self.user1, state="multiapp-issue")

    def test_refresh_token_with_wrong_client_id_is_rejected(self):
        """
        OAuth2 refresh_token grant: DOT verifies the presenting client owns the
        refresh token. App B's credentials with app A's refresh token must be
        rejected.

        This is the load-bearing isolation contract — without it any
        confidential client could mint access tokens for any other client's
        sessions.
        """
        body = self._issue_token_for_app1()

        resp = self.refresh_token(
            refresh_token=body["refresh_token"],
            client_id=self.app_b_id,
            client_secret=self.app_b_secret,
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

    def test_introspect_does_not_isolate_between_apps(self):
        """
        Pinned: DOT lets any authenticated confidential client introspect any
        token in the same provider.

        RFC 7662 doesn't mandate per-client isolation; this test documents the
        choice rather than enforces it. Failure means DOT changed behaviour —
        review carefully, it could be a hardening or a regression.
        """
        body = self._issue_token_for_app1()

        resp = self.client.post(
            "/o/introspect/",
            data={
                "token": body["access_token"],
                "client_id": self.app_b_id,
                "client_secret": self.app_b_secret,
            },
        )
        self.assertEqual(200, resp.status_code)
        introspection = json.loads(resp.content.decode("utf-8"))
        self.assertTrue(
            introspection.get("active"),
            "DOT used to treat any authenticated client as authorized "
            "to introspect any token; if this fails, DOT now isolates "
            "per-client and the suite needs to assert the new contract.",
        )
        # The leaked metadata: app B sees app A's user, scope, expiry.
        self.assertEqual(self.user1.username, introspection.get("username"))

    def test_revoke_with_other_app_credentials_succeeds_in_dot(self):
        """
        Pinned: RFC 7009 §2.1 requires the server to verify the token belongs
        to the requesting client; DOT does not.

        Any confidential client can revoke any token in the provider. This test
        pins the current (insecure) DOT behaviour — if it starts failing, DOT
        has tightened revoke and we should celebrate then update the assertion.
        """
        body = self._issue_token_for_app1()
        access_token = body["access_token"]

        revoke_resp = self.client.post(
            "/o/revoke_token/",
            data={
                "token": access_token,
                "client_id": self.app_b_id,
                "client_secret": self.app_b_secret,
            },
        )
        self.assertEqual(200, revoke_resp.status_code)

        # The token is now unusable, even though app B revoked it.
        post_revoke = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {access_token}"},
        )
        self.assertIn(post_revoke.status_code, (401, 403))
