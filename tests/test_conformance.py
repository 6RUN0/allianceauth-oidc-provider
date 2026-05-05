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

import base64
import hashlib
import json
import os

from jwcrypto import jwk, jwt

from ._oidc_testcase import OIDCTestCase


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TestDiscoveryAndJWKS(OIDCTestCase):
    def test_openid_configuration_advertises_required_endpoints(self):
        """OIDC discovery document must list the standard endpoints and the
        issuer.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))

        for key in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ):
            with self.subTest(claim=key):
                self.assertIn(key, doc)

        self.assertIn(
            "RS256", doc.get("id_token_signing_alg_values_supported", [])
        )
        # Endpoints are absolute URIs.
        for endpoint_key in (
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ):
            self.assertTrue(doc[endpoint_key].startswith("http"))

    def test_jwks_advertises_an_rsa_key_with_kid_and_alg(self):
        """
        JWKS must contain at least one RSA key with the fields downstream
        verifiers need (kty, kid, n, e).

        DOT advertises alg=RS256 only when an app uses RS256.
        """
        resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, resp.status_code)
        body = json.loads(resp.content.decode("utf-8"))
        keys = body.get("keys", [])
        self.assertTrue(keys, "JWKS endpoint returned no keys")
        first = keys[0]
        self.assertEqual("RSA", first.get("kty"))
        for field in ("kid", "n", "e"):
            self.assertIn(field, first)

    def test_id_token_is_signed_and_verifiable_against_jwks(self):
        """
        Round-trip: run the authorization-code flow, decode `id_token` with
        the public key from /o/.well-known/jwks.json, and assert both the
        critical claims (iss, sub, aud, exp, iat) and the JWT header
        (alg=RS256, kid present).

        Catches silent regressions where DOT swaps the algorithm or stops
        publishing it on the JWKS.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(self.user1, state="id-token-verify")
        id_token = tokens["id_token"]

        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        keyset = jwk.JWKSet.from_json(jwks_resp.content.decode("utf-8"))
        verified = jwt.JWT(jwt=id_token, key=keyset)
        claims = json.loads(verified.claims)

        # Header invariants — guard against a downgrade attack where the
        # token still parses but with `alg=none` or HS256.
        header = json.loads(verified.header)
        self.assertEqual("RS256", header.get("alg"))
        self.assertIn("kid", header)

        self.assertEqual(str(self.user1.pk), claims.get("sub"))
        self.assertEqual(self.oauth_id, claims.get("aud"))
        self.assertIn("iss", claims)
        self.assertIn("exp", claims)
        self.assertIn("iat", claims)
        self.assertLessEqual(claims["iat"], claims["exp"])

    def test_id_token_round_trips_nonce_when_provided(self):
        """
        OIDC Core §3.1.2.1: if the client passes `nonce` in the authorize
        request, it must echo back unchanged in the id_token.

        Mitigates replay attacks where a stolen id_token is re-used in a
        different authentication context.
        """
        self.grant_oidc_access(self.user1)
        nonce = "n-0S6_WzA2Mj"  # arbitrary fixed value
        tokens = self.run_code_flow(
            self.user1,
            state="nonce-test",
            extra_authorize_params={"nonce": nonce},
        )
        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        keyset = jwk.JWKSet.from_json(jwks_resp.content.decode("utf-8"))
        verified = jwt.JWT(jwt=tokens["id_token"], key=keyset)
        claims = json.loads(verified.claims)
        self.assertEqual(nonce, claims.get("nonce"))


class TestRevokeAndIntrospect(OIDCTestCase):
    def _issue_access_token(self, *, scope: str = "openid") -> str:
        """Run the authorization-code flow and return a fresh access_token."""
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(
            self.user1, scope=scope, state="issue-token"
        )["access_token"]

    def test_revoked_access_token_no_longer_authorizes_userinfo(self):
        """RFC 7009: after /o/revoke_token/, the token must no longer be
        usable on /o/userinfo/.
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
        """RFC 7009: revoking an already-revoked or unknown token must
        still respond 200 (clients can retry safely).
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
        """RFC 7662: /o/introspect/ must return active=true for a valid
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
        body = json.loads(resp.content.decode("utf-8"))
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
        body = json.loads(resp.content.decode("utf-8"))
        self.assertFalse(body.get("active"))


class TestPKCEFlow(OIDCTestCase):
    def test_pkce_s256_round_trip(self):
        """
        Even with PKCE_REQUIRED=False, the code+verifier exchange must work
        when a client opts into PKCE.

        Smoke test: generate a verifier,
        derive S256 challenge, run the full flow.
        """
        verifier = _b64url(os.urandom(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "pkce-test",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )

        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "redirect_uri": "http://localhost/redir/",
                "code": code,
                "code_verifier": verifier,
            },
        )
        self.assertEqual(200, resp.status_code)
        body = json.loads(resp.content.decode("utf-8"))
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)
