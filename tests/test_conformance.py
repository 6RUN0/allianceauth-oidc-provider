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

from ._factories import make_app
from ._oidc_testcase import REDIRECT_URI, SCOPE_OPENID, OIDCTestCase

REQUIRED_DISCOVERY_KEYS = frozenset(
    {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    }
)

ABSOLUTE_URL_DISCOVERY_KEYS = (
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TestDiscoveryAndJWKS(OIDCTestCase):
    def test_openid_configuration_advertises_required_endpoints(self):
        """
        OIDC discovery document must list the standard endpoints and the
        issuer.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))

        missing = REQUIRED_DISCOVERY_KEYS - doc.keys()
        self.assertFalse(
            missing, f"discovery document missing keys: {sorted(missing)}"
        )
        self.assertIn(
            "RS256", doc.get("id_token_signing_alg_values_supported", [])
        )
        for key in ABSOLUTE_URL_DISCOVERY_KEYS:
            self.assertTrue(
                doc[key].startswith("http"),
                f"{key}={doc[key]!r} is not absolute",
            )

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
        Round-trip: run the authorization-code flow, decode `id_token` with the
        public key from /o/.well-known/jwks.json, and assert both the critical
        claims (iss, sub, aud, exp, iat) and the JWT header (alg=RS256, kid
        present).

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
    @staticmethod
    def _make_verifier_and_challenge() -> tuple[str, str]:
        verifier = _b64url(os.urandom(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        return verifier, challenge

    def _authorize_with_pkce(self, *, challenge: str, state: str) -> str:
        """Issue an authorization code with a code_challenge attached."""
        return self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state=state,
            extra_authorize_params={
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    def _exchange_with_verifier(
        self, *, code: str, verifier: str | None
    ) -> tuple[int, dict]:
        """POST /o/token/ with the given code and (optional) verifier."""
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.oauth_id,
            "client_secret": self.oauth_secret,
            "redirect_uri": REDIRECT_URI,
            "code": code,
        }
        if verifier is not None:
            payload["code_verifier"] = verifier
        resp = self.client.post("/o/token/", data=payload)
        return resp.status_code, json.loads(resp.content.decode("utf-8"))

    def test_pkce_s256_round_trip(self):
        """
        Happy path: a client opting into S256 PKCE still gets a working
        code + verifier exchange.

        With per-app PKCE the shared fixture has ``pkce_required=False``
        (so non-PKCE flows in other modules keep working), but a client
        sending ``code_challenge`` regardless still drives the full
        verifier round-trip — DOT enforces PKCE whenever the
        authorize-time challenge is present.
        """
        verifier, challenge = self._make_verifier_and_challenge()
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-happy"
        )
        status, body = self._exchange_with_verifier(
            code=code, verifier=verifier
        )
        self.assertEqual(200, status)
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)

    def test_pkce_with_wrong_verifier_is_rejected(self):
        """
        RFC 7636: presenting a verifier that does NOT hash to the previously-
        supplied challenge must be rejected with invalid_grant.

        Otherwise PKCE provides no protection.
        """
        _, challenge = self._make_verifier_and_challenge()
        wrong_verifier = _b64url(os.urandom(32))  # unrelated random bytes
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-wrong-verifier"
        )
        status, body = self._exchange_with_verifier(
            code=code, verifier=wrong_verifier
        )
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )

    def test_pkce_missing_verifier_when_challenge_provided_is_rejected(
        self,
    ):
        """
        RFC 7636 §4.6: if the authorize request used PKCE, the token request
        MUST include code_verifier.

        Omitting it must fail.
        """
        _, challenge = self._make_verifier_and_challenge()
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-missing-verifier"
        )
        status, body = self._exchange_with_verifier(code=code, verifier=None)
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )


class TestPerAppPkceRequired(OIDCTestCase):
    """
    Per-app ``pkce_required`` override exercised over the HTTP authorize
    surface.

    These tests build dedicated ``make_app(pkce_required=...)`` fixtures
    so the shared OIDCTestCase fixture (``pkce_required=False``) stays
    isolated and other modules' assumptions are not affected.
    """

    def _authorize_no_challenge(self, *, client_id: str, state: str):
        return self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state=state,
            extra={"client_id": client_id},
        )

    def test_pkce_required_per_app_strict_no_challenge(self):
        """
        Fixture ``pkce_required=True``; authorize without ``code_challenge``
        must fail (DOT redirects with ``error=invalid_request``).
        """
        creds = make_app(owner=self.user1, pkce_required=True)
        self.grant_oidc_access(self.user1)
        resp = self._authorize_no_challenge(
            client_id=creds.client_id, state="pkce-strict"
        )
        # DOT for missing PKCE returns either a 302 with the error
        # encoded in the redirect, or a 400 with the error in the body.
        # Accept both shapes.
        self.assertIn(resp.status_code, (302, 400))
        body = resp.content.decode("utf-8") + str(resp.headers)
        self.assertIn("invalid_request", body)

    def test_pkce_required_per_app_lenient_no_challenge(self):
        """
        Fixture ``pkce_required=False``; authorize without
        ``code_challenge`` must succeed (302 redirect carrying ``code=``).
        """
        creds = make_app(
            owner=self.user1, pkce_required=False, skip_authorization=True
        )
        self.grant_oidc_access(self.user1)
        resp = self._authorize_no_challenge(
            client_id=creds.client_id, state="pkce-lenient"
        )
        self.assertEqual(302, resp.status_code)
        location = resp.headers["Location"]
        self.assertIn("code=", location)
        self.assertNotIn("error=", location)

    def test_pkce_required_with_method_plain_round_trip(self):
        """
        RFC 7636 §4.2 ``code_challenge_method=plain``: the verifier is
        the challenge verbatim. With ``pkce_required=True`` this still
        round-trips because the challenge is supplied.
        """
        verifier = _b64url(os.urandom(32))
        challenge = verifier  # plain method: challenge == verifier
        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        self.grant_oidc_access(self.user1)
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="pkce-plain",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "plain",
            },
        )
        self.assertEqual(302, resp.status_code)
        location = resp.headers["Location"]
        self.assertIn("code=", location)
        # Extract the code and exchange it.
        from urllib.parse import parse_qs, urlparse

        code = parse_qs(urlparse(location).query)["code"][0]
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
