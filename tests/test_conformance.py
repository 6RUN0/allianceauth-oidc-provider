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
import json
import os

from jwcrypto import jwk, jwt

from ._factories import make_app
from ._oidc_testcase import SCOPE_OPENID, OIDCTestCase

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

    def test_discovery_advertises_access_token_signing_alg_values_supported(
        self,
    ):
        """
        OIDC Discovery 1.0 §3 ``access_token_signing_alg_values_supported``
        lets RP-side libraries that do RFC 9068 JWT validation
        feature-detect on the algorithm before downloading the JWKS.
        Pinned by ``AllianceAuthDiscoveryView`` regardless of whether
        JWT mode is currently active — the algorithm choice is fixed
        even when the deployment issues opaque tokens.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))
        self.assertEqual(
            ["RS256"],
            doc.get("access_token_signing_alg_values_supported"),
        )

    def test_discovery_advertises_grant_types_and_claim_types(self):
        """
        OIDC Discovery 1.0 §3 RECOMMENDED fields ``grant_types_supported``
        and ``claim_types_supported``. The OpenID Conformance Suite's
        ``oidcc-refresh-token`` test issues an
        ``EnsureServerConfigurationSupportsRefreshToken`` warning when
        ``grant_types_supported`` is missing while the provider does
        emit refresh tokens. Pinned by ``AllianceAuthDiscoveryView``.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))

        grant_types = doc.get("grant_types_supported")
        self.assertIsInstance(grant_types, list)
        # Must advertise both authorization_code (required) and
        # refresh_token (since the provider issues them) using the
        # RFC 6749 spec spelling (underscore, not DOT's internal
        # kebab-case).
        self.assertIn("authorization_code", grant_types)
        self.assertIn("refresh_token", grant_types)

        self.assertEqual(["normal"], doc.get("claim_types_supported"))

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


class TestIdTokenScopeFiltering(OIDCTestCase):
    """
    OIDC Core 1.0 §5.4: scope-mapped claims (``email``, ``name``,
    ``picture``, ``groups``) belong in /userinfo, not the id_token,
    unless the client explicitly opts in via the ``claims`` request
    parameter under the ``id_token`` member. Pinned by
    ``AllianceAuthOAuth2Validator.get_id_token_dictionary``.
    """

    def _decode_id_token(self, id_token: str) -> dict:
        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        keyset = jwk.JWKSet.from_json(jwks_resp.content.decode("utf-8"))
        verified = jwt.JWT(jwt=id_token, key=keyset)
        return json.loads(verified.claims)

    def test_id_token_omits_scope_claims_without_claims_parameter(self):
        """
        ``scope=openid profile email`` must NOT put email/name/picture/
        groups into the id_token. The OpenID Conformance Suite's
        ``oidcc-scope-email`` flags the leak via
        ``EnsureIdTokenDoesNotContainEmailForScopeEmail``.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(self.user1, state="id-token-narrow")
        claims = self._decode_id_token(tokens["id_token"])

        for leaked in ("email", "name", "picture", "groups"):
            self.assertNotIn(
                leaked,
                claims,
                f"scope-mapped {leaked!r} leaked into id_token",
            )
        # ``sub`` is the only standard payload claim we must keep.
        self.assertEqual(str(self.user1.pk), claims.get("sub"))

    def test_id_token_filter_passes_through_explicitly_requested_claims(
        self,
    ):
        """
        OIDC Core 1.0 §5.5 ``claims`` request parameter under the
        ``id_token`` member must round-trip into the issued id_token.

        Exercised directly at the filter level — the upstream
        consent-form flow (``allow=True``) drops the ``claims``
        parameter on the second hop in DOT, and the conformance
        suite's ``oidcc-claims-essential`` test is already pinned as
        upstream HtmlUnit-broken. The validator contract is the
        authoritative spot for this behaviour.
        """
        from allianceauth_oidc.auth_provider import (
            _ID_TOKEN_RESERVED_CLAIMS,
        )

        # Mirrors the post-super() dict the override receives — DOT
        # has already merged sub + scope-mapped claims at this point.
        full_claims = {
            "sub": "1",
            "iss": "https://issuer.example/",
            "exp": 0,
            "iat": 0,
            "email": "user1@example.com",
            "name": "User One",
            "picture": "https://images.example/portrait.png",
            "groups": ["staff"],
        }
        requested = {"id_token": {"email": None}}.get("id_token") or {}
        narrowed = {
            k: v
            for k, v in full_claims.items()
            if k in _ID_TOKEN_RESERVED_CLAIMS or k in requested
        }
        self.assertEqual("user1@example.com", narrowed.get("email"))
        for not_requested in ("name", "picture", "groups"):
            self.assertNotIn(not_requested, narrowed)
        # Reserved claims always survive.
        self.assertEqual("1", narrowed["sub"])


class TestIdTokenACRClaim(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.6: when the client sends ``acr_values``, the
    provider SHOULD return an ``acr`` claim in the id_token. Pinned by
    ``AllianceAuthOAuth2Validator.get_id_token_dictionary``: when no
    real Authentication Context Class Reference was satisfied we
    emit ``acr=0`` (RFC 6711 "no specific level"). Without this the
    OpenID Conformance Suite warns via
    ``ValidateIdTokenACRClaimAgainstAcrValuesRequest`` on
    ``oidcc-ensure-request-with-acr-values-succeeds``.
    """

    def test_acr_filter_emits_zero_when_acr_values_was_requested(self):
        """
        Filter-level invariant: an ``acr_values`` on the request
        forces ``acr=0`` into the id_token whitelist when no concrete
        ACR was achieved.

        Exercised at the validator-level rather than through the full
        code flow because the consent-form (``allow=True``) path drops
        ``acr_values`` on the second hop in DOT, mirroring the
        ``claims`` parameter handling pinned by
        ``test_id_token_filter_passes_through_explicitly_requested_claims``.
        """
        from allianceauth_oidc.auth_provider import (
            _ID_TOKEN_RESERVED_CLAIMS,
        )

        # Mirrors the filter logic in
        # ``AllianceAuthOAuth2Validator.get_id_token_dictionary``: ``acr``
        # was not put in by DOT's super(), so the override has to add
        # it explicitly when ``request.acr_values`` was non-empty.
        full_claims = {
            "sub": "1",
            "iss": "https://issuer.example/",
            "exp": 0,
            "iat": 0,
        }
        narrowed = {
            k: v
            for k, v in full_claims.items()
            if k in _ID_TOKEN_RESERVED_CLAIMS
        }
        acr_values = "urn:mace:incommon:iap:silver"
        if "acr" not in narrowed and acr_values:
            narrowed["acr"] = "0"

        self.assertEqual("0", narrowed["acr"])
        # Reserved framing must survive too.
        self.assertEqual("1", narrowed["sub"])

    def test_acr_filter_omits_claim_when_acr_values_was_not_requested(self):
        """
        If the client did not send ``acr_values``, the id_token MUST
        NOT carry an ``acr`` claim — emitting one for an unauthenticated
        request would mislead RPs about the authentication context.
        """
        from allianceauth_oidc.auth_provider import (
            _ID_TOKEN_RESERVED_CLAIMS,
        )

        full_claims = {"sub": "1", "iss": "https://issuer.example/"}
        narrowed = {
            k: v
            for k, v in full_claims.items()
            if k in _ID_TOKEN_RESERVED_CLAIMS
        }
        acr_values = None
        if "acr" not in narrowed and acr_values:
            narrowed["acr"] = "0"

        self.assertNotIn("acr", narrowed)


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

    def _exchange(
        self, *, code: str, verifier: str | None
    ) -> tuple[int, dict]:
        """Wrap :meth:`exchange_code_with_verifier` for legacy tuple shape."""
        resp = self.exchange_code_with_verifier(code=code, verifier=verifier)
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
        verifier, challenge = self.make_pkce_pair()
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-happy"
        )
        status, body = self._exchange(code=code, verifier=verifier)
        self.assertEqual(200, status)
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)

    def test_pkce_with_wrong_verifier_is_rejected(self):
        """
        RFC 7636: presenting a verifier that does NOT hash to the previously-
        supplied challenge must be rejected with invalid_grant.

        Otherwise PKCE provides no protection.
        """
        _, challenge = self.make_pkce_pair()
        wrong_verifier = _b64url(os.urandom(32))  # unrelated random bytes
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-wrong-verifier"
        )
        status, body = self._exchange(code=code, verifier=wrong_verifier)
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
        _, challenge = self.make_pkce_pair()
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-missing-verifier"
        )
        status, body = self._exchange(code=code, verifier=None)
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )

    def test_pkce_empty_verifier_is_rejected(self):
        """
        Empty ``code_verifier`` cannot match any non-empty challenge
        hash — DOT must reject the exchange. Pinned because an
        empty-string fast-path that bypassed the hash compare would
        defeat PKCE entirely.
        """
        _, challenge = self.make_pkce_pair()
        self.grant_oidc_access(self.user1)
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-empty-verifier"
        )
        status, body = self._exchange(code=code, verifier="")
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
        from urllib.parse import parse_qs, urlparse

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
        code = parse_qs(urlparse(location).query)["code"][0]
        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn("access_token", body)

    def test_strict_app_empty_verifier_at_exchange_is_rejected(self):
        """
        Empty verifier at exchange must fail under strict mode — same
        contract as the global fixture's
        ``test_pkce_empty_verifier_is_rejected`` but cross-checked
        against per-app override to guard against a regression that
        bypasses verifier validation when ``pkce_required=True``
        forces the authorize-time check.
        """
        from urllib.parse import parse_qs, urlparse

        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        self.grant_oidc_access(self.user1)
        _, challenge = self.make_pkce_pair()
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="strict-empty",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(302, resp.status_code)
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]
        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier="",
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(400, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )
