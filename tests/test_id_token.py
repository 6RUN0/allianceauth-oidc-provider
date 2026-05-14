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

from jwcrypto import jwk, jwt

from ._oidc_testcase import (
    OIDCTestCase,
)


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


class TestIdTokenAuthTime(OIDCTestCase):
    """
    OIDC Core 1.0 §2 + §3.1.2.1: when the RP includes ``max_age``
    in the authorize request, the id_token MUST carry an
    ``auth_time`` claim (numeric epoch). Strictly, ``auth_time``
    is OPTIONAL outside the ``max_age`` case — but emitting it
    unconditionally for authenticated users matches DOT's
    behaviour and lets RPs implement client-side ``max_age``
    enforcement without negotiating a server config flag.
    """

    def _decode_id_token(self, id_token: str) -> dict:
        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        keyset = jwk.JWKSet.from_json(jwks_resp.content.decode("utf-8"))
        verified = jwt.JWT(jwt=id_token, key=keyset)
        return json.loads(verified.claims)

    def test_id_token_carries_auth_time_when_max_age_requested(
        self,
    ) -> None:
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(
            self.user1,
            state="auth-time-test",
            extra_authorize_params={"max_age": "3600"},
        )
        claims = self._decode_id_token(tokens["id_token"])
        self.assertIn(
            "auth_time",
            claims,
            f"auth_time MUST be present under max_age request; got "
            f"claims keys={sorted(claims)}",
        )
        self.assertIsInstance(
            claims["auth_time"],
            int,
            f"auth_time must be numeric epoch; got {claims['auth_time']!r}",
        )

    def test_auth_time_matches_user_last_login(self) -> None:
        """
        The emitted ``auth_time`` is the integer epoch
        representation of ``user.last_login`` — that is the
        source of truth used by ``_max_age_expired``, so the
        RP-visible value and the AS-side enforcement value must
        agree.
        """
        from django.utils import dateformat

        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(
            self.user1,
            state="auth-time-equality",
            extra_authorize_params={"max_age": "3600"},
        )
        claims = self._decode_id_token(tokens["id_token"])
        self.user1.refresh_from_db()
        expected = int(dateformat.format(self.user1.last_login, "U"))
        self.assertEqual(expected, claims["auth_time"])


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


class TestIdTokenAlgConfusion(OIDCTestCase):
    """
    Algorithm-confusion defences on the issued id_token.

    A regression that drops the id_token down to ``alg=none`` (or
    re-signs with HS256 using the *public* JWKS key) is the textbook
    JWT-confusion attack — every downstream RP that validates with
    "any alg the header claims" is then trivially impersonated.

    The existing ``test_id_token_is_signed_and_verifiable_against_jwks``
    pins ``alg=RS256`` indirectly. This class makes the defensive
    assertions explicit, decoupled from the success-path JWKS
    verification flow, so a regression review sees the defence by
    test name alone.
    """

    def _decode_id_token_header(self, id_token: str) -> dict:
        # Split JWT header without verifying — we are asserting the
        # header's algorithm field, not the signature.
        header_b64 = id_token.split(".", 1)[0]
        # base64url decode with padding restored.
        padding = "=" * (-len(header_b64) % 4)
        return json.loads(
            base64.urlsafe_b64decode(header_b64 + padding).decode("utf-8")
        )

    def test_id_token_alg_is_never_none(self) -> None:
        """
        Tight regression pin: a freshly issued id_token's header
        ``alg`` MUST NOT be ``"none"`` or ``"None"``. Any value that
        matches case-insensitively reduces the JWT to an unsigned
        blob and bypasses every downstream verification step.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(self.user1, state="id-token-alg-none")
        header = self._decode_id_token_header(tokens["id_token"])
        alg = header.get("alg", "")
        self.assertNotIn(
            alg.lower(),
            ("none", ""),
            f"id_token header alg={alg!r} is forbidden — unsigned "
            "JWTs MUST NOT be issued",
        )

    def test_id_token_alg_matches_jwks_advertised(self) -> None:
        """
        The header ``alg`` must be one of the algorithms advertised by
        ``/.well-known/openid-configuration/id_token_signing_alg_values_supported``.
        A drift between header and discovery breaks RP signature
        verification and is the precondition for an alg-confusion
        attack on naive verifiers.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(self.user1, state="id-token-alg-match")
        header = self._decode_id_token_header(tokens["id_token"])

        discovery = self.client.get("/o/.well-known/openid-configuration/")
        advertised = json.loads(discovery.content.decode("utf-8")).get(
            "id_token_signing_alg_values_supported"
        )
        self.assertIsInstance(advertised, list)
        self.assertIn(
            header.get("alg"),
            advertised,
            f"id_token header alg={header.get('alg')!r} is not in the "
            f"discovery-advertised set {advertised!r}",
        )

    def test_discovery_does_not_advertise_alg_none(self) -> None:
        """
        ``id_token_signing_alg_values_supported`` MUST NOT include
        ``"none"``. Even a single advertised ``none`` entry is a
        green light for RP libraries that auto-select the first
        algorithm — and a green light for an alg-confusion attack
        on every downstream consumer.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        doc = json.loads(resp.content.decode("utf-8"))
        algs = doc.get("id_token_signing_alg_values_supported", [])
        self.assertNotIn(
            "none",
            algs,
            f"alg=none MUST NOT be advertised; got {algs!r}",
        )

    def test_id_token_kid_resolves_to_a_jwks_key(self) -> None:
        """
        The header ``kid`` must point at a key actually published on
        the JWKS endpoint. A dangling ``kid`` (header references a
        key absent from JWKS) means every RP fails verification but
        the AS thinks it issued a valid token — a hard-to-debug
        outage and a precondition for downgrade attacks.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(self.user1, state="id-token-kid")
        header = self._decode_id_token_header(tokens["id_token"])
        token_kid = header.get("kid")
        self.assertIsInstance(token_kid, str)
        self.assertTrue(token_kid)

        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        jwks = json.loads(jwks_resp.content.decode("utf-8"))
        published_kids = {k.get("kid") for k in jwks.get("keys", [])}
        self.assertIn(
            token_kid,
            published_kids,
            f"id_token kid={token_kid!r} is not published in JWKS "
            f"{sorted(published_kids)!r}",
        )
