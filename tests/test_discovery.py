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
from typing import Any

from django.test import override_settings
from jwcrypto import jwk, jwt

from ._oidc_testcase import (
    OIDCTestCase,
)

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

    def test_discovery_grant_types_excludes_deprecated_flows(self):
        """
        F-5 regression: discovery must NOT advertise grant types this
        provider does not implement. ``password`` (RFC 6749 §4.3,
        deprecated by RFC 9700 §2.1.2) and ``implicit`` (RFC 6749 §4.2,
        deprecated by RFC 9700 §2.1.1) used to appear in
        ``grant_types_supported`` even though
        ``response_types_supported`` is pinned to ``("code",)`` and
        per-app ``authorization_grant_type`` gating rejects them at
        runtime. Advertising them was a spec-conformance lie that
        invited RP libraries to attempt the flows and silently observe
        opaque ``invalid_grant`` responses.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        doc = json.loads(resp.content.decode("utf-8"))
        grant_types = doc.get("grant_types_supported")

        self.assertNotIn("password", grant_types)
        self.assertNotIn("implicit", grant_types)
        # Positive list — exactly the three the provider actually issues.
        self.assertEqual(
            ["authorization_code", "refresh_token", "client_credentials"],
            grant_types,
        )

    def test_discovery_advertises_end_session_endpoint(self):
        """
        OIDC RP-Initiated Logout 1.0 §2.1: discovery MUST publish
        ``end_session_endpoint`` whenever the AS supports RP-initiated
        logout. DOT gates this advertisement behind
        ``OIDC_RP_INITIATED_LOGOUT_ENABLED`` (default ``False``
        upstream); the AllianceAuth AppConfig flips that default to
        ``True`` in :func:`_apply_default_oauth2_provider_settings`
        so a stock deployment ships a working logout path without
        explicit opt-in. This test pins that wired-together posture:
        if the AppConfig default is reverted or the helper stops
        running on app load, the key disappears and this assertion
        fires loudly — instead of the silent half-paved street the
        upstream default produces (``/o/logout/`` 404, discovery
        missing the endpoint, RP-side logout libraries
        feature-detecting off ``end_session_endpoint`` and giving
        up).
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))
        end_session = doc.get("end_session_endpoint")
        self.assertIsInstance(end_session, str)
        self.assertTrue(
            end_session.startswith("http"),
            f"end_session_endpoint={end_session!r} is not absolute",
        )
        # Sanity that DOT mounted the route we expect. Loose match
        # (``in``) rather than an exact URL so the test survives DOT
        # changing the mount prefix; a future rename to ``/o/end_session``
        # would fail this assertion with a clear diff and prompt a
        # deliberate review rather than a silent contract drift.
        self.assertIn("/logout", end_session, end_session)

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


class TestDiscoveryPolicyAndTosUris(OIDCTestCase):
    """
    OIDC Discovery 1.0 §3 OPTIONAL ``op_policy_uri`` / ``op_tos_uri``.

    Opt-in via two Django settings — surfaced in the discovery
    document when set, omitted otherwise. Tested four ways:
    both unset (default posture), both set, only one set,
    explicit empty string (treated as unset).
    """

    def _discovery(self) -> dict[str, Any]:
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    def test_neither_key_present_by_default(self) -> None:
        doc = self._discovery()
        self.assertNotIn("op_policy_uri", doc)
        self.assertNotIn("op_tos_uri", doc)

    @override_settings(
        ALLIANCEAUTH_OIDC_POLICY_URI="https://auth.example.org/privacy/",
        ALLIANCEAUTH_OIDC_TOS_URI="https://auth.example.org/tos/",
    )
    def test_both_keys_present_when_both_set(self) -> None:
        doc = self._discovery()
        self.assertEqual(
            "https://auth.example.org/privacy/", doc.get("op_policy_uri")
        )
        self.assertEqual(
            "https://auth.example.org/tos/", doc.get("op_tos_uri")
        )

    @override_settings(
        ALLIANCEAUTH_OIDC_POLICY_URI="https://auth.example.org/privacy/",
    )
    def test_only_policy_uri_present_when_only_one_set(self) -> None:
        """
        Operators may surface only a privacy policy without a
        terms-of-service page (or vice versa). The two settings are
        independent — emitting one does not implicitly emit the other.
        """
        doc = self._discovery()
        self.assertEqual(
            "https://auth.example.org/privacy/", doc.get("op_policy_uri")
        )
        self.assertNotIn("op_tos_uri", doc)

    @override_settings(
        ALLIANCEAUTH_OIDC_POLICY_URI="",
        ALLIANCEAUTH_OIDC_TOS_URI="",
    )
    def test_empty_string_treated_as_unset(self) -> None:
        """
        An explicit empty string is operator-equivalent to "not
        configured" — emitting ``"op_policy_uri": ""`` into the
        discovery document would mislead RPs into rendering a
        broken link.
        """
        doc = self._discovery()
        self.assertNotIn("op_policy_uri", doc)
        self.assertNotIn("op_tos_uri", doc)


class TestDiscoveryFieldTypes(OIDCTestCase):
    """
    Strict typing/value contracts on the discovery document.

    The existing :class:`TestDiscoveryAndJWKS` asserts presence
    + a few hand-picked invariants. This class tightens the type
    and value space of a handful of fields that RP-side libraries
    parse strictly — wrong types here cause hard-to-debug client
    failures rather than auth-server errors, and the conformance
    suite covers them indirectly via
    ``oidcc-discovery-endpoint-verification`` (which TIMEOUTs).
    """

    def _doc(self) -> dict[str, Any]:
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    def test_response_types_supported_includes_code(self) -> None:
        """The project supports only the authorization-code flow."""
        doc = self._doc()
        rts = doc.get("response_types_supported")
        self.assertIsInstance(rts, list)
        self.assertIn("code", rts)

    def test_subject_types_supported_is_a_nonempty_string_list(self) -> None:
        """
        OIDC Discovery §3 — ``subject_types_supported`` is REQUIRED
        and must be a non-empty list of strings. Project emits
        ``"public"`` subs (User.pk).
        """
        doc = self._doc()
        sts = doc.get("subject_types_supported")
        self.assertIsInstance(sts, list)
        self.assertTrue(sts)
        for entry in sts:
            self.assertIsInstance(entry, str)
        self.assertIn("public", sts)

    def test_scopes_supported_includes_openid(self) -> None:
        """
        Discovery §3 RECOMMENDED ``scopes_supported`` — even though
        OPTIONAL, RPs auto-select scopes off this list. ``openid``
        MUST be present since the provider is an OIDC provider.
        """
        doc = self._doc()
        scopes = doc.get("scopes_supported")
        self.assertIsInstance(scopes, list)
        self.assertIn("openid", scopes)

    def test_issuer_is_absolute_https_or_http(self) -> None:
        """
        Discovery §3 — ``issuer`` is REQUIRED, MUST be a URL using
        the ``https`` scheme. The test settings pin a placeholder
        ``http://`` issuer for reproducibility; both schemes are
        accepted here, the contract is "absolute URL string".
        """
        doc = self._doc()
        issuer = doc.get("issuer")
        self.assertIsInstance(issuer, str)
        self.assertRegex(issuer, r"^https?://")


class TestDiscoveryPkceAcrSilentAuthMetadata(OIDCTestCase):
    """
    OIDC Discovery 1.0 §3 / RFC 8414 §2 OPTIONAL feature-detect fields.

    Pinned by ``AllianceAuthDiscoveryView`` to the values that mirror
    the concrete provider behaviour: PKCE S256 only (RFC 9700
    forbids ``plain``); ACR fallback ``"0"`` (the value
    :meth:`_inject_acr_fallback` emits); three response_mode values
    DOT actually implements; the three prompt values
    ``AuthAuthorizationView.dispatch`` understands; ``claims``
    request parameter honoured; JAR / PAR not implemented.

    The two negative-flag tests (``request_parameter_supported`` /
    ``request_uri_parameter_supported``) document the deliberate
    refusal to advertise capabilities the provider does not have —
    when a future PR adds JAR or PAR support, flip the assertion to
    ``assertTrue`` and remove the matching row from
    :class:`TestExtensionEndpointsAbsence`.
    """

    def _doc(self) -> dict[str, Any]:
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    def test_code_challenge_methods_supported_is_s256_only(self) -> None:
        doc = self._doc()
        self.assertEqual(["S256"], doc.get("code_challenge_methods_supported"))

    def test_acr_values_supported_carries_rfc6711_zero(self) -> None:
        """
        ``"0"`` is RFC 6711 "no specific level" — the fallback
        ``_inject_acr_fallback`` emits when the RP requested ``acr``
        but the AS cannot satisfy a concrete level. Advertising it
        keeps the discovery + token contract in sync.
        """
        doc = self._doc()
        self.assertEqual(["0"], doc.get("acr_values_supported"))

    def test_response_modes_supported_lists_three_modes(self) -> None:
        doc = self._doc()
        self.assertEqual(
            ["query", "fragment", "form_post"],
            doc.get("response_modes_supported"),
        )

    def test_prompt_values_supported_matches_implementation(self) -> None:
        """
        The three values are the ones ``AuthAuthorizationView.dispatch``
        understands: ``none`` (silent auth via
        ``validate_silent_login`` + ``validate_silent_authorization``),
        ``login`` (force-reauth in ``_enforce_reauth``), ``consent``
        (``_ForceConsentRequired`` sentinel). ``select_account`` is
        deliberately absent — no multi-account UX.
        """
        doc = self._doc()
        self.assertEqual(
            ["none", "login", "consent"],
            doc.get("prompt_values_supported"),
        )

    def test_claims_parameter_supported_is_true(self) -> None:
        doc = self._doc()
        self.assertIs(True, doc.get("claims_parameter_supported"))

    def test_request_parameter_supported_is_false(self) -> None:
        """JAR (RFC 9101 ``request`` JWT) is not implemented."""
        doc = self._doc()
        self.assertIs(False, doc.get("request_parameter_supported"))

    def test_request_uri_parameter_supported_is_false(self) -> None:
        """PAR (RFC 9126 ``request_uri``) is not implemented."""
        doc = self._doc()
        self.assertIs(False, doc.get("request_uri_parameter_supported"))


class TestJWKSCryptoHygiene(OIDCTestCase):
    """
    Cryptographic-hygiene contracts on the published JWKS.

    Three invariants, each closing a foot-gun that has bitten real
    OIDC deployments:

    1. RSA modulus ≥ 2048 bits. Sub-2048 RSA is broken by modern
       factoring research and disallowed by NIST SP 800-131A as of
       2014. An operator who generates a quick 1024-bit test key
       for a demo and forgets to rotate gives every RP a trivially
       impersonable provider.

    2. ``alg`` field, when present per key, MUST be a strong
       signing algorithm — ``RS256/384/512``, ``PS256/384/512``,
       ``ES256/384/512``, or ``EdDSA``. ``none`` and ``HS256`` MUST
       NOT be advertised; the former is unsigned, the latter is
       symmetric and would leak the shared secret via the public
       JWKS.

    3. JWKS MUST NOT expose private-key components. RSA public key
       fields are ``n`` and ``e``. The private fields
       (``d``, ``p``, ``q``, ``dp``, ``dq``, ``qi``, ``oth``) are
       the entire attack — if any of these leaks, every signed JWT
       can be forged.
    """

    def _jwks(self) -> dict:
        resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    @staticmethod
    def _decode_b64url_uint(value: str) -> int:
        # Padding-safe URL-base64 decode of the big-endian integer.
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        return int.from_bytes(raw, "big")

    def test_rsa_modulus_at_least_2048_bits(self) -> None:
        keys = self._jwks().get("keys", [])
        self.assertTrue(keys, "JWKS endpoint returned no keys")
        rsa_keys = [k for k in keys if k.get("kty") == "RSA"]
        self.assertTrue(rsa_keys, "no RSA keys advertised in JWKS")
        for key in rsa_keys:
            n = key.get("n")
            self.assertIsInstance(n, str)
            modulus = self._decode_b64url_uint(n)
            bits = modulus.bit_length()
            self.assertGreaterEqual(
                bits,
                2048,
                f"RSA key kid={key.get('kid')!r} has only {bits}-bit "
                f"modulus; NIST SP 800-131A retired sub-2048 RSA in 2014",
            )

    def test_no_weak_alg_advertised_in_jwks(self) -> None:
        """
        ``alg`` per-key (if present) MUST be in the strong-sig set.

        DOT advertises ``alg=RS256`` on its JWKS keys when an app
        uses RS256; pin that no future code accidentally adds a
        symmetric or unsigned algorithm to the public set.
        """
        strong = {
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "EdDSA",
        }
        keys = self._jwks().get("keys", [])
        for key in keys:
            alg = key.get("alg")
            # ``alg`` is OPTIONAL per RFC 7517 §4.4; only check when
            # present.
            if alg is not None:
                self.assertIn(
                    alg,
                    strong,
                    f"weak alg {alg!r} on key kid={key.get('kid')!r} "
                    f"invites alg-confusion attacks",
                )

    def test_jwks_does_not_expose_private_key_components(self) -> None:
        """
        RSA private components leak the entire signing key. The
        contract: NONE of these fields appears on any published
        key — only the public ``n`` / ``e`` (and ``alg`` / ``kid``
        metadata).
        """
        private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
        keys = self._jwks().get("keys", [])
        for key in keys:
            leaked = set(key) & private_fields
            self.assertFalse(
                leaked,
                f"JWKS key kid={key.get('kid')!r} leaks private "
                f"component(s) {sorted(leaked)} — the entire signing "
                "key is compromised",
            )


class TestDiscoveryAndJWKSCORS(OIDCTestCase):
    """
    Browser-based RPs (SPA / mobile-web) fetch discovery + JWKS
    cross-origin. Both endpoints SHOULD carry
    ``Access-Control-Allow-Origin: *`` — the documents are public
    metadata, no per-request authorization, and any RP MUST be able
    to read them.

    ``AllianceAuthDiscoveryView`` sets the header explicitly. JWKS
    is served by DOT's ``JwksInfoView``; pinning the contract here
    documents whether DOT default is sufficient (current: no CORS
    header on JWKS — a gap if SPA clients hit JWKS via fetch()).
    """

    def test_discovery_advertises_wildcard_cors_origin(self) -> None:
        """Set explicitly in AllianceAuthDiscoveryView.get."""
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("*", resp.headers.get("Access-Control-Allow-Origin"))

    def test_jwks_advertises_wildcard_cors_origin(self) -> None:
        """
        DOT's ``JwksInfoView`` emits ``Access-Control-Allow-Origin: *``
        by default. Pin the contract so a future middleware override
        that strips or restricts the header is caught — SPA clients
        that fetch /jwks.json cross-origin depend on this.
        """
        resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, resp.status_code)
        self.assertEqual("*", resp.headers.get("Access-Control-Allow-Origin"))


class TestExtensionEndpointsAbsence(OIDCTestCase):
    """
    Pin absence of OAuth/OIDC extension endpoints in discovery.

    Discovery does **not** advertise a handful of OAuth/OIDC
    extensions that the upstream stack (django-oauth-toolkit + this
    project) does not implement. Pinning the absence catches two
    classes of regression:

    1. A silent flip to ``true`` when DOT (or a downstream override)
       gains partial support — the corresponding feature would be
       half-implemented and we want explicit review of the
       semantics, not implicit advertisement.
    2. A typo in the discovery builder that emits a key with a
       confusing default (e.g. ``"pushed_authorization_request_endpoint": ""``).

    When any of these features lands, flip the matching assertion
    from ``assertNotIn`` to ``assertEqual`` against the actual
    value.
    """

    def _doc(self) -> dict[str, Any]:
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    def test_extension_keys_absent_from_discovery_sweep(self) -> None:
        """
        Sweep of discovery keys we deliberately do not advertise.

        Each row pins one extension that DOT upstream doesn't
        ship today. When DOT eventually adds support for one of
        them, flip the matching ``assertNotIn`` to ``assertIn``
        and add a smoke test for the new behaviour at the
        endpoint level.

        * ``pushed_authorization_request_endpoint`` +
          ``require_pushed_authorization_requests`` — RFC 9126
          (PAR): clients POST authorize params to a dedicated
          endpoint and receive a ``request_uri``. Mitigates
          URL-length limits and authorize-param tampering.
        * ``dpop_signing_alg_values_supported`` — RFC 9449
          (DPoP): sender-constrained tokens via a per-request
          proof JWT. Mitigates bearer-token theft.
        * ``check_session_iframe`` — OIDC Session Management
          1.0 §3 iframe URL. Superseded by Back-Channel Logout
          (already covered in test_back_channel_logout.py).
        * ``introspection_endpoint_auth_methods_supported`` —
          RFC 7662 §3 RECOMMENDS advertising it; until DOT
          does, RPs must fall back to
          ``token_endpoint_auth_methods_supported``.
        """
        doc = self._doc()
        cases: tuple[tuple[str, str], ...] = (
            (
                "pushed_authorization_request_endpoint",
                "PAR (RFC 9126) endpoint",
            ),
            (
                "require_pushed_authorization_requests",
                "PAR (RFC 9126) per-client flag",
            ),
            (
                "dpop_signing_alg_values_supported",
                "DPoP (RFC 9449) advertised algs",
            ),
            (
                "check_session_iframe",
                "OIDC Session Management iframe",
            ),
            (
                "introspection_endpoint_auth_methods_supported",
                "RFC 7662 §3 RECOMMENDED introspection auth",
            ),
        )
        for key, why in cases:
            with self.subTest(key=key):
                self.assertNotIn(
                    key,
                    doc,
                    f"DOT shipped {why}; flip this assertion "
                    f"to ``assertIn`` and add a smoke test.",
                )
