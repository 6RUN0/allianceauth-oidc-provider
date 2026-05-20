"""
RFC 9068 JWT access tokens — shape, claim matrix, signature, size guard, key rotation.

Sibling concerns live in test_jwt_shape.py, test_jwt_dispatcher.py,
test_jwt_grants.py, and test_jwt_validation.py. Shared helpers
(split_jwt / mode-switch dicts / lookalike generator) live in
tests/_jwt_helpers.py.
"""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from django.conf import settings as django_settings
from django.test import TestCase, override_settings

from ._jwt_helpers import (
    _jwt_mode_oauth2_provider,
    _opaque_mode_oauth2_provider,
    split_jwt,
)
from ._oidc_testcase import SCOPE_FULL, GrantedOIDCTestCase


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestJWTAccessTokenShape(GrantedOIDCTestCase):
    """RFC 9068 §2.1 / §2.2 shape conformance for issued AT."""

    def setUp(self) -> None:
        super().setUp()

    def _issue_at(self) -> str:
        body = self.run_code_flow(self.user1)
        return body["access_token"]

    def test_typ_is_at_plus_jwt(self) -> None:
        header, _ = split_jwt(self._issue_at())
        self.assertEqual("at+jwt", header.get("typ"))

    def test_alg_is_rs256(self) -> None:
        header, _ = split_jwt(self._issue_at())
        self.assertEqual("RS256", header.get("alg"))

    def test_kid_is_present_and_nonempty(self) -> None:
        header, _ = split_jwt(self._issue_at())
        kid = header.get("kid")
        self.assertIsInstance(kid, str)
        self.assertTrue(kid, "kid must be non-empty (RFC 7638 thumbprint)")

    def test_required_claims_present_per_rfc_9068(self) -> None:
        _, payload = split_jwt(self._issue_at())
        # RFC 9068 §2.2 required: iss, exp, aud, sub, client_id, iat, jti.
        # ``scope`` is required when scopes are present in the request.
        for claim in ("iss", "exp", "aud", "sub", "client_id", "iat", "jti"):
            self.assertIn(claim, payload, f"missing required claim: {claim}")
        self.assertIn("scope", payload)

    def test_aud_matches_client_id(self) -> None:
        _, payload = split_jwt(self._issue_at())
        # AA convention: ``aud`` identifies the application that the
        # token was issued for, mirroring ``client_id``. Documented in
        # ``docs/JWT_ACCESS_TOKENS.md``.
        self.assertEqual(payload.get("client_id"), payload.get("aud"))
        self.assertEqual(self.oauth_id, payload["aud"])

    def test_exp_is_future_iat_is_now(self) -> None:
        _, payload = split_jwt(self._issue_at())
        # ``iat`` is when the token was issued; ``exp`` is later.
        # Strict ``>`` because ``ACCESS_TOKEN_EXPIRE_SECONDS`` is 60
        # in the test settings.
        self.assertIsInstance(payload.get("iat"), int)
        self.assertIsInstance(payload.get("exp"), int)
        self.assertGreater(payload["exp"], payload["iat"])

    def test_sub_is_user_pk_for_authorization_code(self) -> None:
        _, payload = split_jwt(self._issue_at())
        self.assertEqual(str(self.user1.pk), payload.get("sub"))

    def test_scope_is_space_delimited_string(self) -> None:
        _, payload = split_jwt(self._issue_at())
        scope = payload.get("scope")
        self.assertIsInstance(scope, str)
        self.assertIn("openid", scope.split())


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestJWTClaimMatrix(GrantedOIDCTestCase):
    """
    Spec line 85 enforcement: AT and id_token claim sets are
    byte-equivalent for the same scope set on the identity-claim axis.
    """

    def setUp(self) -> None:
        super().setUp()

    def test_jwt_access_token_claims_byte_equivalent_to_id_token(self) -> None:
        body = self.run_code_flow(self.user1, scope=SCOPE_FULL)
        _, at_claims = split_jwt(body["access_token"])
        _, id_claims = split_jwt(body["id_token"])
        # Identity claims are scope-gated by DOT's canonical
        # ``oidc_claim_scope`` map; we re-use that same machinery for
        # the AT (see ``allianceauth_oidc.tokens._identity_claims``).
        # Asserting the intersection of identity-claim names is the
        # tightest statement we can make without coupling to id_token's
        # own framing claims (``nonce``, ``at_hash``, ``c_hash``, ``azp``,
        # ``auth_time``).
        identity_axis = {
            "sub",
            "email",
            "email_verified",
            "name",
            "picture",
            "groups",
            "locale",
        }
        common = identity_axis & at_claims.keys() & id_claims.keys()
        self.assertTrue(
            common,
            "expected at least one identity claim shared between "
            "AT and id_token (sub / email / name / ...)",
        )
        for key in common:
            self.assertEqual(
                id_claims[key],
                at_claims[key],
                f"identity claim {key!r} diverges between AT and id_token",
            )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestSignatureVerification(GrantedOIDCTestCase):
    """
    End-to-end signature verification using ``jwcrypto`` against the
    JWKS published at ``/o/.well-known/jwks.json``. ``jwcrypto`` is
    a transitive dependency of django-oauth-toolkit (DOT signs id_tokens
    with it at ``oauth2_validators.py``); no new package dependency.
    """

    def setUp(self) -> None:
        super().setUp()

    def test_jwt_signature_verifies_against_published_jwks(self) -> None:
        body = self.run_code_flow(self.user1)
        token_str = body["access_token"]

        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, jwks_resp.status_code)
        jwks_doc = self.json_body(jwks_resp, expected_status=None)
        self.assertIn("keys", jwks_doc)
        self.assertGreaterEqual(len(jwks_doc["keys"]), 1)

        from jwcrypto import jwk, jwt

        keyset = jwk.JWKSet()
        for key_data in jwks_doc["keys"]:
            keyset.add(jwk.JWK(**key_data))

        # ``jwt.JWT(jwt=..., key=...)`` deserialises and validates in
        # the constructor; an invalid signature, unknown ``kid``, or
        # mismatched ``alg`` raises immediately. Reaching the next
        # line is the assertion — read claims to prove the JWT was
        # actually decoded against the published key.
        decoded = jwt.JWT(jwt=token_str, key=keyset)
        payload = json.loads(decoded.claims)
        self.assertEqual(self.oauth_id, payload.get("aud"))
        self.assertIn("sub", payload)


class TestSplitJWTHelper(TestCase):
    """Smoke tests for the ``split_jwt`` helper used by other tests."""

    def test_three_segment_input_decodes(self) -> None:
        # Pre-encoded ``{"typ":"at+jwt","alg":"RS256"}`` header
        # paired with ``{"sub":"u"}`` payload and a placeholder
        # signature segment.
        header_seg = (
            base64.urlsafe_b64encode(b'{"typ":"at+jwt","alg":"RS256"}')
            .rstrip(b"=")
            .decode()
        )
        payload_seg = (
            base64.urlsafe_b64encode(b'{"sub":"u"}').rstrip(b"=").decode()
        )
        token = f"{header_seg}.{payload_seg}.sig"
        header, payload = split_jwt(token)
        self.assertEqual("at+jwt", header["typ"])
        self.assertEqual("u", payload["sub"])

    def test_non_jwt_input_raises(self) -> None:
        with self.assertRaises(AssertionError):
            split_jwt("not-a-jwt")


# ---------------------------------------------------------------------------
# US-010 — Batch 2: config-priority integration, forward-compat, size guard,
# unknown-client, startup wiring.
# ---------------------------------------------------------------------------


class TestForwardCompat(GrantedOIDCTestCase):
    """
    Existing deployments upgrading to this module: the migration adds
    ``access_token_format`` with ``default=None``, so legacy rows
    surface as ``None`` and must fall back to whatever the global
    default is. The renamed test (per plan v3 C-N15) exercises the
    actual dispatcher path, not DOT's own ``_load_access_token``.
    """

    def test_legacy_app_row_with_null_format_falls_back_to_global(
        self,
    ) -> None:
        from allianceauth_oidc.tokens import _resolve_access_token_format

        # Simulate a row that existed before migration 0012 and
        # carries the post-migration default ``None``.
        self.oauth_app.access_token_format = None
        self.oauth_app.save(update_fields=["access_token_format"])
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            self.assertEqual(
                "opaque", _resolve_access_token_format(self.oauth_id)
            )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestSizeGuard(GrantedOIDCTestCase):
    """
    The size-guard threshold is operator-configurable via
    ``OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES']`` and
    fires a ``WARNING`` when exceeded; never mutates the token, never
    rejects issuance.
    """

    def setUp(self) -> None:
        super().setUp()

    def test_default_threshold_no_warning_for_small_token(self) -> None:
        # Default 4096 is well above a typical AA JWT (~600-1500 bytes
        # for an authenticated user with a handful of groups). The
        # fixture user1 has no extra groups; the issued JWT must be
        # under threshold.
        with self.assertNoLogs(
            "extensions.allianceauth_oidc.tokens", level="WARNING"
        ):
            body = self.run_code_flow(self.user1)
        # Sanity: confirm the AT really is JWT.
        self.assertEqual(3, body["access_token"].count(".") + 1)

    def test_setting_override_lowers_threshold_and_warns(self) -> None:
        # Threshold 16 bytes guarantees the warning fires on any
        # non-trivial JWT.
        provider = _jwt_mode_oauth2_provider()
        provider["ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES"] = 16
        with (
            override_settings(OAUTH2_PROVIDER=provider),
            self.assertLogs(
                "extensions.allianceauth_oidc.tokens", level="WARNING"
            ) as captured,
        ):
            self.run_code_flow(self.user1)
        joined = "\n".join(captured.output)
        self.assertIn("size", joined.lower())
        self.assertIn("exceeds", joined.lower())

    def test_size_threshold_setting_invalid_falls_back_to_default(
        self,
    ) -> None:
        # Garbage value falls back silently to the module default.
        from allianceauth_oidc.app_settings import (
            _DEFAULT_JWT_SIZE_WARN_BYTES,
            OIDCSettings,
        )

        provider = _jwt_mode_oauth2_provider()
        provider["ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES"] = "not-a-number"
        with override_settings(OAUTH2_PROVIDER=provider):
            self.assertEqual(
                _DEFAULT_JWT_SIZE_WARN_BYTES,
                OIDCSettings.from_django().jwt_size_warn_bytes,
            )


class TestKeyRotationOverlap(GrantedOIDCTestCase):
    """
    RFC 7517 / DOT key-rotation idiom: during the overlap window,
    ``OIDC_RSA_PRIVATE_KEYS_INACTIVE`` lists keys that JWKS continues
    to publish so existing tokens remain verifiable while
    ``OIDC_RSA_PRIVATE_KEY`` (the active signing key) is the one the
    AS uses to sign new tokens.

    Documented in ``docs/JWT_ACCESS_TOKENS.md`` §"Key rotation". This
    test locks that documented overlap into a regression: JWKS
    publishes both kids, and freshly issued JWTs sign with the new
    key.
    """

    @staticmethod
    def _generate_rsa_pem() -> str:
        """Mint a fresh 2048-bit RSA key as PEM string."""
        # Local import — only this test class needs the heavy
        # ``cryptography`` primitives, and they are a transitive dep
        # of ``jwcrypto``.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("ascii")

    def setUp(self) -> None:
        super().setUp()
        # Pre-generate the rotated-out key once per test (cheap on
        # 2048; ~50ms). Tests that need the original key read it
        # from the active settings.
        self.old_pem = django_settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"]
        self.new_pem = self._generate_rsa_pem()

    def test_jwks_publishes_active_and_inactive_keys(self) -> None:
        provider = _jwt_mode_oauth2_provider()
        provider["OIDC_RSA_PRIVATE_KEY"] = self.new_pem
        provider["OIDC_RSA_PRIVATE_KEYS_INACTIVE"] = [self.old_pem]
        with override_settings(OAUTH2_PROVIDER=provider):
            resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, resp.status_code)
        doc = self.json_body(resp, expected_status=None)
        self.assertIn("keys", doc)
        kids = {k.get("kid") for k in doc["keys"]}
        self.assertEqual(
            2,
            len(kids),
            f"JWKS must publish exactly 2 distinct kids during overlap, "
            f"got {kids!r}",
        )

    def test_freshly_issued_jwt_signs_with_active_kid(self) -> None:
        from oauth2_provider.utils import jwk_from_pem

        # ``jwk_from_pem`` is ``lru_cache``d at module level in DOT.
        # Different PEM inputs produce distinct cache entries, so no
        # ``cache_clear()`` needed.
        expected_kid = jwk_from_pem(self.new_pem).thumbprint()

        provider = _jwt_mode_oauth2_provider()
        provider["OIDC_RSA_PRIVATE_KEY"] = self.new_pem
        provider["OIDC_RSA_PRIVATE_KEYS_INACTIVE"] = [self.old_pem]
        with override_settings(OAUTH2_PROVIDER=provider):
            body = self.run_code_flow(self.user1)
        header, _ = split_jwt(body["access_token"])
        self.assertEqual(expected_kid, header.get("kid"))


class TestSizeWarnDefault(TestCase):
    """
    Pin the JWT size-warn default at 4096.

    Cosmic-ray's ``NumberReplacer`` flips the literal to neighbouring
    integers (4095, 4097) and the existing ``TestSizeGuard`` suite
    does NOT discriminate them — the "small token under default"
    test passes for any threshold large enough to exceed the typical
    AA JWT size (~600-1500 bytes), and the explicit override test
    uses ``16``. The exact-value assertion below kills every
    NumberReplacer flip on the constant.

    Post-refactor (c747ee1): the constant now lives in
    ``allianceauth_oidc.app_settings`` and is exposed via
    ``OIDCSettings.from_django().jwt_size_warn_bytes`` — tokens.py
    delegates to the snapshot.
    """

    def test_default_size_warn_bytes_constant_is_4096(self) -> None:
        from allianceauth_oidc.app_settings import (
            _DEFAULT_JWT_SIZE_WARN_BYTES,
        )

        # 4096 is a deliberate choice: Apache LimitRequestFieldSize
        # defaults to 8190, leaving headroom; documented in the module.
        self.assertEqual(4096, _DEFAULT_JWT_SIZE_WARN_BYTES)

    def test_default_threshold_is_4096_via_resolver(self) -> None:
        # Doubles as a contract check on the resolver pipeline: the
        # ``OIDCSettings`` snapshot must read the module default when
        # the operator has not overridden the setting.
        from allianceauth_oidc.app_settings import OIDCSettings

        # Default OAUTH2_PROVIDER in test settings does not set the
        # threshold key — the snapshot returns the module constant.
        self.assertEqual(4096, OIDCSettings.from_django().jwt_size_warn_bytes)


class TestRequiredClaimsArithmetic(TestCase):
    """
    Pin the ``exp = now + expires_in`` arithmetic and the
    ``user is not None and is_authenticated`` boolean guard inside
    ``_required_claims``.

    The end-to-end JWT tests do not pin exact ``exp`` / ``iat``
    values because they rely on real ``time.time()``. Patching
    ``time.time`` to a fixed instant makes the addition observable
    — ``+`` mutated to ``*`` / ``-`` / ``<<`` etc. each yields a
    different numeric ``exp``.
    """

    def test_exp_equals_now_plus_expires_in(self) -> None:
        # Drive ``_required_claims`` with a stub request so we
        # control ``now`` and ``expires_in`` independently of any
        # DOT or fixture state. The function reads ``time.time``
        # directly, so patching that module path is enough.
        from unittest import mock

        from allianceauth_oidc import tokens as tokens_mod

        fake_request = SimpleNamespace(
            user=None,
            client=SimpleNamespace(client_id="cid"),
            expires_in=600,
            scopes=["openid"],
        )
        with mock.patch.object(
            tokens_mod.time, "time", return_value=1_700_000_000
        ):
            claims = tokens_mod._required_claims(fake_request)
        self.assertEqual(1_700_000_000, claims["iat"])
        # ``now + expires_in`` = 1_700_000_000 + 600 — pin the exact
        # value so binary-op flips (``*``, ``-``, ``<<``, ``**``) all
        # produce an observable difference.
        self.assertEqual(1_700_000_600, claims["exp"])

    def test_sub_falls_back_to_client_id_for_machine_to_machine(self) -> None:
        # ``user is not None and is_authenticated`` -> False (user is
        # None) means ``sub`` = ``client_id`` per RFC 9068 §3.
        # ``ReplaceComparisonOperator_IsNot_Is`` flipping ``is not
        # None`` to ``is None`` would make every user be treated as
        # the client-credentials grant — wrong ``sub`` claim, but the
        # existing tests don't pin a specific value here.
        from allianceauth_oidc.tokens import _required_claims

        fake_request = SimpleNamespace(
            user=None,
            client=SimpleNamespace(client_id="my-client"),
            expires_in=60,
            scopes=["openid"],
        )
        claims = _required_claims(fake_request)
        self.assertEqual("my-client", claims["sub"])
        # No ``auth_time`` on the m2m branch.
        self.assertNotIn("auth_time", claims)

    def test_user_without_is_authenticated_attr_is_machine_to_machine(self):
        # ``getattr(user, "is_authenticated", False)`` default — a
        # stub user that omits the attribute MUST take the False
        # branch (m2m path; ``sub`` = client_id). Flipping the
        # default to True would silently elevate every attribute-less
        # object to "authenticated" and try to read ``user.pk``.
        from allianceauth_oidc.tokens import _required_claims

        # A bare ``object()`` has no ``is_authenticated`` and no
        # ``pk`` — the False default keeps us safely on the m2m
        # branch.
        fake_request = SimpleNamespace(
            user=object(),
            client=SimpleNamespace(client_id="cid-x"),
            expires_in=60,
            scopes=["openid"],
        )
        claims = _required_claims(fake_request)
        self.assertEqual("cid-x", claims["sub"])
        self.assertNotIn("auth_time", claims)
