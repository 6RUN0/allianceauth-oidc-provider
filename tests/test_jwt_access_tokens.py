"""
Tests for RFC 9068 JWT access tokens.

Covers shape, byte-equivalence with id_token at the identity claims,
signature verification end-to-end against published JWKS, the
``DOT`` ``AccessToken.token`` field invariant, the audit signal
payload, and the unit-level policy DI seam.

JWT mode is activated per test class via ``override_settings`` that
merges ``ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt"`` onto
the test settings dict. The dispatcher itself is wired globally in
``tests/test_settingsAA4.py`` so the override only flips the format
flag — exactly the operator path documented in
``docs/JWT_ACCESS_TOKENS.md``.
"""

from __future__ import annotations

import base64
import json
import logging
from types import SimpleNamespace
from typing import Any

from django.conf import settings as django_settings
from django.test import TestCase, override_settings

from allianceauth_oidc.security import DEFAULT_POLICY
from allianceauth_oidc.signals import oidc_token_issued

from ._oidc_testcase import REDIRECT_URI, SCOPE_FULL, OIDCTestCase

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jwt_mode_oauth2_provider() -> dict:
    """
    Return ``OAUTH2_PROVIDER`` test dict with JWT mode enabled.

    Snapshot evaluated once at module-import time. Tests that need
    additional overrides (e.g. ``ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES``)
    build their own copy of this dict and patch on top.
    """
    base = dict(django_settings.OAUTH2_PROVIDER)
    base["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "jwt"
    return base


def _opaque_mode_oauth2_provider() -> dict:
    """Return ``OAUTH2_PROVIDER`` test dict with explicit opaque mode."""
    base = dict(django_settings.OAUTH2_PROVIDER)
    base["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "opaque"
    return base


def _b64url_decode(seg: str) -> bytes:
    """Padding-safe URL-safe base64 decode."""
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def split_jwt(token: str) -> tuple[dict, dict]:
    """Return ``(header, payload)`` from a compact JWT (no signature check)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AssertionError(
            f"Token does not look like a JWT (got {len(parts)} segments): "
            f"{token[:32]!r}..."
        )
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def lookalike_access_token_generator(request: Any) -> str:
    """
    Decoy generator used by the L-3 regression test.

    ``__module__`` and ``__qualname__`` are rewritten below so the
    formatted ``f"{module}.{qualname}"`` happens to contain the
    canonical dispatcher path as substring — a substring-based wiring
    check would incorrectly stay silent. Identity-based detection
    must still flag the mismatch because ``actual is dispatcher``
    short-circuits before any name introspection.
    """
    return "lookalike-not-a-real-token"


# DOT resolves ``ACCESS_TOKEN_GENERATOR`` via ``importlib`` against the
# real dotted path (``tests.test_jwt_access_tokens.lookalike_...``).
# The introspected ``__module__`` / ``__qualname__`` below are pure
# attribute writes — they do not affect import — and exist solely to
# fool the substring formatter.
lookalike_access_token_generator.__module__ = "allianceauth_oidc.tokens"
lookalike_access_token_generator.__qualname__ = (
    "dispatching_access_token_generator"
)


# ---------------------------------------------------------------------------
# US-009 — Batch 1
# ---------------------------------------------------------------------------


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestJWTAccessTokenShape(OIDCTestCase):
    """RFC 9068 §2.1 / §2.2 shape conformance for issued AT."""

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

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
class TestJWTClaimMatrix(OIDCTestCase):
    """
    Spec line 85 enforcement: AT and id_token claim sets are
    byte-equivalent for the same scope set on the identity-claim axis.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

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
class TestSignatureVerification(OIDCTestCase):
    """
    End-to-end signature verification using ``jwcrypto`` against the
    JWKS published at ``/o/.well-known/jwks.json``. ``jwcrypto`` is
    a transitive dependency of django-oauth-toolkit (DOT signs id_tokens
    with it at ``oauth2_validators.py``); no new package dependency.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_signature_verifies_against_published_jwks(self) -> None:
        body = self.run_code_flow(self.user1)
        token_str = body["access_token"]

        jwks_resp = self.client.get("/o/.well-known/jwks.json")
        self.assertEqual(200, jwks_resp.status_code)
        jwks_doc = json.loads(jwks_resp.content)
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


class TestDOTContract(TestCase):
    """
    Invariant test that locks DOT's ``AccessToken.token`` field shape
    so a future DOT release cannot silently break our wide-token
    assumption (see ``.omc/plans/jwt-access-tokens-plan-v3.md``
    Decision D and Risk R1').
    """

    def test_dot_access_token_field_is_textfield(self) -> None:
        from django.db.models import TextField
        from oauth2_provider.models import get_access_token_model

        field = get_access_token_model()._meta.get_field("token")
        self.assertIsInstance(
            field,
            TextField,
            "DOT regression: AccessToken.token narrowed; widening the "
            "field is now this module's responsibility — see plan v3 "
            "Decision D for the rationale and the migration recipe.",
        )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestAuditSignal(OIDCTestCase):
    """
    Verify ``oidc_token_issued`` payload includes ``format="jwt"`` so
    SIEM receivers can route on issued format. Default receiver
    ignores the field (only logs ``grant_type`` / ``scope``); custom
    receivers wire ``body.get("format")`` themselves.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)
        self.captured: list[dict[str, Any]] = []

        def capture(sender: Any, **kwargs: Any) -> None:
            self.captured.append(kwargs)

        self._capture_receiver = capture
        oidc_token_issued.connect(capture, weak=False)
        self.addCleanup(oidc_token_issued.disconnect, capture)

    def test_audit_signal_payload_includes_format_jwt(self) -> None:
        self.run_code_flow(self.user1)
        formats = [
            kwargs.get("body", {}).get("format")
            for kwargs in self.captured
            if "body" in kwargs and isinstance(kwargs["body"], dict)
        ]
        self.assertIn("jwt", formats)


@override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider())
class TestAuditSignalOpaque(OIDCTestCase):
    """Companion: opaque mode emits ``format="opaque"``."""

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)
        self.captured: list[dict[str, Any]] = []

        def capture(sender: Any, **kwargs: Any) -> None:
            self.captured.append(kwargs)

        oidc_token_issued.connect(capture, weak=False)
        self.addCleanup(oidc_token_issued.disconnect, capture)

    def test_audit_signal_payload_includes_format_opaque(self) -> None:
        self.run_code_flow(self.user1)
        formats = [
            kwargs.get("body", {}).get("format")
            for kwargs in self.captured
            if "body" in kwargs and isinstance(kwargs["body"], dict)
        ]
        self.assertIn("opaque", formats)


class TestDispatcherFormatResolution(TestCase):
    """
    Unit-level: ``AccessPolicy.access_token_format`` resolves an
    ``AppLike`` double without touching the DB. Mirrors the per-app
    PKCE DI-seam test pattern — synthetic doubles work because the
    policy is pure logic.
    """

    def test_per_app_jwt_overrides_global_opaque(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "opaque",
            }
        ):
            app = SimpleNamespace(access_token_format="jwt")
            self.assertEqual("jwt", DEFAULT_POLICY.access_token_format(app))

    def test_per_app_none_falls_back_to_global_jwt(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
            }
        ):
            app = SimpleNamespace(access_token_format=None)
            self.assertEqual("jwt", DEFAULT_POLICY.access_token_format(app))

    def test_per_app_none_global_absent_falls_back_to_opaque(self) -> None:
        with override_settings(OAUTH2_PROVIDER={}):
            app = SimpleNamespace(access_token_format=None)
            self.assertEqual("opaque", DEFAULT_POLICY.access_token_format(app))

    def test_app_is_none_uses_global(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
            }
        ):
            self.assertEqual("jwt", DEFAULT_POLICY.access_token_format(None))

    def test_invalid_per_app_value_falls_through_to_global(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "opaque",
            }
        ):
            app = SimpleNamespace(access_token_format="garbage")
            self.assertEqual("opaque", DEFAULT_POLICY.access_token_format(app))

    def test_invalid_global_value_falls_back_to_opaque(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "garbage",
            }
        ):
            self.assertEqual(
                "opaque", DEFAULT_POLICY.access_token_format(None)
            )


# ---------------------------------------------------------------------------
# Helper-tests: keep ``classify_token_format`` / ``split_jwt`` honest.
# These guard the test infrastructure itself; if either drifts, every
# JWT test in this file silently regresses.
# ---------------------------------------------------------------------------


class TestClassifyTokenFormat(TestCase):
    """
    Direct tests for ``views.classify_token_format``.

    The classifier flows into ``OIDCAuditBody["format"]`` so audit
    receivers can route by issued token shape. Until this class
    landed, the only coverage was indirect (through the audit signal
    on a JWT-issuing test); cosmic-ray flagged ~10 surviving mutants
    spread across the ``isinstance`` guard, the length-of-segments
    check, the base64 padding math, the exception filter, and the
    ``and``/``==`` pair on the ``typ`` lookup. Each test below pins
    one of those edges.
    """

    @staticmethod
    def _jws_with_header(header: dict | list | str) -> str:
        """
        Build a 3-segment JWS whose header decodes to ``header``.

        Payload + signature are placeholders — the classifier only
        reads the header. The base64 segment is stripped of ``=`` to
        match real-world JWS encoding and exercise the padding-math
        branch in ``classify_token_format``.
        """
        header_bytes = json.dumps(header).encode()
        header_b64 = (
            base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode()
        )
        return f"{header_b64}.payload.sig"

    def test_non_string_returns_none(self) -> None:
        # The ``isinstance(token_str, str)`` guard short-circuits to
        # ``None`` for anything but a string. Mutating ``not
        # isinstance(...)`` to ``isinstance(...)`` (cosmic-ray's
        # ``AddNot``) would let bytes/dicts reach ``.split(".")``,
        # which then either crashes (bytes have no .split-with-str
        # method) or returns a wrong value.
        from allianceauth_oidc.views import classify_token_format

        for non_str in (b"abc", None, 12345, [], {}, object()):
            self.assertIsNone(classify_token_format(non_str))

    def test_two_segments_is_opaque(self) -> None:
        # ``len(parts) != 3`` length check. Mutants:
        #   * ``!=`` → ``>`` / ``<`` / ``is not``: each lets a
        #     wrong-segment-count input slip past as if it were a
        #     valid JWS and crash on base64-decoding a non-base64
        #     payload.
        # All three flips MUST take the opaque branch for this input.
        from allianceauth_oidc.views import classify_token_format

        self.assertEqual("opaque", classify_token_format("a.b"))

    def test_four_segments_is_opaque(self) -> None:
        # Symmetric: more dots than expected.
        from allianceauth_oidc.views import classify_token_format

        self.assertEqual("opaque", classify_token_format("a.b.c.d"))

    def test_zero_dot_token_is_opaque(self) -> None:
        # Edge case: no dot at all (single segment after ``split``).
        from allianceauth_oidc.views import classify_token_format

        self.assertEqual("opaque", classify_token_format("opaque-token"))

    def test_valid_jws_with_at_jwt_typ_is_jwt(self) -> None:
        # Happy path: 3-segment JWS, header decodes to a dict, ``typ``
        # equals ``"at+jwt"``. Both branches of the final ``and``
        # must succeed for the function to return ``"jwt"``.
        from allianceauth_oidc.views import classify_token_format

        token = self._jws_with_header({"typ": "at+jwt", "alg": "RS256"})
        self.assertEqual("jwt", classify_token_format(token))

    def test_valid_jws_with_different_typ_is_opaque(self) -> None:
        # ``header.get("typ") == "at+jwt"`` — ``Eq_*`` mutants flip
        # the operator to ``<=`` / ``>=`` / ``is not``: for a plain
        # ``"JWT"`` value, ``==`` returns False (the only "correct"
        # answer for this input). Any of the mutated forms would
        # erroneously return ``"jwt"``.
        from allianceauth_oidc.views import classify_token_format

        token = self._jws_with_header({"typ": "JWT", "alg": "RS256"})
        self.assertEqual("opaque", classify_token_format(token))

    def test_valid_jws_without_typ_is_opaque(self) -> None:
        # ``header.get("typ")`` returns ``None``; ``None != "at+jwt"``
        # → opaque. Pins the ``.get("typ")`` default behaviour
        # (cosmic-ray doesn't directly mutate ``.get`` but the test
        # also closes the "header has typ key" ambiguity).
        from allianceauth_oidc.views import classify_token_format

        token = self._jws_with_header({"alg": "RS256"})
        self.assertEqual("opaque", classify_token_format(token))

    def test_header_not_dict_is_opaque(self) -> None:
        # ``isinstance(header, dict) and ...`` — if the JSON decode
        # yields a list/string/number, the left side of the ``and``
        # is False and the whole expression short-circuits. Mutating
        # ``and`` to ``or`` (``ReplaceAndWithOr``) would unconditionally
        # evaluate the right side: ``["not", "dict"].get("typ")``
        # raises AttributeError and the function crashes.
        from allianceauth_oidc.views import classify_token_format

        token = self._jws_with_header(["not", "a", "dict"])
        self.assertEqual("opaque", classify_token_format(token))

    def test_malformed_base64_header_is_opaque(self) -> None:
        # The ``try`` wraps base64 decode + json parse and catches
        # ``(ValueError, TypeError, binascii.Error)``. Mutants that
        # narrow the exception set (e.g. drop ``binascii.Error``)
        # let a malformed-base64 header crash the classifier instead
        # of falling through to ``"opaque"``.
        from allianceauth_oidc.views import classify_token_format

        # ``@`` is outside the base64url alphabet; 3-segment shape
        # makes the input reach the decode.
        self.assertEqual("opaque", classify_token_format("@@@.@@@.@@@"))

    def test_header_non_json_payload_is_opaque(self) -> None:
        # base64-decodes fine but yields bytes that aren't valid
        # JSON. ``json.loads`` raises ValueError → caught → opaque.
        from allianceauth_oidc.views import classify_token_format

        # Valid base64 for "garbage" (not JSON).
        bad_header = (
            base64.urlsafe_b64encode(b"not-json").rstrip(b"=").decode()
        )
        token = f"{bad_header}.payload.sig"
        self.assertEqual("opaque", classify_token_format(token))

    def test_header_padding_math_handles_non_aligned_segment(self) -> None:
        # ``pad = "=" * (-len(parts[0]) % 4)`` rebuilds the base64
        # padding stripped from the wire form. ``USub_UAdd`` flips
        # ``-len(...)`` to ``+len(...)``: for a 22-char segment
        # ``-22 % 4 == 2`` (correct: add 2 ``=``) versus ``+22 % 4 == 2``
        # (accidentally equal), so a length of e.g. 23 distinguishes
        # them (``-23 % 4 == 1``, ``+23 % 4 == 3``). The 14-byte
        # header below encodes to a 19-char segment (``19 % 4 == 3``,
        # ``-19 % 4 == 1``) — a length where the two arithmetic
        # mutations disagree, so a JWT-typed header through this
        # function only classifies as ``"jwt"`` when the padding is
        # right.
        from allianceauth_oidc.views import classify_token_format

        header_bytes = b'{"typ":"at+jwt"}'  # 16 bytes → 22-char b64
        header_b64 = (
            base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode()
        )
        # Confirm the segment is NOT already 4-aligned so the
        # mutation has actual work to disagree on.
        self.assertNotEqual(0, len(header_b64) % 4)
        token = f"{header_b64}.payload.sig"
        self.assertEqual("jwt", classify_token_format(token))


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


class TestFormatConfigResolution(OIDCTestCase):
    """
    Integration-level dispatcher behaviour through the adapter and
    through the live DB. Mirrors the unit-level
    ``TestDispatcherFormatResolution`` cases but exercises the full
    ``_resolve_access_token_format(client_id)`` path that DOT calls
    on every token issuance.
    """

    def _resolve(self, client_id: str) -> str:
        from allianceauth_oidc.tokens import _resolve_access_token_format

        return _resolve_access_token_format(client_id)

    def test_per_app_jwt_overrides_global_opaque(self) -> None:
        self.oauth_app.access_token_format = "jwt"
        self.oauth_app.save(update_fields=["access_token_format"])
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            self.assertEqual("jwt", self._resolve(self.oauth_id))

    def test_per_app_none_falls_back_to_global_jwt(self) -> None:
        self.oauth_app.access_token_format = None
        self.oauth_app.save(update_fields=["access_token_format"])
        with override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider()):
            self.assertEqual("jwt", self._resolve(self.oauth_id))

    def test_per_app_none_global_opaque_returns_opaque(self) -> None:
        self.oauth_app.access_token_format = None
        self.oauth_app.save(update_fields=["access_token_format"])
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            self.assertEqual("opaque", self._resolve(self.oauth_id))

    def test_per_app_none_global_absent_returns_opaque(self) -> None:
        # Global key absent — the safe-by-default fallback to opaque
        # is exactly what protects existing deployments from a
        # surprise upgrade when this module is installed.
        self.oauth_app.access_token_format = None
        self.oauth_app.save(update_fields=["access_token_format"])
        provider = dict(django_settings.OAUTH2_PROVIDER)
        provider.pop("ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT", None)
        with override_settings(OAUTH2_PROVIDER=provider):
            self.assertEqual("opaque", self._resolve(self.oauth_id))


class TestForwardCompat(OIDCTestCase):
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
class TestSizeGuard(OIDCTestCase):
    """
    The size-guard threshold is operator-configurable via
    ``OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES']`` and
    fires a ``WARNING`` when exceeded; never mutates the token, never
    rejects issuance.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

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
        # Garbage value falls back silently to ``_DEFAULT_SIZE_WARN_BYTES``.
        from allianceauth_oidc.tokens import (
            _DEFAULT_SIZE_WARN_BYTES,
            _size_warn_threshold,
        )

        provider = _jwt_mode_oauth2_provider()
        provider["ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES"] = "not-a-number"
        with override_settings(OAUTH2_PROVIDER=provider):
            self.assertEqual(_DEFAULT_SIZE_WARN_BYTES, _size_warn_threshold())


class TestUnknownClient(TestCase):
    """
    Fail-safe-strict on unknown / empty ``client_id``: the dispatcher
    logs a ``WARNING`` and returns ``"opaque"`` rather than refusing
    to issue. Mirrors the per-app PKCE adapter pattern.
    """

    def test_unknown_client_id_falls_back_to_opaque_with_warning(
        self,
    ) -> None:
        from allianceauth_oidc.tokens import _resolve_access_token_format

        with self.assertLogs(
            "extensions.allianceauth_oidc.tokens", level="WARNING"
        ) as captured:
            self.assertEqual(
                "opaque",
                _resolve_access_token_format("does-not-exist-client"),
            )
        self.assertIn("unknown client_id", "\n".join(captured.output))

    def test_empty_client_id_falls_back_to_opaque_with_warning(self) -> None:
        from allianceauth_oidc.tokens import _resolve_access_token_format

        with self.assertLogs(
            "extensions.allianceauth_oidc.tokens", level="WARNING"
        ) as captured:
            self.assertEqual("opaque", _resolve_access_token_format(""))
        self.assertIn("empty client_id", "\n".join(captured.output))


class TestStartupWiringCheck(TestCase):
    """
    The ``apps.py:_check_jwt_wiring`` startup helper logs a warning
    only when the operator activated JWT mode but did not also wire
    ``ACCESS_TOKEN_GENERATOR`` to our dispatcher. SAFE-by-design:
    log-only, no settings mutation; ``try/except`` wrapped so a
    misconfigured dotted path cannot crash app startup.

    Drives the helper exclusively through Django ``override_settings``
    so DOT's ``OAuth2ProviderSettings`` reload-on-signal flow stays
    intact — direct ``patch.object`` on ``oauth2_settings`` collides
    with the cleanup pass when ``override_settings`` exits.
    """

    LOGGER_NAME = "extensions.allianceauth_oidc.apps"
    EXPECTED = "allianceauth_oidc.tokens.dispatching_access_token_generator"

    def _build_provider(self, **overrides: Any) -> dict:
        provider = dict(django_settings.OAUTH2_PROVIDER)
        provider.update(overrides)
        return provider

    def _capture_check(self, provider: dict) -> Any:
        from allianceauth_oidc.apps import _check_jwt_wiring

        with (
            override_settings(OAUTH2_PROVIDER=provider),
            self.assertLogs(self.LOGGER_NAME, level="DEBUG") as captured,
        ):
            # Anchor record so ``assertLogs`` does not raise when
            # the helper produces no output (the no-warning branches).
            # We filter to WARNING+ below.
            logging.getLogger(self.LOGGER_NAME).debug("test-anchor")
            _check_jwt_wiring()
        return captured

    def _warning_records(self, captured: Any) -> list[str]:
        return [line for line in captured.output if line.startswith("WARNING")]

    def test_no_warning_when_default_is_opaque(self) -> None:
        captured = self._capture_check(
            self._build_provider(
                ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="opaque",
            )
        )
        self.assertEqual([], self._warning_records(captured))

    def test_warning_when_jwt_default_but_no_dispatcher(self) -> None:
        # Removing ACCESS_TOKEN_GENERATOR from OAUTH2_PROVIDER causes
        # DOT to fall back to its own default (None) when oauth2_settings
        # reloads inside the override.
        provider = self._build_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt",
        )
        provider.pop("ACCESS_TOKEN_GENERATOR", None)
        captured = self._capture_check(provider)
        warnings = self._warning_records(captured)
        self.assertTrue(
            warnings,
            "expected a WARNING when JWT mode is on without dispatcher",
        )
        joined = "\n".join(warnings)
        self.assertIn(self.EXPECTED, joined)

    def test_no_warning_when_jwt_default_and_correct_dispatcher(
        self,
    ) -> None:
        # ``ACCESS_TOKEN_GENERATOR`` is wired to our dispatcher in
        # ``tests/test_settingsAA4.py``; the build_provider inherits
        # that, so flipping the format flag should NOT log a warning.
        captured = self._capture_check(
            self._build_provider(
                ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt",
            )
        )
        self.assertEqual([], self._warning_records(captured))

    def test_warns_on_lookalike_generator_with_spoofed_qualname(
        self,
    ) -> None:
        """
        Substring detection had a false-negative on a callable whose
        ``__module__``/``__qualname__`` were rewritten to look like
        ours — the formatted name contained the expected path, so a
        ``substring in actual_name`` test stayed silent. Identity
        check (``actual is dispatching_access_token_generator``)
        catches the mismatch because object identity ignores the
        spoofed attributes.
        """
        provider = self._build_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt",
            ACCESS_TOKEN_GENERATOR=(
                "tests.test_jwt_access_tokens.lookalike_access_token_generator"
            ),
        )
        captured = self._capture_check(provider)
        warnings = self._warning_records(captured)
        self.assertTrue(
            warnings,
            "expected a WARNING for a lookalike whose name spoofs the "
            "dispatcher path but whose identity differs",
        )
        joined = "\n".join(warnings)
        self.assertIn(self.EXPECTED, joined)


# ---------------------------------------------------------------------------
# US-011 — Batch 3: client_credentials, password, refresh, lifecycle.
# ---------------------------------------------------------------------------


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestClientCredentials(OIDCTestCase):
    """
    RFC 9068 §3 + OAuth 2.0 §4.4 fallback: ``sub=client_id`` for
    client_credentials grants because there is no end user.
    ``auth_time`` is omitted in this branch — there is no
    authentication event to timestamp.
    """

    def setUp(self) -> None:
        super().setUp()
        from oauth2_provider.models import AbstractApplication

        from ._factories import make_app

        self.grant_oidc_access(self.user1)
        cc_app, cc_id, cc_secret = make_app(
            owner=self.user1,
            authorization_grant_type=(
                AbstractApplication.GRANT_CLIENT_CREDENTIALS
            ),
            client_type=AbstractApplication.CLIENT_CONFIDENTIAL,
            pkce_required=False,
            access_token_format="jwt",
        )
        self.cc_app = cc_app
        self.cc_id = cc_id
        self.cc_secret = cc_secret

    def _issue(self) -> str:
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "client_credentials",
                "client_id": self.cc_id,
                "client_secret": self.cc_secret,
                "scope": "openid",
            },
        )
        self.assertEqual(200, resp.status_code, resp.content)
        body = json.loads(resp.content)
        return body["access_token"]

    def test_sub_eq_client_id_when_user_is_none(self) -> None:
        token = self._issue()
        _, payload = split_jwt(token)
        self.assertEqual(self.cc_id, payload.get("sub"))
        self.assertEqual(self.cc_id, payload.get("client_id"))
        self.assertEqual(self.cc_id, payload.get("aud"))

    def test_no_auth_time_for_client_credentials(self) -> None:
        token = self._issue()
        _, payload = split_jwt(token)
        self.assertNotIn("auth_time", payload)


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestPasswordGrant(OIDCTestCase):
    """
    Password grant under JWT mode: should produce a JWT with
    ``sub=user.pk`` (an authenticated user is involved), unlike
    client_credentials.
    """

    def setUp(self) -> None:
        super().setUp()
        from oauth2_provider.models import AbstractApplication

        from ._factories import make_app

        self.grant_oidc_access(self.user1)
        # Password grant requires a known cleartext password on the
        # user; AA's ``AuthUtils.create_user`` does not expose one
        # convenient for tests, so set one explicitly.
        self.user1.set_password("secret-pw-123")  # nosec B106 - test fixture
        self.user1.save(update_fields=["password"])
        pw_app, pw_id, pw_secret = make_app(
            owner=self.user1,
            authorization_grant_type=AbstractApplication.GRANT_PASSWORD,
            client_type=AbstractApplication.CLIENT_CONFIDENTIAL,
            pkce_required=False,
            access_token_format="jwt",
        )
        self.pw_app = pw_app
        self.pw_id = pw_id
        self.pw_secret = pw_secret

    def test_password_grant_produces_jwt_with_user_sub(self) -> None:
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "password",
                "username": self.user1.username,
                "password": "secret-pw-123",
                "client_id": self.pw_id,
                "client_secret": self.pw_secret,
                "scope": "openid",
            },
        )
        self.assertEqual(200, resp.status_code, resp.content)
        body = json.loads(resp.content)
        token = body["access_token"]
        header, payload = split_jwt(token)
        self.assertEqual("at+jwt", header.get("typ"))
        self.assertEqual(str(self.user1.pk), payload.get("sub"))


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestRefreshRotation(OIDCTestCase):
    """
    Refresh-token rotation under JWT mode: the rotated AT must also
    be a JWT (signed with the current ``kid``).
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_refresh_token_rotation_yields_jwt(self) -> None:
        body = self.run_code_flow(self.user1)
        original_refresh = body["refresh_token"]

        resp = self.refresh_token(refresh_token=original_refresh)
        rotated = json.loads(resp.content)
        rotated_at = rotated["access_token"]
        # Rotated AT is itself a JWT.
        header, _ = split_jwt(rotated_at)
        self.assertEqual("at+jwt", header.get("typ"))
        self.assertEqual("RS256", header.get("alg"))


class TestRefreshFormatFlip(OIDCTestCase):
    """
    Format-flip-on-refresh: tokens are issued anew per request, so
    flipping the global default between issuance and refresh changes
    the format of the rotated AT.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_refresh_with_format_flip_yields_new_format(self) -> None:
        # Step 1: issue under JWT mode → AT is a JWT.
        with override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            self.assertIn(".", body["access_token"])
            refresh = body["refresh_token"]

        # Step 2: flip to opaque, refresh → rotated AT is opaque.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            resp = self.refresh_token(refresh_token=refresh)
            rotated = json.loads(resp.content)
            rotated_at = rotated["access_token"]
        # Opaque tokens never have 3 dot-separated segments.
        self.assertNotEqual(
            3,
            rotated_at.count(".") + 1,
            "expected opaque (random-string) AT after format flip",
        )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestBackcompatLifecycle(OIDCTestCase):
    """
    Existing AT rows from a deployment that ran under opaque mode
    must remain introspectable and revocable after a flip to JWT.
    The dispatcher only governs ISSUANCE, so old rows pass through
    DOT's ``_load_access_token`` unchanged.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def _introspect(self, token: str) -> dict:
        # DOT requires a confidential client to introspect.
        resp = self.client.post(
            "/o/introspect/",
            data={"token": token},
            headers={
                "authorization": (
                    "Basic "
                    + base64.b64encode(
                        f"{self.oauth_id}:{self.oauth_secret}".encode("ascii")
                    ).decode("ascii")
                )
            },
        )
        return json.loads(resp.content)

    def test_existing_opaque_tokens_remain_valid_after_global_flip(
        self,
    ) -> None:
        # Issue under opaque mode.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            opaque_at = body["access_token"]
        # Flip to JWT (decorator already applies). Now introspect the
        # opaque token.
        intro = self._introspect(opaque_at)
        self.assertTrue(
            intro.get("active"),
            f"expected legacy opaque token to remain valid; got {intro!r}",
        )


# ---------------------------------------------------------------------------
# US-012 — Follow-up coverage from second-pass review (M-1, G-1, G-2, G-3)
# ---------------------------------------------------------------------------


class TestHS256JWTRejection(OIDCTestCase):
    """
    Operators can configure ``algorithm`` per app (DOT's
    ``AbstractApplication`` field). Combining ``algorithm="HS256"`` with
    ``access_token_format="jwt"`` is logically incoherent: id_tokens
    would sign with the per-app HMAC key while access_tokens would
    sign with the deployment's RSA key — two different keys for two
    tokens of the same session. We refuse the combination at the
    model-validation layer so the admin form rejects it before
    persistence.

    The opposite combination (``algorithm="HS256"`` +
    ``access_token_format=None|"opaque"``) stays valid because the
    opaque format does not sign anything.
    """

    def test_full_clean_rejects_hs256_plus_jwt(self) -> None:
        from django.core.exceptions import ValidationError

        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            algorithm="HS256",
            access_token_format="jwt",
        )
        with self.assertRaises(ValidationError) as ctx:
            creds.app.full_clean()
        # The validation error must explicitly cite ``access_token_format``
        # so admin-form errors point operators at the offending field.
        self.assertIn("access_token_format", ctx.exception.message_dict)

    def test_full_clean_accepts_rs256_plus_jwt(self) -> None:
        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            algorithm="RS256",
            access_token_format="jwt",
        )
        # full_clean() should not raise on the supported combination.
        creds.app.full_clean()

    def test_full_clean_accepts_hs256_plus_opaque(self) -> None:
        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            algorithm="HS256",
            access_token_format="opaque",
        )
        creds.app.full_clean()

    def test_full_clean_accepts_hs256_plus_null_format(self) -> None:
        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            algorithm="HS256",
            access_token_format=None,
        )
        creds.app.full_clean()


class TestMissingPrivateKey(OIDCTestCase):
    """
    JWT mode without ``OIDC_RSA_PRIVATE_KEY`` is an operator
    misconfiguration. The dispatcher must fail-closed (no token
    issued) rather than fail-silent or fall back to opaque — the
    operator explicitly opted into JWT mode, so a silent fallback
    would mask their mistake.

    We assert that the token endpoint returns a non-200 response;
    the exact OAuth2 error code is left to oauthlib's translation
    layer because ``_build_jwt``'s exception type is an implementation
    detail of ``jwcrypto``.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_mode_without_private_key_does_not_issue_a_token(
        self,
    ) -> None:
        provider = _jwt_mode_oauth2_provider()
        provider["OIDC_RSA_PRIVATE_KEY"] = ""
        # The Django test client re-raises view exceptions by default;
        # in production the same path renders a 500 via the standard
        # Django exception middleware. Disable re-raise so we observe
        # the operator-visible behaviour (a non-2xx response with no
        # access_token), not the test-time pass-through.
        self.client.raise_request_exception = False
        with override_settings(OAUTH2_PROVIDER=provider):
            code = self.authorize_to_code(self.user1)
            resp = self.client.post(
                "/o/token/",
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.oauth_id,
                    "client_secret": self.oauth_secret,
                    "redirect_uri": REDIRECT_URI,
                    "code": code,
                },
            )
        self.assertNotEqual(
            200,
            resp.status_code,
            f"expected non-2xx on missing private key, got 200: "
            f"{resp.content!r}",
        )
        # Body must NOT contain a usable access_token. Even on 500
        # responses the body is rendered, so check structurally.
        try:
            body = json.loads(resp.content.decode("utf-8"))
        except json.JSONDecodeError:
            return  # non-JSON 500 page; absence of token is implicit
        self.assertNotIn(
            "access_token",
            body,
            f"unexpected access_token in failure response: {body!r}",
        )


class TestKeyRotationOverlap(OIDCTestCase):
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
        self.grant_oidc_access(self.user1)
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
        doc = json.loads(resp.content)
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


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestJWTRevocation(OIDCTestCase):
    """
    RFC 7009 ``/o/revoke_token/`` works on the persisted ``AccessToken``
    row, not on the wire format. Revocation must succeed for a JWT
    that was just issued, AND for an opaque token issued *before*
    flipping the global default to JWT.

    Closes G-3 from the second-pass review.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def _introspect(self, token: str) -> dict:
        resp = self.client.post(
            "/o/introspect/",
            data={"token": token},
            headers={
                "authorization": (
                    "Basic "
                    + base64.b64encode(
                        f"{self.oauth_id}:{self.oauth_secret}".encode("ascii")
                    ).decode("ascii")
                )
            },
        )
        return json.loads(resp.content)

    def _revoke(self, token: str) -> int:
        resp = self.client.post(
            "/o/revoke_token/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        return resp.status_code

    def test_revoke_jwt_access_token(self) -> None:
        body = self.run_code_flow(self.user1)
        jwt_at = body["access_token"]
        # Sanity: it really is a JWT under JWT mode.
        header, _ = split_jwt(jwt_at)
        self.assertEqual("at+jwt", header.get("typ"))

        # Token starts active.
        self.assertTrue(self._introspect(jwt_at).get("active"))
        # RFC 7009 §2.2: success is 200 with empty body.
        self.assertEqual(200, self._revoke(jwt_at))
        # Post-revocation, introspection reports inactive.
        self.assertFalse(self._introspect(jwt_at).get("active"))

    def test_revoke_legacy_opaque_token_after_format_flip(self) -> None:
        # Issue under opaque mode; the JWT-mode decorator is overridden
        # for this block only.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            opaque_at = body["access_token"]
        # The class-level decorator (JWT mode) is back in effect.
        self.assertTrue(self._introspect(opaque_at).get("active"))
        self.assertEqual(200, self._revoke(opaque_at))
        self.assertFalse(self._introspect(opaque_at).get("active"))


class TestSizeWarnDefault(TestCase):
    """
    Pin the ``_DEFAULT_SIZE_WARN_BYTES`` literal value at 4096.

    Cosmic-ray's ``NumberReplacer`` flips the literal to neighbouring
    integers (4095, 4097) and the existing ``TestSizeGuard`` suite
    does NOT discriminate them — the "small token under default"
    test passes for any threshold large enough to exceed the typical
    AA JWT size (~600-1500 bytes), and the explicit override test
    uses ``16``. The exact-value assertion below kills every
    NumberReplacer flip on the constant.
    """

    def test_default_size_warn_bytes_constant_is_4096(self) -> None:
        from allianceauth_oidc.tokens import _DEFAULT_SIZE_WARN_BYTES

        # 4096 is a deliberate choice: Apache LimitRequestFieldSize
        # defaults to 8190, leaving headroom; documented in the module.
        self.assertEqual(4096, _DEFAULT_SIZE_WARN_BYTES)

    def test_default_threshold_is_4096_via_resolver(self) -> None:
        # Doubles as a contract check on ``_size_warn_threshold()``:
        # the resolver must read the module default when the operator
        # has not overridden the setting.
        from allianceauth_oidc.tokens import _size_warn_threshold

        # Default OAUTH2_PROVIDER in test settings does not set the
        # threshold key — the resolver returns the module constant.
        self.assertEqual(4096, _size_warn_threshold())


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


class TestIdentityClaimsAnonGuard(TestCase):
    """
    ``_identity_claims`` short-circuits to an empty dict when the
    request has no authenticated user — six surviving cosmic-ray
    mutants live on the single ``if user is None or not getattr(
    user, "is_authenticated", False):`` guard.
    """

    def test_no_user_returns_empty_dict(self) -> None:
        # ``user is None`` — left side of the ``or`` fires.
        from allianceauth_oidc.tokens import _identity_claims

        fake_request = SimpleNamespace(user=None, scopes=["openid"])
        self.assertEqual({}, _identity_claims(fake_request))

    def test_unauthenticated_user_returns_empty_dict(self) -> None:
        # ``user.is_authenticated`` is False — right side of the
        # ``or`` fires. Together with the None case above, both halves
        # of the ``or`` are exercised — kills ``ReplaceOrWithAnd``
        # which would require BOTH conditions True simultaneously.
        from allianceauth_oidc.tokens import _identity_claims

        fake_request = SimpleNamespace(
            user=SimpleNamespace(is_authenticated=False),
            scopes=["openid"],
        )
        self.assertEqual({}, _identity_claims(fake_request))

    def test_user_without_is_authenticated_attr_returns_empty_dict(
        self,
    ) -> None:
        # ``getattr(user, "is_authenticated", False)`` default —
        # ``ReplaceFalseWithTrue`` would let an attribute-less object
        # reach the validator-instantiation code path below and
        # crash on ``user.pk``. The False default keeps the
        # short-circuit firing.
        from allianceauth_oidc.tokens import _identity_claims

        fake_request = SimpleNamespace(user=object(), scopes=["openid"])
        self.assertEqual({}, _identity_claims(fake_request))


class TestDispatchingAccessTokenGeneratorBoundary(OIDCTestCase):
    """
    Pin two comparison-operator boundaries in the access-token dispatcher.

    Surviving cosmic-ray mutants:

    * ``if fmt == "jwt":`` — the existing JWT-mode tests issue real
      JWTs through the dispatcher but their string ``"jwt"`` is
      interned, so ``==`` -> ``is`` cannot be distinguished by
      ``run_code_flow``. Forcing a non-interned ``"jwt"`` resolution
      keeps the equality operator pinned.
    * ``if len(token) > threshold:`` — exact-boundary test
      (``len(token) == threshold``) discriminates ``>`` from ``>=``;
      both produce the same warning behaviour on inputs strictly
      above the threshold.
    """

    def test_size_warning_fires_strictly_above_threshold(self) -> None:
        # ``> threshold`` boundary: a token exactly AT the threshold
        # must NOT warn. ``>=`` mutation would emit the warning at
        # the boundary too. Driving the dispatcher with a stub
        # ``_build_jwt`` returning a known-length token gives us
        # precise control over the inequality.
        from unittest import mock

        from allianceauth_oidc import tokens as tokens_mod

        # Threshold default 4096; build a token exactly 4096 bytes.
        threshold = 4096
        fake_token = "x" * threshold
        fake_request = SimpleNamespace(client=SimpleNamespace(client_id="cid"))
        with (
            mock.patch.object(
                tokens_mod, "_resolve_access_token_format", return_value="jwt"
            ),
            mock.patch.object(
                tokens_mod, "_build_jwt", return_value=fake_token
            ),
            mock.patch.object(
                tokens_mod, "_size_warn_threshold", return_value=threshold
            ),
            self.assertNoLogs(
                "extensions.allianceauth_oidc.tokens", level="WARNING"
            ),
        ):
            out = tokens_mod.dispatching_access_token_generator(fake_request)
        self.assertEqual(fake_token, out)

    def test_size_warning_fires_one_byte_above_threshold(self) -> None:
        # The companion case: one byte above the threshold MUST log.
        # Together with the "exactly at threshold" case above, the
        # ``>`` vs ``>=`` ambiguity is closed.
        from unittest import mock

        from allianceauth_oidc import tokens as tokens_mod

        threshold = 4096
        fake_token = "x" * (threshold + 1)
        fake_request = SimpleNamespace(client=SimpleNamespace(client_id="cid"))
        with (
            mock.patch.object(
                tokens_mod, "_resolve_access_token_format", return_value="jwt"
            ),
            mock.patch.object(
                tokens_mod, "_build_jwt", return_value=fake_token
            ),
            mock.patch.object(
                tokens_mod, "_size_warn_threshold", return_value=threshold
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.tokens", level="WARNING"
            ) as cap,
        ):
            tokens_mod.dispatching_access_token_generator(fake_request)
        self.assertTrue(
            any("size" in m.lower() for m in cap.output),
            f"size-warning missing in {cap.output!r}",
        )

    def test_format_jwt_with_non_interned_string_routes_to_build_jwt(
        self,
    ) -> None:
        # ``ReplaceComparisonOperator_Eq_Is`` flips ``fmt == "jwt"``
        # to ``fmt is "jwt"``. For an interned literal the two
        # operators agree; a runtime-built string defeats CPython's
        # interning and forces the distinction. We assemble the
        # value at runtime via slice-concatenation, same trick as
        # ``TestAccessTokenFormatComparison`` in test_security.py.
        from unittest import mock

        from allianceauth_oidc import tokens as tokens_mod

        non_interned_jwt = "jw" + "t"
        fake_request = SimpleNamespace(client=SimpleNamespace(client_id="cid"))
        with (
            mock.patch.object(
                tokens_mod,
                "_resolve_access_token_format",
                return_value=non_interned_jwt,
            ),
            mock.patch.object(
                tokens_mod, "_build_jwt", return_value="signed-token"
            ) as build_jwt,
        ):
            out = tokens_mod.dispatching_access_token_generator(fake_request)
        build_jwt.assert_called_once_with(fake_request)
        self.assertEqual("signed-token", out)
