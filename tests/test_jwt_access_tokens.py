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

from ._oidc_testcase import SCOPE_FULL, OIDCTestCase

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

        jwks_resp = self.client.get(
            "/o/.well-known/jwks.json"
        )
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
        self.addCleanup(
            oidc_token_issued.disconnect, capture
        )

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
            self.assertEqual(
                "opaque", DEFAULT_POLICY.access_token_format(app)
            )

    def test_app_is_none_uses_global(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
            }
        ):
            self.assertEqual(
                "jwt", DEFAULT_POLICY.access_token_format(None)
            )

    def test_invalid_per_app_value_falls_through_to_global(self) -> None:
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "opaque",
            }
        ):
            app = SimpleNamespace(access_token_format="garbage")
            self.assertEqual(
                "opaque", DEFAULT_POLICY.access_token_format(app)
            )

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
# Helper-tests: keep ``_classify_token_format`` / ``split_jwt`` honest.
# These guard the test infrastructure itself; if either drifts, every
# JWT test in this file silently regresses.
# ---------------------------------------------------------------------------


class TestSplitJWTHelper(TestCase):
    """Smoke tests for the ``split_jwt`` helper used by other tests."""

    def test_three_segment_input_decodes(self) -> None:
        # Pre-encoded ``{"typ":"at+jwt","alg":"RS256"}`` header
        # paired with ``{"sub":"u"}`` payload and a placeholder
        # signature segment.
        header_seg = (
            base64.urlsafe_b64encode(
                b'{"typ":"at+jwt","alg":"RS256"}'
            ).rstrip(b"=").decode()
        )
        payload_seg = (
            base64.urlsafe_b64encode(b'{"sub":"u"}')
            .rstrip(b"=")
            .decode()
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
    EXPECTED = (
        "allianceauth_oidc.tokens.dispatching_access_token_generator"
    )

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
        return [
            line for line in captured.output if line.startswith("WARNING")
        ]

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
            HTTP_AUTHORIZATION=(
                "Basic "
                + base64.b64encode(
                    f"{self.oauth_id}:{self.oauth_secret}".encode("ascii")
                ).decode("ascii")
            ),
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
