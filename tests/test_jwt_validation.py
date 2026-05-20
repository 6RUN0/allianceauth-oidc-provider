"""
RFC 9068 JWT access tokens — validation: HS256 rejection, missing key, startup wiring.

Sibling concerns live in test_jwt_shape.py, test_jwt_dispatcher.py,
test_jwt_grants.py, and test_jwt_validation.py. Shared helpers
(split_jwt / mode-switch dicts / lookalike generator) live in
tests/_jwt_helpers.py.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any

from django.conf import settings as django_settings
from django.test import TestCase, override_settings

from ._jwt_helpers import (
    _jwt_mode_oauth2_provider,
)
from ._oidc_testcase import REDIRECT_URI, GrantedOIDCTestCase


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
                "tests._jwt_helpers.lookalike_access_token_generator"
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


class TestHS256JWTRejection(GrantedOIDCTestCase):
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


class TestMissingPrivateKey(GrantedOIDCTestCase):
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
            body = self.json_body(resp, expected_status=None)
        except json.JSONDecodeError:
            return  # non-JSON 500 page; absence of token is implicit
        self.assertNotIn(
            "access_token",
            body,
            f"unexpected access_token in failure response: {body!r}",
        )


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
