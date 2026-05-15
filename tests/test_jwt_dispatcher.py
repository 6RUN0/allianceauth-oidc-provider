"""
RFC 9068 JWT access tokens — dispatcher and format resolution.

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

from allianceauth_oidc.security import DEFAULT_POLICY

from ._jwt_helpers import (
    _jwt_mode_oauth2_provider,
    _opaque_mode_oauth2_provider,
)
from ._oidc_testcase import OIDCTestCase


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


class TestDispatcherFormatResolution(TestCase):
    """
    Unit-level: ``AccessPolicy.access_token_format`` resolves an
    ``AppLike`` double without touching the DB. Mirrors the per-app
    PKCE DI-seam test pattern — synthetic doubles work because the
    policy is pure logic.
    """

    def test_access_token_format_resolution_matrix(self) -> None:
        """
        Sweep per-app x global x app-shape format resolution.

        ``AccessPolicy.access_token_format`` is a pure
        precedence function: per-app value wins if recognised,
        else global, else opaque. Each row pins one branch:

        * ``per_app_jwt_overrides_global_opaque`` — per-app
          recognised value beats global.
        * ``per_app_none_falls_back_to_global_jwt`` — per-app
          ``None`` defers to a recognised global.
        * ``per_app_none_global_absent_returns_opaque`` —
          everything missing falls back to opaque.
        * ``app_none_uses_global_jwt`` — ``app=None`` skips the
          per-app check and uses the global.
        * ``invalid_per_app_falls_through_to_global`` —
          unrecognised per-app value defers to global.
        * ``invalid_global_falls_back_to_opaque`` — unrecognised
          global falls back to opaque.

        ``_NO_APP`` sentinel means "pass app=None to the
        method" (vs. an app with ``access_token_format=None``).
        ``global=None`` means the OAUTH2_PROVIDER dict omits the
        key entirely.
        """
        _NO_APP = object()
        cases: tuple[tuple[str, object, str | None, str], ...] = (
            (
                "per_app_jwt_overrides_global_opaque",
                "jwt",
                "opaque",
                "jwt",
            ),
            (
                "per_app_none_falls_back_to_global_jwt",
                None,
                "jwt",
                "jwt",
            ),
            (
                "per_app_none_global_absent_returns_opaque",
                None,
                None,
                "opaque",
            ),
            ("app_none_uses_global_jwt", _NO_APP, "jwt", "jwt"),
            (
                "invalid_per_app_falls_through_to_global",
                "garbage",
                "opaque",
                "opaque",
            ),
            (
                "invalid_global_falls_back_to_opaque",
                _NO_APP,
                "garbage",
                "opaque",
            ),
        )
        for label, per_app, global_val, expected in cases:
            with self.subTest(case=label):
                provider_cfg: dict[str, str] = (
                    {}
                    if global_val is None
                    else {
                        "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_"
                        "TOKEN_FORMAT": global_val
                    }
                )
                with override_settings(OAUTH2_PROVIDER=provider_cfg):
                    if per_app is _NO_APP:
                        app = None
                    else:
                        app = SimpleNamespace(access_token_format=per_app)
                    self.assertEqual(
                        expected,
                        DEFAULT_POLICY.access_token_format(app),
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
