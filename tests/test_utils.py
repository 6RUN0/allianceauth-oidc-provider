"""
Unit tests for `allianceauth_oidc.utils` — the secret-masking and debug-meta
helpers used by the audit/log paths.

These are pure functions; tests don't need the OIDCTestCase fixture
or a database. Kept in the same `tests/` directory so the suite stays
discoverable by ``django test tests``.
"""

import logging
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings

from allianceauth_oidc.utils import (
    app_log,
    build_oidc_debug_meta,
    mask_secret,
    redact_secret,
)


class TestMaskSecret(SimpleTestCase):
    def test_none_returns_none(self):
        self.assertIsNone(mask_secret(None))

    def test_empty_string_returns_empty(self):
        self.assertEqual("", mask_secret(""))

    def test_short_string_fully_masked(self):
        # head + tail >= len(value) → all characters become '*'.
        self.assertEqual("***", mask_secret("abc"))
        self.assertEqual("****", mask_secret("abcd"))

    def test_long_string_shows_head_and_tail(self):
        self.assertEqual("ab…yz", mask_secret("abcdefxyyz"))

    def test_custom_head_tail(self):
        self.assertEqual("a…z", mask_secret("abcdefxyz", head=1, tail=1))
        self.assertEqual("abc…xyz", mask_secret("abcdefghxyz", head=3, tail=3))

    def test_zero_head_tail_returns_ellipsis(self):
        self.assertEqual("...", mask_secret("abcdef", head=0, tail=0))

    def test_negative_head_tail_clamped_to_zero(self):
        # Defensive: caller passes a negative head/tail, treat as 0.
        self.assertEqual("...", mask_secret("abcdef", head=-3, tail=-3))

    def test_bytes_input_decoded(self):
        self.assertEqual("ab…yz", mask_secret(b"abcdefxyyz"))

    def test_bytes_with_non_utf8_replaced(self):
        # `errors="replace"` substitutes invalid bytes with U+FFFD.
        self.assertIn("…", mask_secret(b"\xff\xfeabcdef\xff\xfe"))

    def test_non_string_returns_typed_marker(self):
        # Defensive path: int/float/dict shouldn't crash, get a marker.
        self.assertEqual("<non-string:int>", mask_secret(42))
        self.assertEqual("<non-string:dict>", mask_secret({"a": 1}))


class TestRedactSecret(SimpleTestCase):
    def test_none_returns_none(self):
        self.assertIsNone(redact_secret(None))

    def test_default_returns_redacted_marker(self):
        # `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS` is False by default.
        self.assertEqual("<redacted>", redact_secret("super-secret"))
        self.assertEqual("<redacted>", redact_secret(b"bytes-secret"))

    @override_settings(ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True)
    def test_masked_mode_uses_mask_secret(self):
        # Settings flag is read at app_settings.py import; force a reimport
        # of the module-level constant to take the override into account.
        import importlib

        import allianceauth_oidc.app_settings as app_settings
        import allianceauth_oidc.utils as utils

        importlib.reload(app_settings)
        importlib.reload(utils)
        try:
            self.assertEqual("su…et", utils.redact_secret("super-secret"))
        finally:
            # Reload back so other tests see the default again.
            importlib.reload(app_settings)
            importlib.reload(utils)


class TestBuildOidcDebugMeta(SimpleTestCase):
    def _request(self, post: dict | None = None) -> SimpleNamespace:
        return SimpleNamespace(POST=post)

    def test_request_without_post_yields_all_none_request_fields(self):
        meta = build_oidc_debug_meta(self._request(post=None), payload=None)
        # Request-side fields all None.
        for key in (
            "grant_type",
            "scope",
            "client_id",
            "redirect_uri",
            "code",
            "refresh_token_req",
            "client_secret",
            "assertion",
        ):
            with self.subTest(key=key):
                self.assertIsNone(meta[key])
        # Response-side fields also None when payload is None.
        for key in (
            "token_type",
            "expires_in",
            "scope_resp",
            "access_token",
            "refresh_token",
            "id_token",
        ):
            with self.subTest(key=key):
                self.assertIsNone(meta[key])

    def test_post_object_without_callable_get_yields_none(self):
        # Defensive path: request.POST is some odd object without .get().
        request = self._request(post=object())
        meta = build_oidc_debug_meta(request, payload=None)
        self.assertIsNone(meta["grant_type"])
        self.assertIsNone(meta["scope"])

    def test_safe_request_fields_pass_through(self):
        request = self._request(
            post={
                "grant_type": "authorization_code",
                "scope": "openid email",
                "client_id": "client-xyz",
                "redirect_uri": "http://localhost/redir/",
            }
        )
        meta = build_oidc_debug_meta(request, payload=None)
        self.assertEqual("authorization_code", meta["grant_type"])
        self.assertEqual("openid email", meta["scope"])
        self.assertEqual("client-xyz", meta["client_id"])
        self.assertEqual("http://localhost/redir/", meta["redirect_uri"])

    def test_secret_request_fields_are_redacted(self):
        request = self._request(
            post={
                "code": "raw-code-value",
                "refresh_token": "raw-refresh-value",
                "client_secret": "raw-client-secret",
                "assertion": "raw-assertion",
            }
        )
        meta = build_oidc_debug_meta(request, payload=None)
        self.assertEqual("<redacted>", meta["code"])
        self.assertEqual("<redacted>", meta["refresh_token_req"])
        self.assertEqual("<redacted>", meta["client_secret"])
        self.assertEqual("<redacted>", meta["assertion"])

    def test_payload_response_tokens_are_redacted(self):
        meta = build_oidc_debug_meta(
            self._request(post={}),
            payload={
                "token_type": "Bearer",
                "expires_in": 60,
                "scope": "openid",
                "access_token": "AT-XXXX",
                "refresh_token": "RT-YYYY",
                "id_token": "eyJ.payload.sig",
            },
        )
        self.assertEqual("Bearer", meta["token_type"])
        self.assertEqual(60, meta["expires_in"])
        self.assertEqual("openid", meta["scope_resp"])
        self.assertEqual("<redacted>", meta["access_token"])
        self.assertEqual("<redacted>", meta["refresh_token"])
        self.assertEqual("<redacted>", meta["id_token"])

    def test_returned_dict_never_contains_raw_secret_strings(self):
        """End-to-end invariant: no raw secret value should appear as a
        substring of any dict value the helper returns.
        """
        secrets = {
            "code": "code-AAAA",
            "refresh_token": "refresh-BBBB",
            "client_secret": "secret-CCCC",
            "assertion": "assertion-DDDD",
        }
        request = self._request(post=secrets)
        meta = build_oidc_debug_meta(
            request,
            payload={
                "access_token": "at-EEEE",
                "refresh_token": "rt-FFFF",
                "id_token": "id-GGGG",
            },
        )
        haystack = " ".join(v for v in meta.values() if isinstance(v, str))
        for raw in (
            *secrets.values(),
            "at-EEEE",
            "rt-FFFF",
            "id-GGGG",
        ):
            with self.subTest(raw=raw):
                self.assertNotIn(raw, haystack)


class TestAppLog(SimpleTestCase):
    def test_logs_at_debug_level_when_debug_mode_off(self):
        app = SimpleNamespace(debug_mode=False)
        logger = logging.getLogger("test.app_log.debug")
        with self.assertLogs(logger, level="DEBUG") as cm:
            app_log(logger, app, "msg %s", "arg")
        self.assertEqual(1, len(cm.records))
        self.assertEqual(logging.DEBUG, cm.records[0].levelno)
        self.assertEqual("msg arg", cm.records[0].getMessage())

    def test_logs_at_info_level_when_debug_mode_on(self):
        app = SimpleNamespace(debug_mode=True)
        logger = logging.getLogger("test.app_log.info")
        with self.assertLogs(logger, level="INFO") as cm:
            app_log(logger, app, "msg %s", "arg")
        self.assertEqual(1, len(cm.records))
        self.assertEqual(logging.INFO, cm.records[0].levelno)

    def test_app_without_debug_mode_attribute_defaults_to_debug(self):
        # Defensive path: getattr(app, "debug_mode", False) returns False.
        logger = logging.getLogger("test.app_log.no_attr")
        with self.assertLogs(logger, level="DEBUG") as cm:
            app_log(logger, object(), "msg")
        self.assertEqual(logging.DEBUG, cm.records[0].levelno)
