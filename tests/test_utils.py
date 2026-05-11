"""
Unit tests for `allianceauth_oidc.utils` — the secret-masking and debug-meta
helpers used by the audit/log paths.

These are pure functions; tests don't need the OIDCTestCase fixture or a
database. Kept in the same `tests/` directory so the suite stays discoverable
by ``django test tests``.
"""

import logging
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings

from allianceauth_oidc.utils import (
    SecretRedactor,
    app_log,
    build_oidc_debug_meta,
)

# Local alias — keep the test bodies tight without losing the
# class-method origin in the import block.
mask = SecretRedactor.mask_secret


class TestMaskSecret(SimpleTestCase):
    def test_none_returns_none(self):
        self.assertIsNone(mask(None))

    def test_empty_string_returns_empty(self):
        self.assertEqual("", mask(""))

    def test_short_string_fully_masked(self):
        # head + tail >= len(value) → all characters become '*'.
        self.assertEqual("***", mask("abc"))
        self.assertEqual("****", mask("abcd"))

    def test_long_string_shows_head_and_tail(self):
        self.assertEqual("ab…yz", mask("abcdefxyyz"))

    def test_custom_head_tail(self):
        self.assertEqual("a…z", mask("abcdefxyz", head=1, tail=1))
        self.assertEqual("abc…xyz", mask("abcdefghxyz", head=3, tail=3))

    def test_zero_head_tail_returns_ellipsis(self):
        self.assertEqual("...", mask("abcdef", head=0, tail=0))

    def test_negative_head_tail_clamped_to_zero(self):
        # Defensive: caller passes a negative head/tail, treat as 0.
        self.assertEqual("...", mask("abcdef", head=-3, tail=-3))

    def test_bytes_input_decoded(self):
        self.assertEqual("ab…yz", mask(b"abcdefxyyz"))

    def test_bytes_with_non_utf8_replaced(self):
        # `errors="replace"` substitutes invalid bytes with U+FFFD.
        self.assertIn("…", mask(b"\xff\xfeabcdef\xff\xfe"))

    def test_non_string_returns_typed_marker(self):
        # Defensive path: int/float/dict shouldn't crash, get a marker.
        self.assertEqual("<non-string:int>", mask(42))
        self.assertEqual("<non-string:dict>", mask({"a": 1}))


class TestSecretRedactorCall(SimpleTestCase):
    """
    Cover ``SecretRedactor.__call__`` end-to-end: ``None`` passthrough,
    the disabled-mode ``"<redacted>"`` marker, the enabled-mode
    masking dispatch, and ``from_django()`` + ``@override_settings``
    integration.
    """

    def test_none_returns_none(self):
        self.assertIsNone(SecretRedactor.from_django()(None))

    def test_default_returns_redacted_marker(self):
        # ``ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS`` is False by default,
        # so neither length nor prefixes/suffixes leak.
        redactor = SecretRedactor.from_django()
        self.assertEqual("<redacted>", redactor("super-secret"))
        self.assertEqual("<redacted>", redactor(b"bytes-secret"))

    @override_settings(ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True)
    def test_masked_mode_uses_mask_secret(self):
        # ``@override_settings`` triggers ``setting_changed`` →
        # ``OIDCSettings`` cache cleared → ``from_django()`` returns a
        # fresh redactor that honours the override.
        self.assertEqual("su…et", SecretRedactor.from_django()("super-secret"))

    @override_settings(
        ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True,
        ALLIANCEAUTH_OIDC_LOG_MASK_HEAD=1,
        ALLIANCEAUTH_OIDC_LOG_MASK_TAIL=3,
    )
    def test_masked_mode_honours_head_and_tail_overrides(self):
        self.assertEqual("s…ret", SecretRedactor.from_django()("super-secret"))

    def test_inline_construction_skips_settings(self):
        # The class is DI-friendly: tests can build a redactor without
        # @override_settings and assert directly on the result.
        self.assertEqual("su…et", SecretRedactor(enabled=True)("super-secret"))


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
        """
        End-to-end invariant: no raw secret value should appear as a
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


class TestSecretRedactorStructure(SimpleTestCase):
    """
    Pin the structural invariants of ``SecretRedactor``.

    ``@dataclass(frozen=True, slots=True)`` carries the same cosmic-
    ray survivor pattern as the AccessDecision dataclasses in
    ``security.py``: existing tests exercise ``__call__`` but never
    pin the constructor-set guarantees. ``ReplaceFalseWithTrue`` on
    the ``enabled: bool = False`` default would silently turn
    ``SecretRedactor()`` (no args) into a leak-by-default redactor.
    """

    def test_default_enabled_is_false(self):
        # The redact-by-default invariant: a zero-arg redactor MUST
        # treat secrets as opaque (``<redacted>`` marker), never
        # leak prefix/suffix.
        redactor = SecretRedactor()
        self.assertFalse(redactor.enabled)
        # Re-assert via behaviour: a real secret resolves to the
        # opaque marker, not a masked prefix.
        self.assertEqual("<redacted>", str(redactor("super-secret")))

    def test_is_frozen(self):
        # ``frozen=True``: instance fields cannot be reassigned.
        # Removing the decorator (or flipping frozen=True) would
        # let downstream code mutate the redactor's settings
        # mid-request.
        from dataclasses import FrozenInstanceError

        redactor = SecretRedactor(enabled=True, head=2, tail=2)
        with self.assertRaises(FrozenInstanceError):
            redactor.enabled = False  # type: ignore[misc]

    def test_uses_slots(self):
        # ``slots=True``: no __dict__; an accidental attribute
        # assignment (caught above by frozen=True) cannot also
        # quietly shadow into a dict.
        self.assertFalse(hasattr(SecretRedactor(), "__dict__"))


class TestMaskSecretArithmeticBoundaries(SimpleTestCase):
    """
    Pin the arithmetic and boundary checks inside ``mask_secret``.

    Three groups of surviving mutants:

    * ``"*" * len(s)`` — ``Mul_Div`` flips the repetition. A short
      string falling into the "fully starred" branch and asserting
      the exact number of ``*`` distinguishes ``*`` from ``/`` /
      ``//`` etc.
    * ``head + tail == 0`` — both the ``+`` (Add_*) and the ``==``
      (Eq_LtE) survive. ``head=0, tail=0`` returns ``"..."``;
      ``head=1, tail=0`` does NOT.
    * ``len(s) <= head + tail`` — boundary discriminates ``+`` from
      multiplication when the values disagree (head=3, tail=2: 3+2=5
      vs 3*2=6). ``len=6`` is the input where they split.
    """

    def test_short_string_returns_exact_star_count(self):
        # ``"*" * 3`` -> ``"***"`` (3 chars). ``"*" / 3`` would
        # raise TypeError; ``"*" // 3`` would also fail. Either way
        # the string-multiply contract is pinned.
        self.assertEqual("***", mask("abc", head=2, tail=2))

    def test_short_string_with_length_one(self):
        # ``len=1``: with default head=tail=2, ``len <= head+tail``
        # is True; output is exactly one ``*``.
        self.assertEqual("*", mask("x", head=2, tail=2))

    def test_zero_head_zero_tail_returns_ellipsis(self):
        # ``head + tail == 0`` -> ellipsis. ``Add_*`` mutating ``+``
        # to ``*`` would also yield 0 here, so this case alone does
        # not distinguish. Pin via the companion below.
        self.assertEqual("...", mask("abcdef", head=0, tail=0))

    def test_zero_one_does_not_return_ellipsis(self):
        # ``head=0, tail=1``: ``+`` = 1, ``*`` = 0. Original branch
        # checks ``head+tail == 0`` (False) and falls through to
        # ``len(s) <= 1`` (False for ``"abcdef"``), then to the
        # formatted branch ``""+"…"+"f" = "…f"``. Mutated
        # ``head*tail = 0`` ⇒ ellipsis branch fires ⇒ ``"..."``.
        # The discriminator pins ``+`` against ``*`` on the zero
        # check. (``head=1, tail=0`` would surface the ``s[-0:]``
        # corner case that returns the full string — a separate
        # subtle behaviour, not what this test pins.)
        self.assertEqual("…f", mask("abcdef", head=0, tail=1))

    def test_len_greater_than_sum_uses_formatted_branch(self):
        # ``head=3, tail=2``: original ``head + tail`` = 5,
        # mutated ``head * tail`` = 6. For ``"abcdef"`` (len=6):
        #   original: 6 <= 5 False ⇒ formatted ``"abc…ef"``
        #   mutated:  6 <= 6 True  ⇒ ``"******"``
        # Length 6 is the only input that distinguishes ``+`` from
        # ``*`` on this guard.
        self.assertEqual("abc…ef", mask("abcdef", head=3, tail=2))


class TestBuildLogoutDebugMetaApplicationGuard(SimpleTestCase):
    """
    Pin the ``application is not None`` short-circuit in
    ``build_logout_debug_meta``.

    Three surviving mutants on the same line:
    * ``AddNot`` flips the guard and yields field values for
      ``application=None`` (AttributeError on ``getattr`` would
      surface).
    * ``IsNot_Is`` flips the comparison ⇒ same effect.

    Existing BCL tests always pass a real application — none cover
    the ``application is None`` arm of the conditional.
    """

    def test_application_none_yields_all_application_fields_none(self):
        from allianceauth_oidc.utils import build_logout_debug_meta

        meta = build_logout_debug_meta(
            application=None, jti="j-1", status_code=200, reason="success"
        )
        # The three application-derived fields collapse to None.
        self.assertIsNone(meta["application_pk"])
        self.assertIsNone(meta["application_name"])
        self.assertIsNone(meta["backchannel_logout_uri"])
        # Non-application fields stay untouched.
        self.assertEqual("j-1", meta["jti"])
        self.assertEqual(200, meta["status_code"])
        self.assertEqual("success", meta["reason"])

    def test_application_present_populates_fields(self):
        # Companion happy path: a real application shape resolves
        # each field. Together with the None case above, both arms
        # of the conditional are pinned.
        from allianceauth_oidc.utils import build_logout_debug_meta

        app_stub = SimpleNamespace(
            pk=42,
            name="acme",
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        meta = build_logout_debug_meta(
            application=app_stub, jti="j-2", status_code=404, reason="oops"
        )
        self.assertEqual(42, meta["application_pk"])
        self.assertEqual("acme", meta["application_name"])
        self.assertEqual(
            "https://rp.example.com/bcl", meta["backchannel_logout_uri"]
        )
