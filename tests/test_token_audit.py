"""
Unit tests for ``allianceauth_oidc.views.TokenAudit``.

These exercise the audit pipeline below the HTTP layer:
``parse_body`` / ``_body_byte_length`` are pure and run as
``SimpleTestCase``; ``emit`` integration coverage stays in
``test_signals`` (HTTP-level) and ``test_logging`` (debug-mode log
assertions). This file is the table-driven complement.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from allianceauth_oidc.views import (
    _DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE,
    TokenAudit,
)


def _audit(body: object, *, max_body_bytes: int | None = None) -> TokenAudit:
    """
    Construct a ``TokenAudit`` for a parser-only test.

    ``request`` and ``sender`` are stubbed because ``parse_body`` /
    ``_body_byte_length`` never touch them. ``max_body_bytes`` defaults
    to the module constant so callers can opt into a tighter cap for
    size-cap tests.
    """
    return TokenAudit(
        request=SimpleNamespace(),  # type: ignore[arg-type]
        body=body,
        sender=type("StubSender", (), {}),
        max_body_bytes=(
            max_body_bytes
            if max_body_bytes is not None
            else _DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE
        ),
    )


class TestBodyByteLength(SimpleTestCase):
    def test_str_returns_utf8_byte_count(self):
        # Multi-byte char must count as its UTF-8 length, not 1
        # code-point — the size-cap is meant to be byte-accurate.
        self.assertEqual(2, TokenAudit._body_byte_length("ab"))
        self.assertEqual(2, TokenAudit._body_byte_length("é"))  # 2 bytes
        self.assertEqual(3, TokenAudit._body_byte_length("€"))  # 3 bytes

    def test_bytes_returns_len(self):
        self.assertEqual(5, TokenAudit._body_byte_length(b"abcde"))

    def test_object_with_len_returns_len(self):
        # Some oauthlib bodies can be a ``bytearray`` or a custom
        # buffer-shaped object — ``__len__`` is the contract.
        self.assertEqual(3, TokenAudit._body_byte_length(bytearray(b"xyz")))

    def test_unmeasurable_returns_none(self):
        # An object without ``__len__`` (and not str/bytes) skips the
        # cap entirely; parser path still parses optimistically.
        self.assertIsNone(TokenAudit._body_byte_length(object()))


class TestParseBody(SimpleTestCase):
    def test_empty_body_returns_none(self):
        self.assertIsNone(_audit(None).parse_body())
        self.assertIsNone(_audit("").parse_body())
        self.assertIsNone(_audit(b"").parse_body())

    def test_oversized_body_logged_and_skipped(self):
        # Force the cap below the body size; parse_body must log a
        # warning and return None instead of attempting json.loads.
        body = '{"access_token":"' + "a" * 200 + '"}'
        audit = _audit(body, max_body_bytes=10)
        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="WARNING"
        ) as cap:
            self.assertIsNone(audit.parse_body())
        self.assertTrue(
            any("over 10-byte cap" in m for m in cap.output),
            f"missing cap-warning in {cap.output!r}",
        )

    def test_invalid_json_logged_and_returns_none(self):
        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="ERROR"
        ) as cap:
            self.assertIsNone(_audit("{not-json").parse_body())
        self.assertTrue(
            any("not valid JSON" in m for m in cap.output),
            f"missing parse-error log in {cap.output!r}",
        )

    def test_non_dict_payload_returns_none(self):
        # Defence-in-depth: even valid JSON that's a list / string /
        # number is rejected because the rest of the pipeline calls
        # ``payload.get("access_token")``.
        self.assertIsNone(_audit("[1,2,3]").parse_body())
        self.assertIsNone(_audit('"oops"').parse_body())
        self.assertIsNone(_audit("42").parse_body())

    def test_dict_payload_returned_as_is(self):
        self.assertEqual(
            {"access_token": "tok", "scope": "openid"},
            _audit('{"access_token":"tok","scope":"openid"}').parse_body(),
        )

    def test_bytes_body_accepted(self):
        # ``json.loads`` accepts bytes since 3.6; the audit path must
        # not require pre-decoding.
        self.assertEqual(
            {"access_token": "abc"},
            _audit(b'{"access_token":"abc"}').parse_body(),
        )


class TestEmitShortCircuits(SimpleTestCase):
    """
    ``emit`` must short-circuit gracefully on every "no audit possible"
    branch — these tests cover the paths where ``parse_body`` returns
    None or ``access_token`` is missing, neither of which touches the
    DB. The DB-backed branches (token found / not found) are exercised
    via ``test_signals``.
    """

    def test_emit_returns_silently_on_unparseable_body(self):
        # Verifies the orchestrator skips the rest of the pipeline.
        # No DB lookup is attempted; if it were, the stub request
        # without ``.POST`` would crash later in the chain.
        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="ERROR"
        ):
            _audit("{garbage").emit()  # logs parse error, returns

    def test_emit_returns_silently_when_access_token_missing(self):
        # Valid JSON but no access_token field — orchestrator stops
        # before touching the DB or the signal layer.
        _audit('{"scope":"openid"}').emit()  # no exception, no log
