"""
Unit tests for ``allianceauth_oidc.views.TokenAudit``.

These exercise the audit pipeline below the HTTP layer:
``parse_body`` / ``_body_byte_length`` are pure and run as
``SimpleTestCase``; ``emit`` integration coverage stays in
``test_signals`` (HTTP-level) and ``test_logging`` (debug-mode log
assertions). This file is the table-driven complement.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from allianceauth_oidc.views import TokenAudit
from allianceauth_oidc.views_token import (
    _DEFAULT_MAX_BODY_BYTES_FOR_AUDIT_PARSE,
)


def _audit(
    body: str | bytes | None,
    *,
    max_body_bytes: int | None = None,
) -> TokenAudit:
    """
    Construct a ``TokenAudit`` for a parser-only test.

    ``request=None`` and a stub ``sender`` are fine because
    ``parse_body`` / ``_body_byte_length`` never touch them, and
    ``_log_debug`` / ``_dispatch_signal`` short-circuit when
    ``request is None`` — keeping parser-only tests free of an
    ``HttpRequest`` fixture.
    """
    return TokenAudit(
        request=None,
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
            "extensions.allianceauth_oidc.views_token", level="WARNING"
        ) as cap:
            self.assertIsNone(audit.parse_body())
        self.assertTrue(
            any("over 10-byte cap" in m for m in cap.output),
            f"missing cap-warning in {cap.output!r}",
        )

    def test_invalid_json_logged_and_returns_none(self):
        with self.assertLogs(
            "extensions.allianceauth_oidc.views_token", level="ERROR"
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

    def test_body_exactly_at_cap_is_parsed(self):
        # Pin ``>`` against ``>=`` on the size guard.
        #
        # ``parse_body`` skips parsing when
        # ``body_len > self.max_body_bytes``. The over-cap case
        # (``test_oversized_body_logged_and_skipped`` above) does
        # NOT distinguish ``>`` from ``>=`` because both are True
        # for ``200 >= 10``. The boundary case ``body_len ==
        # max_body_bytes`` is the discriminator: with ``>`` the
        # body is exactly at the limit (still parseable), with
        # ``>=`` the boundary is rejected.
        body = '{"access_token":"y"}'  # exactly 20 bytes
        cap = len(body.encode("utf-8"))
        audit = _audit(body, max_body_bytes=cap)
        parsed = audit.parse_body()
        self.assertEqual({"access_token": "y"}, parsed)


class TestLogDebugDefault(SimpleTestCase):
    """
    ``TokenAudit._log_debug`` reads ``app.debug_mode`` with a
    ``getattr(..., False)`` default. Flipping the default to
    ``True`` (cosmic-ray's ``ReplaceFalseWithTrue``) would silently
    enable the debug log line for every application that simply
    lacks the attribute. The test forces the function down the
    log-emit path on a stub application without ``debug_mode`` and
    asserts the log stayed silent.
    """

    def test_app_without_debug_mode_attr_does_not_emit(self):
        from types import SimpleNamespace

        # No ``debug_mode`` attribute — getattr returns the default
        # (False). The token shape only needs ``application`` /
        # ``user`` for the log line, neither of which is exercised
        # here because the short-circuit on ``not debug_mode``
        # returns before any field is read.
        token = SimpleNamespace(
            application=SimpleNamespace(),  # no debug_mode
            user=SimpleNamespace(id=1),
        )
        audit = _audit('{"access_token":"x"}')
        # ``request`` is None on parser-only audits; ``_log_debug``
        # short-circuits earlier on that, so feed a synthetic
        # request via a setattr that ``_log_debug`` will read.
        from django.test import RequestFactory

        audit.request = RequestFactory().post(
            "/o/token/", data={"grant_type": "authorization_code"}
        )
        with self.assertNoLogs(
            "extensions.allianceauth_oidc.views_token", level="INFO"
        ):
            audit._log_debug(token, {"access_token": "x"})


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
            "extensions.allianceauth_oidc.views_token", level="ERROR"
        ):
            _audit("{garbage").emit()  # logs parse error, returns

    def test_emit_returns_silently_when_access_token_missing(self):
        # Valid JSON but no access_token field — orchestrator stops
        # before touching the DB or the signal layer.
        _audit('{"scope":"openid"}').emit()  # no exception, no log


# Lazy DB-bound imports kept at module tail so the parser-only
# ``SimpleTestCase`` classes above stay self-contained.
from datetime import timedelta  # noqa: E402

from django.utils import timezone  # noqa: E402
from oauth2_provider.models import get_access_token_model  # noqa: E402

from ._factories import make_app  # noqa: E402
from ._oidc_testcase import OIDCTestCase  # noqa: E402


class TestFindTokenByChecksum(OIDCTestCase):
    """
    ``TokenAudit._find_token`` must locate the persisted row via
    ``token_checksum`` (SHA256, indexed in DOT 3.x), not by raw
    ``token`` equality. The raw lookup misses on hashed-at-rest
    deployments and is a full-table scan on the unindexed ``token``
    TextField even on default storage; the checksum lookup is what
    DOT itself uses in its introspect/refresh paths.
    """

    def test_find_token_succeeds_when_raw_token_replaced_by_hash(
        self,
    ) -> None:
        AT = get_access_token_model()
        raw = "raw-token-value-for-checksum-test"
        creds = make_app(owner=self.users[0])
        access = AT.objects.create(
            user=self.users[0],
            application=creds.app,
            token=raw,
            expires=timezone.now() + timedelta(seconds=3600),
            scope="openid",
        )
        # ``token_checksum`` auto-populated by
        # ``TokenChecksumField.pre_save`` (sha256 of ``token``).
        # Now break the raw column to ensure the new lookup is
        # genuinely going through the checksum index.
        AT.objects.filter(pk=access.pk).update(token="<<hashed at rest>>")
        audit = TokenAudit(
            request=None,
            body=None,
            sender=type("StubSender", (), {}),
        )
        found = audit._find_token(raw)
        self.assertIsNotNone(found)
        self.assertEqual(found.pk, access.pk)
