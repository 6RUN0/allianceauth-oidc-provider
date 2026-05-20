"""
Tests for the ``oidc_token_issued`` Django signal.

The signal is the documented extension point for SIEM/audit forwarding — third
parties hook receivers without monkey-patching ``TokenView``. These tests guard
the contract: the signal fires on success with a specific payload shape, and
does NOT fire on failed token exchanges.
"""

import types
from unittest.mock import patch

from django.test import SimpleTestCase
from oauth2_provider.models import get_access_token_model

from allianceauth_oidc.signals import (
    audit_oidc_token_issued,
    oidc_token_issued,
)

from ._oidc_testcase import REDIRECT_URI, GrantedOIDCTestCase


class TestOidcTokenIssuedSignal(GrantedOIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.captured: list[dict] = []

        def receiver(sender, **kwargs):
            self.captured.append(kwargs)

        self._receiver = receiver
        oidc_token_issued.connect(receiver, dispatch_uid="test-signal-capture")
        self.addCleanup(
            oidc_token_issued.disconnect,
            dispatch_uid="test-signal-capture",
        )

    def test_signal_fires_with_token_and_body_on_successful_exchange(self):
        """
        Successful authorization-code exchange must fire
        ``oidc_token_issued`` exactly once with a payload that includes the
        persisted ``token`` model and the request ``body`` dict carrying
        ``grant_type``/``scope``.
        """
        body = self.run_code_flow(self.user1, state="signal-success")
        self.assertIn("access_token", body)

        self.assertEqual(
            1,
            len(self.captured),
            f"expected exactly one signal, got {len(self.captured)}",
        )
        kw = self.captured[0]
        # Token model is exposed so receivers can pull
        # app/user/scope without re-querying.
        self.assertIn("token", kw)
        token = kw["token"]
        self.assertEqual(self.user1.pk, token.user.pk)
        self.assertEqual(self.oauth_id, token.application.client_id)

        # body dict mirrors the OAuth2 request — grant_type at minimum,
        # no raw token strings. (scope lives on `token.scope`, not on
        # the token-endpoint request, so it can be None here.)
        self.assertIn("body", kw)
        request_body = kw["body"]
        self.assertEqual("authorization_code", request_body.get("grant_type"))
        # Token model carries the granted scope.
        self.assertEqual("openid profile email", token.scope)

    def test_signal_does_not_fire_on_invalid_grant(self):
        """
        Failed token exchange (revoked permission between authorize and
        token) must NOT fire the signal.

        Otherwise audit sinks would record successful issuance for tokens that
        were never minted.
        """
        code = self.authorize_to_code(self.user1, state="signal-fail")

        # Revoke the global OIDC permission before exchange — the
        # validator denies the code.
        self.user1.user_permissions.remove(self.access_oauth)
        self.user1.refresh_from_db()

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )
        self.assertOAuthError(resp, expected_error="invalid_grant")
        self.assertEqual(
            [],
            self.captured,
            "signal must not fire when token exchange fails",
        )

    def test_receiver_failure_does_not_break_token_issuance(self):
        """
        A misbehaving audit receiver must NOT propagate its exception:
        token issuance succeeds, the failure is logged, other receivers
        still run. Regression for ``send_robust`` semantics in
        ``signals.dispatch_audit_signal`` (Architect#6 / N-6).
        """

        def boom(sender, **kwargs):
            raise RuntimeError("simulated SIEM forwarder failure")

        self._boom = boom  # strong ref so weak-connect doesn't evict
        oidc_token_issued.connect(boom, dispatch_uid="test-signal-boom")
        self.addCleanup(
            oidc_token_issued.disconnect,
            dispatch_uid="test-signal-boom",
        )

        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="ERROR"
        ) as cm:
            body = self.run_code_flow(self.user1, state="receiver-failure")

        # Token issued normally despite the failing receiver.
        self.assertIn("access_token", body)
        # The non-failing capture receiver still ran.
        self.assertEqual(1, len(self.captured))
        # The failure was logged with the exception message.
        joined = "\n".join(cm.output)
        self.assertIn("OIDC audit receiver", joined)
        self.assertIn("simulated SIEM forwarder failure", joined)

    def test_audit_skipped_when_access_token_not_in_db(self):
        """
        ``_find_token`` keys off the SHA256 ``token_checksum``
        (DOT 3.x indexed column). If the lookup misses — e.g.
        because the row was reaped between issuance and the audit
        signal — the audit pipeline must skip silently (debug-level
        log), not crash and not leak the exception to the OAuth
        client.
        """
        access_token_model = get_access_token_model()
        with (
            patch.object(
                access_token_model.objects,
                "get",
                side_effect=access_token_model.DoesNotExist,
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.views_token", level="DEBUG"
            ) as cm,
        ):
            body = self.run_code_flow(self.user1, state="hashed-storage")

        # Token issued; OAuth client never sees the audit failure.
        self.assertIn("access_token", body)
        # Signal NOT dispatched (the capture receiver did not fire).
        self.assertEqual([], self.captured)
        # Debug log explains why audit was skipped.
        self.assertTrue(
            any("checksum miss" in msg for msg in cm.output),
            f"expected checksum-miss mention in logs, got {cm.output}",
        )

    def test_audit_skipped_when_body_exceeds_size_cap(self):
        """
        A response body larger than the audit-parse cap (64 KiB) skips the
        parse entirely with a warning, instead of feeding json.loads an
        unbounded blob.

        Defence-in-depth: a normal DOT response is
        ~1 KiB; anything orders of magnitude larger indicates upstream
        misconfiguration and is not worth parsing.
        """
        from allianceauth_oidc.views import TokenView

        # Replace TokenView.create_token_response with a stub that
        # returns a >64 KiB body containing a fake access_token.
        oversized_body = (
            '{"access_token": "x", "padding": "' + ("A" * 70_000) + '"}'
        )
        with (
            patch.object(
                TokenView,
                "create_token_response",
                return_value=(None, {}, oversized_body, 200),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.views_token", level="WARNING"
            ) as cm,
        ):
            self.client.post(
                "/o/token/",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.oauth_id,
                    "client_secret": self.oauth_secret,
                },
            )

        # Signal NOT dispatched: parse skipped, no token model fetched.
        self.assertEqual([], self.captured)
        joined = "\n".join(cm.output)
        self.assertIn("over", joined)
        self.assertIn("byte cap", joined)

    def test_signal_payload_contains_no_raw_secrets(self):
        """
        The signal exposes the OAuth2 request body to receivers; the payload
        must not contain raw access/refresh/id tokens — those live only on the
        ``token`` model that receivers can query.
        """
        token_body = self.run_code_flow(self.user1, state="signal-no-leak")

        self.assertEqual(1, len(self.captured))
        kw_body = self.captured[0]["body"]
        # The dispatched body comes from request.POST and intentionally
        # only carries grant_type/scope — receivers cannot accidentally
        # log token strings.
        for token_kind in ("access_token", "refresh_token", "id_token"):
            self.assertNotIn(token_kind, kw_body)
            # And of course the actual token value should not be in
            # any other key either.
            for v in kw_body.values():
                if isinstance(v, str):
                    self.assertNotIn(token_body[token_kind], v)

    def test_oidc_token_issued_fires_with_pkce_off(self):
        """
        Audit signal must dispatch on a non-PKCE token exchange — the
        existing shared fixture has ``pkce_required=False``, so a plain
        run_code_flow exercises this path directly.
        """
        body = self.run_code_flow(self.user1, state="signal-pkce-off")
        self.assertIn("access_token", body)
        self.assertEqual(1, len(self.captured))

    def test_oidc_token_issued_fires_with_pkce_on(self):
        """
        Audit signal must also dispatch when the token was issued under
        a strict-PKCE contract.
        """
        from urllib.parse import parse_qs, urlparse

        from ._factories import make_app

        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )

        verifier, challenge = self.make_pkce_pair()

        resp = self.authorize_get_default(
            self.user1,
            scope="openid",
            state="signal-pkce-on",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]
        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = self.json_body(token_resp, expected_status=None)
        self.assertIn("access_token", body)
        self.assertEqual(1, len(self.captured))


class TestOidcCodeReuseDetectedSignal(GrantedOIDCTestCase):
    """
    Contract test for ``oidc_code_reuse_detected``.

    The signal is the documented SIEM/alerting hook for RFC 6749
    §10.5 reuse events — receivers connect to it (not to logs) to
    forward to external systems.
    """

    def setUp(self) -> None:
        super().setUp()
        from allianceauth_oidc.signals import oidc_code_reuse_detected

        self.captured: list[dict] = []

        def receiver(sender, **kwargs):
            self.captured.append(kwargs)

        # Pin a strong reference to the closure — Django's
        # ``Signal.connect`` defaults to ``weak=True``, and the
        # closure is otherwise eligible for GC the moment setUp
        # returns. Without this anchor the test is timing-fragile and
        # the signal dispatcher may find the receiver evicted.
        self._receiver = receiver
        oidc_code_reuse_detected.connect(
            receiver, dispatch_uid="test-reuse-signal-capture"
        )
        self.addCleanup(
            oidc_code_reuse_detected.disconnect,
            dispatch_uid="test-reuse-signal-capture",
        )

    def test_signal_payload_on_code_reuse(self):
        """
        On code reuse the signal MUST fire exactly once with
        ``application`` / ``code_hash`` / ``access_token_id`` /
        ``refresh_token_id`` / ``reuse_count`` kwargs populated.
        """
        import hashlib

        code = self.authorize_to_code(self.user1, state="signal-reuse")
        self.exchange_code_for_token(code=code, redirect_uri=REDIRECT_URI)
        # Replay → signal fires.
        self.exchange_code_for_token(
            code=code, redirect_uri=REDIRECT_URI, expected_status=400
        )

        self.assertEqual(
            1,
            len(self.captured),
            f"expected exactly one reuse signal, got {len(self.captured)}",
        )
        kw = self.captured[0]
        self.assertEqual(self.oauth_app, kw["application"])
        self.assertEqual(
            hashlib.sha256(code.encode("utf-8")).hexdigest(),
            kw["code_hash"],
        )
        self.assertIsNotNone(kw["access_token_id"])
        self.assertIsNotNone(kw["refresh_token_id"])
        self.assertEqual(1, kw["reuse_count"])

    def test_signal_does_not_fire_for_unknown_code(self):
        """
        A token request with a code that was NEVER issued must NOT
        produce a reuse-detected signal — that path returns
        ``invalid_grant`` because of DOT's own ``Grant.DoesNotExist``,
        unrelated to reuse.
        """
        self.exchange_code_for_token(
            code="this-code-was-never-issued",
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )
        self.assertEqual(
            0,
            len(self.captured),
            "no signal expected for codes never tracked by the audit table",
        )


class TestAuditReceiverErrorPath(SimpleTestCase):
    """
    Cover the defensive ``except`` in ``audit_oidc_token_issued``.

    The body intentionally narrows to four exception types known to come
    from partially-mocked tokens or malformed audit bodies. Anything else
    must propagate so genuine bugs surface in tests rather than being
    silently logged away.
    """

    def _token(self) -> types.SimpleNamespace:
        # Stable ``type(...).__name__`` for log assertions; the receiver
        # only reads ``application``/``user`` via ``getattr(..., default)``
        # so missing attrs are tolerated.
        return types.SimpleNamespace(
            application=types.SimpleNamespace(id=42, client_id="cid"),
            user=types.SimpleNamespace(id=7, username="alice"),
            scope=None,
        )

    def test_attribute_error_from_malformed_body_is_swallowed_and_logged(
        self,
    ) -> None:
        # ``[1, 2, 3]`` is truthy so ``if body:`` enters the meta block,
        # but ``body.get(...)`` raises AttributeError — exactly the failure
        # mode the narrow except is designed to catch.
        token = self._token()
        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="ERROR"
        ) as cm:
            audit_oidc_token_issued(
                sender=None,
                request=None,
                token=token,
                body=[1, 2, 3],  # type: ignore[arg-type]
            )

        joined = "\n".join(cm.output)
        # Operators grep audit failures by token kind / app / user — all
        # three identifiers must appear so the failed call is locatable.
        self.assertIn("SimpleNamespace", joined)
        self.assertIn("42", joined)
        self.assertIn("7", joined)

    def test_none_body_skips_meta_block_and_logs_info(self) -> None:
        # ``body=None`` keeps the receiver on the happy path but skips
        # the meta-extraction branch; covers the ``if body:`` False arm.
        token = self._token()
        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="INFO"
        ) as cm:
            audit_oidc_token_issued(
                sender=None, request=None, token=token, body=None
            )
        self.assertIn("OIDC token issued", "\n".join(cm.output))

    def test_unrelated_exception_propagates(self) -> None:
        # MemoryError / RecursionError / KeyboardInterrupt are explicitly
        # NOT caught. Neither is RuntimeError. If someone widens the
        # except to ``Exception:`` this test fails — that's the point.  # noqa: ERA001
        class BoomToken:
            @property
            def application(self) -> object:
                raise RuntimeError("simulated unrelated bug")

            user = None
            scope = None

        with self.assertRaises(RuntimeError):
            audit_oidc_token_issued(
                sender=None,
                request=None,
                token=BoomToken(),  # type: ignore[arg-type]
                body=None,
            )


class TestSignalsKillMutants(SimpleTestCase):
    """
    Surface tests for the surviving cosmic-ray mutants in
    ``allianceauth_oidc/signals.py``.

    * ``Signal(use_caching=True)`` on ``oidc_token_issued`` —
      mirror of the existing AC-7 / AC-10 pins on
      ``oidc_logout_required`` / ``oidc_logout_dispatched``. Same
      ``ReplaceTrueWithFalse`` mutant, same kill technique.

    * Inside ``audit_oidc_token_issued`` the line
      ``meta = {k: v for k, v in meta.items() if v is not None}
      or None`` carries two mutants on one expression:
      - ``v is not None`` -> ``v is None``: keeps None-valued
        fields and drops real values; the test below pins both
        directions.
      - ``... or None`` -> ``... and None``: ``and`` would collapse
        every non-empty dict to ``None`` (truthy short-circuit
        flipped); pinned by the populated-dict test below.
    """

    def test_oidc_token_issued_signal_uses_caching(self):
        # AC-7 mirror: ``use_caching=True`` lets Django cache the
        # receiver list — important for hot signal paths like the
        # token endpoint. Mutation ``ReplaceTrueWithFalse`` would
        # silently disable the cache and let every send walk the
        # receiver registry.
        self.assertTrue(oidc_token_issued.use_caching)

    def test_audit_meta_filters_none_values_keeping_real_values(self):
        # The comprehension ``{k: v for k, v in meta.items() if v
        # is not None}`` keeps fields with values and drops Nones.
        # Combined with the ``or None`` fallback (next test),
        # ``meta`` ends up as ``None`` when EVERY field was None,
        # and a dict containing ONLY the non-None fields otherwise.
        #
        # Pin both: a body where ``grant_type`` carries a value
        # and ``scope`` is None must yield a meta dict containing
        # ``grant_type`` but NOT ``scope``.
        from types import SimpleNamespace
        from unittest import mock

        token = SimpleNamespace(
            application=SimpleNamespace(client_id="cid", id=1),
            user=SimpleNamespace(id=2, username="u"),
            scope="openid",
        )
        body = {
            "grant_type": "authorization_code",
            "scope": None,  # explicitly None — must be filtered out
        }
        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="INFO"
        ) as cap:
            audit_oidc_token_issued(
                sender=None,
                request=mock.MagicMock(),
                token=token,  # type: ignore[arg-type]
                body=body,  # type: ignore[arg-type]
            )
        # Log emits ``meta=`` followed by the dict repr. The
        # filtered dict contains only ``grant_type``.
        joined = "\n".join(cap.output)
        self.assertIn("'grant_type': 'authorization_code'", joined)
        # ``scope`` must NOT appear inside the ``meta`` dict
        # (it appears as a token attribute earlier in the line —
        # constrain the match to the ``meta=`` segment).
        meta_segment = joined.split("meta=", 1)[1]
        self.assertNotIn("'scope'", meta_segment)

    def test_audit_meta_collapses_empty_dict_to_none(self):
        # Both fields None ⇒ filtered dict is empty ⇒
        # ``{} or None`` evaluates to None. ``or`` flipped to
        # ``and`` would short-circuit on the falsy empty dict and
        # return ``{}`` instead — observable as ``meta={}`` in the
        # log line.
        from types import SimpleNamespace
        from unittest import mock

        token = SimpleNamespace(
            application=SimpleNamespace(client_id="cid", id=1),
            user=SimpleNamespace(id=2, username="u"),
            scope="openid",
        )
        body = {"grant_type": None, "scope": None}
        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="INFO"
        ) as cap:
            audit_oidc_token_issued(
                sender=None,
                request=mock.MagicMock(),
                token=token,  # type: ignore[arg-type]
                body=body,  # type: ignore[arg-type]
            )
        joined = "\n".join(cap.output)
        # ``meta=None`` per the ``or None`` short-circuit; with
        # ``and None`` the log would render ``meta={}``.
        self.assertIn("meta=None", joined)
        self.assertNotIn("meta={}", joined)
