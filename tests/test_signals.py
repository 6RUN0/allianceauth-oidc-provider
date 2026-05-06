"""
Tests for the ``oidc_token_issued`` Django signal.

The signal is the documented extension point for SIEM/audit forwarding — third
parties hook receivers without monkey-patching ``TokenView``. These tests guard
the contract: the signal fires on success with a specific payload shape, and
does NOT fire on failed token exchanges.
"""

from unittest.mock import patch

from oauth2_provider.models import get_access_token_model

from allianceauth_oidc.signals import oidc_token_issued

from ._oidc_testcase import REDIRECT_URI, OIDCTestCase


class TestOidcTokenIssuedSignal(OIDCTestCase):
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
        self.grant_oidc_access(self.user1)
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
        self.grant_oidc_access(self.user1)
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
        ``TokenView._emit_audit``.
        """
        self.grant_oidc_access(self.user1)

        def boom(sender, **kwargs):
            raise RuntimeError("simulated SIEM forwarder failure")

        oidc_token_issued.connect(boom, dispatch_uid="test-signal-boom")
        self.addCleanup(
            oidc_token_issued.disconnect,
            dispatch_uid="test-signal-boom",
        )

        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="ERROR"
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
        In hashed-token storage configurations DOT persists a hashed token
        but returns the raw value in the response body, so the
        ``objects.get(token=...)`` lookup misses.

        The audit pipeline must skip silently (debug-level log), not crash and
        not leak the exception to the OAuth client.
        """
        self.grant_oidc_access(self.user1)

        access_token_model = get_access_token_model()
        with (
            patch.object(
                access_token_model.objects,
                "get",
                side_effect=access_token_model.DoesNotExist,
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.views", level="DEBUG"
            ) as cm,
        ):
            body = self.run_code_flow(self.user1, state="hashed-storage")

        # Token issued; OAuth client never sees the audit failure.
        self.assertIn("access_token", body)
        # Signal NOT dispatched (the capture receiver did not fire).
        self.assertEqual([], self.captured)
        # Debug log explains why audit was skipped.
        self.assertTrue(
            any("hashed-token storage" in msg for msg in cm.output),
            f"expected hashed-storage mention in logs, got {cm.output}",
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

        self.grant_oidc_access(self.user1)

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
                "extensions.allianceauth_oidc.views", level="WARNING"
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
        self.grant_oidc_access(self.user1)
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
