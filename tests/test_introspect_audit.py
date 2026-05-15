"""
Tests for the ``oidc_token_introspected`` audit signal.

DOT's stock introspect endpoint performs the RFC 7662 lookup but
produces no audit trail. ``AllianceAuthIntrospectTokenView`` adds
one signal emit after the response is built, mirroring the
``oidc_token_issued`` contract on the issuance side.

Four invariants:

1. The signal fires for an active-token probe and carries the
   sha256 hex of the introspected bearer (matching DOT's
   ``AccessToken.token_checksum``).
2. The signal fires for an unknown / invalid token too — the
   audit must record every probe, including the negative ones
   (a 5xx on a missed probe IS the operator signal worth
   correlating).
3. The default audit receiver logs at INFO without leaking the
   raw bearer value of either the introspected token or the
   introspector's credentials.
4. An audit-receiver failure does NOT break the introspection
   response — the protocol contract is non-negotiable.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from django.test import override_settings
from django.utils import timezone
from oauth2_provider.models import get_access_token_model

from allianceauth_oidc.signals import oidc_token_introspected

from ._oidc_testcase import OIDCTestCase


class TestOIDCIntrospectAuditSignal(OIDCTestCase):
    """Pin the four invariants the override is responsible for."""

    def _seed_access_token(self, token: str = "intro-audit-at") -> None:
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=token,
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )

    def test_signal_fires_with_sha256_for_active_token(self) -> None:
        token = "intro-audit-active"
        self._seed_access_token(token)

        captured: list[dict[str, object]] = []

        def sink(sender, request, introspector, body, **kw):
            captured.append(
                {
                    "active": body.get("active"),
                    "client_id": body.get("client_id"),
                    "token_sha256": body.get("token_sha256"),
                }
            )

        oidc_token_introspected.connect(
            sink, dispatch_uid="test.introspect.active"
        )
        try:
            data = self.introspect_token(token)
        finally:
            oidc_token_introspected.disconnect(
                dispatch_uid="test.introspect.active"
            )

        self.assertTrue(data.get("active"))
        self.assertEqual(1, len(captured), captured)
        meta = captured[0]
        self.assertIs(True, meta["active"])
        self.assertEqual(self.oauth_id, meta["client_id"])
        expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.assertEqual(expected_hash, meta["token_sha256"])

    def test_signal_fires_for_unknown_token(self) -> None:
        """
        The probe is itself the operator signal — a resource server
        repeatedly asking the AS about tokens that do not exist is
        exactly the enumeration pattern SIEM detection rules want.
        Audit MUST fire on the miss path.
        """
        unknown = "no-such-token-anywhere"

        captured: list[dict[str, object]] = []

        def sink(sender, request, introspector, body, **kw):
            captured.append(
                {
                    "active": body.get("active"),
                    "token_sha256": body.get("token_sha256"),
                }
            )

        oidc_token_introspected.connect(
            sink, dispatch_uid="test.introspect.miss"
        )
        try:
            data = self.introspect_token(unknown)
        finally:
            oidc_token_introspected.disconnect(
                dispatch_uid="test.introspect.miss"
            )

        self.assertIs(False, data.get("active"))
        self.assertEqual(1, len(captured), captured)
        meta = captured[0]
        self.assertIs(False, meta["active"])
        expected_hash = hashlib.sha256(unknown.encode("utf-8")).hexdigest()
        self.assertEqual(expected_hash, meta["token_sha256"])

    @override_settings(ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=False)
    def test_default_audit_logger_does_not_leak_tokens_or_secrets(
        self,
    ) -> None:
        """
        The default receiver logs at INFO. None of the raw bearer
        value, the introspector's Basic auth credentials, or the
        client secret may appear in the captured log output.
        """
        token = "intro-audit-no-leak-bearer"
        self._seed_access_token(token)

        # ``audit_oidc_token_introspected`` lives at
        # ``extensions.allianceauth_oidc.signals``; captureall to be
        # safe against logger-name churn in the receiver module.
        with self.assertLogs(
            "extensions.allianceauth_oidc.signals", level="INFO"
        ) as cap:
            self.introspect_token(token)

        body = "\n".join(cap.output)
        for forbidden in (token, self.oauth_secret):
            self.assertNotIn(
                forbidden,
                body,
                f"audit log leaked {forbidden!r} into the captured "
                f"output:\n{body}",
            )

    def test_audit_receiver_failure_does_not_break_introspection(self) -> None:
        """
        A misbehaving operator-installed receiver MUST NOT propagate
        out of the audit emit. The introspect response is the
        protocol contract; the audit is observability. Crash here
        and the AS becomes unable to serve introspection for every
        RP that has the broken receiver wired.
        """

        def boom(sender, request, introspector, body, **kw):
            raise RuntimeError("simulated receiver crash")

        token = "intro-audit-crash-survivor"
        self._seed_access_token(token)
        oidc_token_introspected.connect(
            boom, dispatch_uid="test.introspect.boom"
        )
        try:
            data = self.introspect_token(token)
        finally:
            oidc_token_introspected.disconnect(
                dispatch_uid="test.introspect.boom"
            )

        # The protocol response survives a broken receiver — DOT's
        # behaviour byte-for-byte.
        self.assertTrue(data.get("active"))
