"""
Tests for OIDC Back-Channel Logout 1.0 (sub-only v1).

Covers acceptance criteria AC-1..AC-41 from plan v5
(``.omc/plans/back-channel-logout-plan-v5.md``).

US-BCL-001 lives in ``TestBackChannelLogoutModel`` — model field,
``clean()`` SSRF guard, DNS-failure non-blocking policy, and migration
shape. US-BCL-002 lives in ``TestBackChannelLogoutSignals`` — the
trigger/audit signal pair and ``LogoutAuditBody`` TypedDict.
"""

from __future__ import annotations

import concurrent.futures
import logging
import socket
import typing
from io import StringIO
from unittest import mock

from django.conf import settings
from django.core import checks
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.validators import URLValidator
from django.db.models import URLField
from django.dispatch import Signal
from django.test import TestCase, override_settings
from oauth2_provider.settings import oauth2_settings

from allianceauth_oidc import signals as oidc_signals
from allianceauth_oidc.constants import DEFAULT_LOGOUT_DISPATCH_UID
from allianceauth_oidc.models import AllianceAuthApplication

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase

# A genuinely public address used as the default "resolves OK" stub.
# RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
# would set ``ipaddress.is_reserved`` to True, which the SSRF guard
# correctly rejects — so a real-world public IP is required to drive
# the happy path. 1.1.1.1 (Cloudflare DNS) is documented, well-known,
# and outside any reserved/private/loopback block.
_PUBLIC_IP = "1.1.1.1"


def _stub_resolver(*ips: str):
    """
    Build a ``getaddrinfo``-compatible return value enumerating ``ips``
    so ``models._resolve_host_bounded`` exits with those addresses.
    """
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0)) for ip in ips]


class TestBackChannelLogoutModel(OIDCTestCase):
    """
    AC-1 / AC-3 / AC-3a / AC-3b / AC-5 / AC-6 — field shape, clean()
    SSRF guard, DNS-failure non-blocking policy, migration sanity.
    """

    def _new_app(self, *, uri: str) -> AllianceAuthApplication:
        creds = make_app(owner=self.user1, backchannel_logout_uri=uri)
        return creds.app

    # ---------- AC-1 ----------

    def test_ac1_field_is_urlfield_with_http_https_schemes(self) -> None:
        field = AllianceAuthApplication._meta.get_field(
            "backchannel_logout_uri"
        )
        self.assertIsInstance(field, URLField)
        self.assertFalse(field.null)
        self.assertTrue(field.blank)
        self.assertEqual(field.default, "")
        # ``URLField.default_validators`` always carries a permissive
        # ``URLValidator()`` (ftp/ftps allowed). AC-1 is satisfied when
        # at least one explicit validator narrows the schemes set down
        # to exactly ``{"http", "https"}`` — the same pattern used by
        # the existing ``logo_url`` field on this model.
        strict_validators = [
            v
            for v in field.validators
            if isinstance(v, URLValidator)
            and set(v.schemes) == {"http", "https"}
        ]
        self.assertTrue(
            strict_validators,
            "AC-1 expects an explicit URLValidator restricting "
            "schemes to http/https on backchannel_logout_uri",
        )

    # ---------- AC-3 ----------

    @override_settings(DEBUG=False)
    def test_ac3_http_rejected_when_debug_false(self) -> None:
        app = self._new_app(uri="http://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                return_value=_stub_resolver(_PUBLIC_IP),
            ),
            self.assertRaises(ValidationError) as ctx,
        ):
            app.full_clean()
        self.assertIn("backchannel_logout_uri", ctx.exception.error_dict)

    @override_settings(DEBUG=True)
    def test_ac3_http_allowed_when_debug_true(self) -> None:
        app = self._new_app(uri="http://rp.example.com/bcl")
        with mock.patch(
            "allianceauth_oidc.models._resolve_host_bounded",
            return_value=_stub_resolver(_PUBLIC_IP),
        ):
            app.full_clean()

    # ---------- AC-3a — SSRF rejections ----------

    @override_settings(DEBUG=False)
    def test_ac3a_private_ip_rejected(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                return_value=_stub_resolver("10.0.0.1"),
            ),
            self.assertRaises(ValidationError) as ctx,
        ):
            app.full_clean()
        self.assertIn("backchannel_logout_uri", ctx.exception.error_dict)
        # Error message names the policy so operators can grep it.
        joined = " ".join(
            ctx.exception.error_dict["backchannel_logout_uri"][0].messages
        )
        self.assertIn("public IP", joined)

    @override_settings(DEBUG=False)
    def test_ac3a_loopback_rejected(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                return_value=_stub_resolver("127.0.0.1"),
            ),
            self.assertRaises(ValidationError),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3a_link_local_rejected(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                return_value=_stub_resolver("169.254.1.1"),
            ),
            self.assertRaises(ValidationError),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3a_multicast_rejected(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                return_value=_stub_resolver("224.0.0.1"),
            ),
            self.assertRaises(ValidationError),
        ):
            app.full_clean()

    @override_settings(
        DEBUG=False, ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True
    )
    def test_ac3a_private_allowed_when_dev_flag_set(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with mock.patch(
            "allianceauth_oidc.models._resolve_host_bounded",
            return_value=_stub_resolver("10.0.0.1"),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3a_public_ip_accepted(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with mock.patch(
            "allianceauth_oidc.models._resolve_host_bounded",
            return_value=_stub_resolver(_PUBLIC_IP),
        ):
            app.full_clean()

    # ---------- AC-3b — non-blocking DNS failure ----------

    @override_settings(DEBUG=False)
    def test_ac3b_gaierror_is_non_blocking_and_warns(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                side_effect=socket.gaierror("nodename nor servname"),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.models", level=logging.WARNING
            ) as ctx,
        ):
            app.full_clean()
        self.assertEqual(len(ctx.records), 1, msg=ctx.output)
        self.assertIn("rp.example.com", ctx.records[0].getMessage())

    @override_settings(DEBUG=False)
    def test_ac3b_socket_timeout_is_non_blocking(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                side_effect=TimeoutError("timed out"),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.models", level=logging.WARNING
            ),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3b_oserror_is_non_blocking(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                side_effect=OSError("network unreachable"),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.models", level=logging.WARNING
            ),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3b_concurrent_timeout_is_non_blocking(self) -> None:
        app = self._new_app(uri="https://rp.example.com/bcl")
        with (
            mock.patch(
                "allianceauth_oidc.models._resolve_host_bounded",
                side_effect=concurrent.futures.TimeoutError(),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.models", level=logging.WARNING
            ),
        ):
            app.full_clean()

    @override_settings(DEBUG=False)
    def test_ac3a_skips_dns_when_uri_blank(self) -> None:
        app = self._new_app(uri="")
        with mock.patch(
            "allianceauth_oidc.models._resolve_host_bounded"
        ) as resolver:
            app.full_clean()
        resolver.assert_not_called()

    # ---------- AC-5 — migration sanity ----------

    def test_ac5_makemigrations_check_dry_run_clean(self) -> None:
        """
        Project tree is in sync with model state — running
        ``makemigrations --check --dry-run`` must NOT raise SystemExit,
        which would mean an un-generated migration is needed.
        """
        out = StringIO()
        # Raises SystemExit(1) when migrations are out of sync.
        call_command(
            "makemigrations",
            "--check",
            "--dry-run",
            stdout=out,
            stderr=out,
        )

    # ---------- AC-6 — round-trip blank default ----------

    def test_ac6_blank_default_round_trip(self) -> None:
        app = self._new_app(uri="")
        self.assertEqual(app.backchannel_logout_uri, "")
        app.save()
        app.refresh_from_db()
        self.assertEqual(app.backchannel_logout_uri, "")


class _SignalSender:
    """
    Stand-in ``sender`` argument for ``Signal.send`` in tests.

    ``oidc_logout_required`` was declared ``use_caching=True`` per
    plan §5.2 AC-7; Django keys the receiver cache on a
    ``WeakValueDictionary`` so the sender must be weakref-able.
    ``None`` and bare ``object()`` instances aren't — using a class
    object satisfies the contract without dragging in real models.
    """


class TestBackChannelLogoutSignals(TestCase):
    """
    AC-7 / AC-8 / AC-9 / AC-10 / AC-11 helper — the trigger/audit
    signal pair, the ``LogoutAuditBody`` TypedDict shape, and the
    ``connect_default_logout_receiver`` indirection helper.
    """

    # ---------- AC-7 ----------

    def test_ac7_oidc_logout_required_is_signal_with_caching(self) -> None:
        sig = oidc_signals.oidc_logout_required
        self.assertIsInstance(sig, Signal)
        self.assertTrue(
            sig.use_caching,
            "AC-7: oidc_logout_required must use_caching=True "
            "(mirrors oidc_token_issued)",
        )

    # ---------- AC-10 ----------

    def test_ac10_oidc_logout_dispatched_is_signal_with_caching(self) -> None:
        sig = oidc_signals.oidc_logout_dispatched
        self.assertIsInstance(sig, Signal)
        self.assertTrue(sig.use_caching)

    # ---------- AC-9 ----------

    def test_ac9_logout_audit_body_has_exact_keys(self) -> None:
        keys = set(typing.get_type_hints(oidc_signals.LogoutAuditBody).keys())
        # ``user_pk`` joined the contract with the dead-letter audit
        # feature: SIEM receivers need to correlate failures with the
        # affected user, including in the ``user_deleted`` flow where
        # the user model is gone by the time the signal arrives.
        self.assertEqual(keys, {"application_id", "user_pk", "reason", "jti"})

    def test_ac9_logout_audit_body_excludes_sid_key(self) -> None:
        """
        v5 path-b: sub-only logout. ``sid`` is explicitly NOT a
        documented audit field — regression assertion against any
        accidental re-introduction.
        """
        keys = set(typing.get_type_hints(oidc_signals.LogoutAuditBody).keys())
        self.assertNotIn("sid", keys)

    # ---------- AC-8 — receiver signature ----------

    def test_ac8_signal_accepts_documented_receiver_signature(self) -> None:
        captured: list[dict] = []

        def receiver(sender, user, application, reason=None, **kwargs):
            captured.append(
                {
                    "user": user,
                    "application": application,
                    "reason": reason,
                }
            )

        try:
            oidc_signals.oidc_logout_required.connect(
                receiver, dispatch_uid="test.ac8.signature"
            )
            for reason in (
                "user_revoked",
                "user_deactivated",
                "groups_changed",
                "state_changed",
                "user_deleted",
            ):
                oidc_signals.oidc_logout_required.send(
                    sender=_SignalSender,
                    user=object(),
                    application=object(),
                    reason=reason,
                )
        finally:
            oidc_signals.oidc_logout_required.disconnect(
                dispatch_uid="test.ac8.signature"
            )
        self.assertEqual(
            [c["reason"] for c in captured],
            [
                "user_revoked",
                "user_deactivated",
                "groups_changed",
                "state_changed",
                "user_deleted",
            ],
        )

    # ---------- AC-11 helper — connect_default_logout_receiver ----------

    def test_connect_default_logout_receiver_uses_constant_uid(self) -> None:
        """
        ``connect_default_logout_receiver`` wires the passed callable
        to ``oidc_logout_required`` under
        :data:`DEFAULT_LOGOUT_DISPATCH_UID`.

        Django's ``Signal.connect`` is append-only on dispatch_uid
        conflict — it does NOT replace an existing receiver. So
        ``apps.py:ready()`` has already wired the production
        dispatcher under this UID; this test swaps it out for an
        in-test stub then restores the original at teardown so
        cross-test isolation holds.
        """
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        calls: list[dict] = []

        def stub(sender, user, application, reason=None, **kwargs):
            calls.append({"reason": reason})

        oidc_signals.oidc_logout_required.disconnect(
            dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
        )
        try:
            oidc_signals.connect_default_logout_receiver(stub)
            oidc_signals.oidc_logout_required.send(
                sender=_SignalSender,
                user=object(),
                application=object(),
                reason="user_revoked",
            )
            self.assertEqual(calls, [{"reason": "user_revoked"}])
        finally:
            oidc_signals.oidc_logout_required.disconnect(
                dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
            )
            oidc_signals.connect_default_logout_receiver(
                dispatch_backchannel_logout
            )

    def test_connect_default_logout_receiver_is_strong_ref(self) -> None:
        """
        ``weak=False`` per plan §5.2 AC-11 prevents Python's GC from
        silently dropping the dispatcher between requests.
        """
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        calls: list[str] = []

        def stub(sender, user, application, reason=None, **kwargs):
            calls.append(reason or "none")

        oidc_signals.oidc_logout_required.disconnect(
            dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
        )
        try:
            oidc_signals.connect_default_logout_receiver(stub)
            del stub
            import gc

            gc.collect()
            oidc_signals.oidc_logout_required.send(
                sender=_SignalSender,
                user=object(),
                application=object(),
                reason="user_revoked",
            )
            self.assertEqual(calls, ["user_revoked"])
        finally:
            oidc_signals.oidc_logout_required.disconnect(
                dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
            )
            oidc_signals.connect_default_logout_receiver(
                dispatch_backchannel_logout
            )


class TestBackChannelLogoutSystemCheck(OIDCTestCase):
    """
    AC-19e / AC-19f / AC-19g — Django system check
    ``allianceauth_oidc.E001`` fires Error when any RP has
    ``backchannel_logout_uri`` set and ``OIDC_ISS_ENDPOINT`` is
    unset; clean otherwise.
    """

    def _build_app_with_bcl(self, *, uri: str = "https://rp.example.com/bcl"):
        # Bypass ``clean()`` SSRF guard — the system check runs on
        # already-persisted rows, so we just write directly.
        creds = make_app(owner=self.user1)
        creds.app.backchannel_logout_uri = uri
        creds.app.save(update_fields=["backchannel_logout_uri"])
        return creds.app

    def _override_iss(self, value: str):
        """
        Wrap ``override_settings(OAUTH2_PROVIDER=...)`` + DOT cache
        reload so the system check sees the new ``OIDC_ISS_ENDPOINT``
        without leaking into siblings.
        """
        from django.conf import settings as dj_settings
        from oauth2_provider.settings import oauth2_settings

        cfg = dict(getattr(dj_settings, "OAUTH2_PROVIDER", {}) or {})
        if value:
            cfg["OIDC_ISS_ENDPOINT"] = value
        else:
            cfg.pop("OIDC_ISS_ENDPOINT", None)
        ctx = override_settings(OAUTH2_PROVIDER=cfg)
        ctx.enable()
        oauth2_settings.reload()
        self.addCleanup(oauth2_settings.reload)
        self.addCleanup(ctx.disable)

    # ---------- AC-19e ----------

    def test_ac19e_error_when_bcl_set_and_iss_unset(self) -> None:
        from allianceauth_oidc.checks import (
            E001_ID,
            check_oidc_iss_endpoint_when_bcl_enabled,
        )

        self._build_app_with_bcl()
        self._override_iss("")
        msgs = check_oidc_iss_endpoint_when_bcl_enabled(None)
        self.assertEqual(len(msgs), 1)
        msg = msgs[0]
        self.assertEqual(msg.id, E001_ID)
        # plan v5 m-V3-1: severity is Error, not Warning. Verify
        # via the ``level`` attribute set by ``Error()``.
        self.assertEqual(msg.level, checks.ERROR)

    # ---------- AC-19f — manage.py check raises SystemCheckError ----------

    def test_ac19f_manage_check_raises_with_e001(self) -> None:
        from io import StringIO

        from django.core.management import call_command
        from django.core.management.base import SystemCheckError

        self._build_app_with_bcl()
        self._override_iss("")
        out = StringIO()
        with self.assertRaises(SystemCheckError) as ctx:
            call_command("check", stdout=out, stderr=out)
        self.assertIn("allianceauth_oidc.E001", str(ctx.exception))

    # ---------- AC-19g — clean when iss set ----------

    def test_ac19g_clean_when_iss_endpoint_set(self) -> None:
        from allianceauth_oidc.checks import (
            check_oidc_iss_endpoint_when_bcl_enabled,
        )

        # Multiple apps with BCL set, but OIDC_ISS_ENDPOINT is pinned
        # via _override_iss — the check must remain clean regardless
        # of how many RPs registered a backchannel_logout_uri.
        for _ in range(3):
            self._build_app_with_bcl()
        self._override_iss("https://auth.example.test/o")
        msgs = check_oidc_iss_endpoint_when_bcl_enabled(None)
        self.assertEqual(msgs, [])

    def test_check_is_clean_when_no_bcl_apps(self) -> None:
        """
        Negative regression: zero apps with BCL → no error even
        with iss unset. Closes the false-positive class.
        """
        from allianceauth_oidc.checks import (
            check_oidc_iss_endpoint_when_bcl_enabled,
        )

        self._override_iss("")
        msgs = check_oidc_iss_endpoint_when_bcl_enabled(None)
        self.assertEqual(msgs, [])


class TestBackChannelLogoutTokenBuilder(OIDCTestCase):
    """
    AC-17 / AC-17a / AC-18 / AC-19 / AC-19a / AC-20 / AC-21 / AC-22
    — ``logout.build_logout_token`` shape, key resolution, byte-
    identical retries, and PII pin.
    """

    def setUp(self) -> None:
        super().setUp()
        creds = make_app(owner=self.user1)
        self.app = creds.app
        self.client_id = creds.client_id

    def _decode_unverified(self, jwt_str: str):
        """Return (header_dict, payload_dict) without signature check."""
        import base64
        import json

        def _b64(part: str) -> dict:
            pad = "=" * ((4 - len(part) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(part + pad).decode())

        header_b64, payload_b64, _sig = jwt_str.split(".")
        return _b64(header_b64), _b64(payload_b64)

    def _jwks_keyset(self):
        """Build a JWKSet from the active OIDC key for verification."""
        from jwcrypto import jwk

        active_pem = oauth2_settings.OIDC_RSA_PRIVATE_KEY
        key = jwk.JWK.from_pem(active_pem.encode())
        ks = jwk.JWKSet()
        ks.add(key)
        return ks

    # ---------- AC-17 — return shape & jti generation ----------

    def test_ac17_returns_jwt_and_jti(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, jti = build_logout_token(self.user1, self.app)
        self.assertIsInstance(token, str)
        self.assertEqual(len(token.split(".")), 3)
        self.assertIsInstance(jti, str)
        self.assertEqual(len(jti), 32)  # uuid4 hex

    def test_ac17_uses_supplied_jti_unchanged(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, jti = build_logout_token(
            self.user1, self.app, jti="deadbeef" * 4
        )
        self.assertEqual(jti, "deadbeef" * 4)
        _h, payload = self._decode_unverified(token)
        self.assertEqual(payload["jti"], "deadbeef" * 4)

    # ---------- AC-17a — SigningKeyRetiredError ----------

    def test_ac17a_unknown_kid_raises_signing_key_retired(self) -> None:
        from allianceauth_oidc.logout import (
            SigningKeyRetiredError,
            build_logout_token,
        )

        with self.assertRaises(SigningKeyRetiredError):
            build_logout_token(
                self.user1, self.app, signing_kid="not-a-real-kid"
            )

    def test_ac17a_kid_resolves_from_inactive_key_store(self) -> None:
        """
        When ``signing_kid`` matches a thumbprint in
        ``OIDC_RSA_PRIVATE_KEYS_INACTIVE``, the worker can still
        rebuild the JWT against the rotated-out key. Covers the
        retry-after-rotation case spec §2.4 requires for monotonic
        delivery.
        """
        from jwcrypto import jwk

        from allianceauth_oidc.logout import build_logout_token

        # Mint a second RSA key and treat the current active key as
        # "newly inactive" — i.e. simulate a rotation where the
        # dispatcher captured ``signing_kid`` against the old key.
        new_key = jwk.JWK.generate(kty="RSA", size=2048)
        new_pem = new_key.export_to_pem(private_key=True, password=None)
        old_pem = oauth2_settings.OIDC_RSA_PRIVATE_KEY
        old_kid = str(jwk.JWK.from_pem(old_pem.encode()).thumbprint())

        cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
        cfg["OIDC_RSA_PRIVATE_KEY"] = new_pem.decode()
        cfg["OIDC_RSA_PRIVATE_KEYS_INACTIVE"] = [old_pem]
        with override_settings(OAUTH2_PROVIDER=cfg):
            oauth2_settings.reload()
            try:
                token, _jti = build_logout_token(
                    self.user1, self.app, signing_kid=old_kid
                )
                header, _ = self._decode_unverified(token)
                self.assertEqual(header["kid"], old_kid)
            finally:
                oauth2_settings.reload()

    # ---------- AC-18 — header shape ----------

    def test_ac18_header_is_logout_plus_jwt_rs256(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        header, _ = self._decode_unverified(token)
        self.assertEqual(header["typ"], "logout+jwt")
        self.assertEqual(header["alg"], "RS256")
        self.assertIsInstance(header["kid"], str)
        self.assertGreater(len(header["kid"]), 16)  # RFC 7638 thumbprint

    # ---------- AC-19 — payload shape (closed set) ----------

    def test_ac19_payload_has_exact_keys(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        _h, payload = self._decode_unverified(token)
        self.assertEqual(
            set(payload.keys()),
            {"iss", "aud", "iat", "jti", "sub", "events"},
        )
        self.assertEqual(payload["aud"], self.client_id)
        self.assertEqual(payload["sub"], str(self.user1.pk))
        self.assertIsInstance(payload["iat"], int)

    def test_ac19_events_uri_is_literal_http_not_https(self) -> None:
        """Spec literal — ``http://`` (NOT https). Regression."""
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        _h, payload = self._decode_unverified(token)
        events = payload["events"]
        self.assertEqual(
            list(events.keys()),
            ["http://schemas.openid.net/event/backchannel-logout"],
        )
        first_event_key = next(iter(events))
        self.assertEqual(events[first_event_key], {})

    # ---------- AC-19a — iss from OIDC_ISS_ENDPOINT ----------

    def test_ac19a_iss_uses_oidc_iss_endpoint_setting(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        _h, payload = self._decode_unverified(token)
        # test_settingsAA4 pins OIDC_ISS_ENDPOINT to this value.
        self.assertEqual(payload["iss"], "https://auth.example.test/o")

    # ---------- AC-20 — nonce MUST NOT ----------

    def test_ac20_payload_never_contains_nonce(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        _h, payload = self._decode_unverified(token)
        self.assertNotIn("nonce", payload)

    # ---------- AC-21 — PII pin ----------

    def test_ac21_payload_never_contains_pii(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        _h, payload = self._decode_unverified(token)
        forbidden = {
            "email",
            "name",
            "picture",
            "groups",
            "locale",
            "scope",
            "client_secret",
            "sid",
        }
        leaked = forbidden & set(payload.keys())
        self.assertEqual(leaked, set(), msg=payload)

    # ---------- AC-22 — JWT verifies against JWKS ----------

    def test_ac22_jwt_verifies_against_jwks(self) -> None:
        from jwcrypto import jwt as jw

        from allianceauth_oidc.logout import build_logout_token

        token, _ = build_logout_token(self.user1, self.app)
        verifier = jw.JWT(jwt=token, key=self._jwks_keyset())
        # If verification fails ``jw.JWT(jwt=..., key=...)`` raises.
        verifier.token.deserialize(token, key=self._jwks_keyset())

    # ---------- Byte-identical retries (AC-30 helper) ----------

    def test_byte_identical_retry_when_jti_and_iat_pinned(self) -> None:
        from allianceauth_oidc.logout import build_logout_token

        jti = "feedbabe" * 4
        iat = 1_700_000_000
        a, _ = build_logout_token(self.user1, self.app, jti=jti, iat=iat)
        b, _ = build_logout_token(self.user1, self.app, jti=jti, iat=iat)
        self.assertEqual(a, b)


class _CapturedDispatches:
    """
    Test helper — connects a sink to ``oidc_logout_required`` (after
    disconnecting the production dispatcher so no real Celery task
    runs) and records every ``(application_pk, reason)`` pair.

    Reuses ``DEFAULT_LOGOUT_DISPATCH_UID`` so the production
    dispatcher is restored at ``__exit__``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[int, str | None]] = []

    def __enter__(self):
        oidc_signals.oidc_logout_required.disconnect(
            dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
        )
        oidc_signals.connect_default_logout_receiver(self._sink)
        return self

    def __exit__(self, exc_type, exc, tb):
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        oidc_signals.oidc_logout_required.disconnect(
            dispatch_uid=DEFAULT_LOGOUT_DISPATCH_UID
        )
        oidc_signals.connect_default_logout_receiver(
            dispatch_backchannel_logout
        )

    def _sink(self, sender, user, application, reason=None, **kwargs):
        self.calls.append((application.pk, reason))


class TestBackChannelLogoutTriggers(OIDCTestCase):
    """
    AC-12 / AC-13 / AC-14 / AC-15 / AC-16 — the five v1 trigger
    sites emit ``oidc_logout_required`` exactly when the plan says
    they should, per ``(user, application)`` with active tokens.
    """

    def _make_active_token(self, *, app, user, kind="access"):
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        if kind == "access":
            AccessToken = get_access_token_model()
            return AccessToken.objects.create(
                user=user,
                application=app,
                token=f"tok-{user.pk}-{app.pk}",
                expires=timezone.now() + timedelta(hours=1),
                scope="openid",
            )
        RefreshToken = get_refresh_token_model()
        return RefreshToken.objects.create(
            user=user,
            application=app,
            token=f"refresh-{user.pk}-{app.pk}",
        )

    # ---------- AC-12 — oidc_revoke_user_tokens command ----------

    def test_ac12_revoke_command_emits_signal_once_per_app(self) -> None:
        creds_a = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp-a.example.com/bcl",
        )
        creds_b = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp-b.example.com/bcl",
        )
        self._make_active_token(app=creds_a.app, user=self.user1)
        self._make_active_token(
            app=creds_a.app, user=self.user1, kind="refresh"
        )
        self._make_active_token(app=creds_b.app, user=self.user1)
        with _CapturedDispatches() as cap:
            call_command("oidc_revoke_user_tokens", "--username=User1")
        seen_apps = {pk for (pk, _) in cap.calls}
        self.assertEqual(seen_apps, {creds_a.app.pk, creds_b.app.pk})
        # Dedup — only ONE signal per (user, app) even though app_a
        # contributed both access AND refresh tokens.
        self.assertEqual(len(cap.calls), 2)
        for _pk, reason in cap.calls:
            self.assertEqual(reason, "user_revoked")

    # ---------- AC-13 — User.is_active flip ----------

    def test_ac13_user_deactivate_fires_signal(self) -> None:
        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self._make_active_token(app=creds.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.is_active = False
            self.user1.save()
        # AA's state recomputation can cascade ``state_changed`` on a
        # ``User.is_active`` flip; per OIDC BCL 1.0 §2.6 multiple
        # logout_tokens for the same ``(user, app)`` are spec-permitted
        # (RPs dedup on ``jti``). Filter to the reason this test
        # exercises directly.
        user_deactivated = [
            (pk, r) for (pk, r) in cap.calls if r == "user_deactivated"
        ]
        self.assertEqual(
            user_deactivated, [(creds.app.pk, "user_deactivated")]
        )

    def test_ac13_user_reactivate_does_not_fire(self) -> None:
        """False -> True (re-activation) MUST NOT trigger logout."""
        self.user1.is_active = False
        self.user1.save()
        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self._make_active_token(app=creds.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.is_active = True
            self.user1.save()
        # ``user_deactivated`` MUST NOT fire on a False→True transition.
        # AA cascades may legitimately fire other reasons (e.g.
        # ``state_changed`` on profile recomputation); those are
        # separately exercised in ``test_ac15``.
        deactivate_calls = [
            (pk, r) for (pk, r) in cap.calls if r == "user_deactivated"
        ]
        self.assertEqual(deactivate_calls, [])

    # ---------- AC-14 — groups m2m change ----------

    def test_ac14_group_removal_fires_when_policy_now_denies(self) -> None:
        from django.contrib.auth.models import Group

        grp = Group.objects.create(name="rp-only")
        self.user1.groups.add(grp)
        creds = make_app(
            owner=self.user1,
            groups=["rp-only"],
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self._make_active_token(app=creds.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.groups.remove(grp)
        self.assertEqual(cap.calls, [(creds.app.pk, "groups_changed")])

    # ---------- AC-15 — AA state_changed ----------

    def test_ac15_state_change_fires_when_policy_now_denies(self) -> None:
        from allianceauth.authentication.models import State
        from allianceauth.authentication.signals import state_changed

        creds = make_app(
            owner=self.user1,
            states=["Blue"],  # User1 is Member, so this denies
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self._make_active_token(app=creds.app, user=self.user1)
        with _CapturedDispatches() as cap:
            state_changed.send(
                sender=type(self.user1),
                user=self.user1,
                state=State.objects.get(name="Member"),
            )
        state_calls = [
            (pk, r) for (pk, r) in cap.calls if r == "state_changed"
        ]
        self.assertEqual(state_calls, [(creds.app.pk, "state_changed")])

    # ---------- AC-16 — pre_delete + post_delete cascade ----------

    def test_ac16_user_delete_fires_per_app(self) -> None:
        from allianceauth_oidc import receivers as bcl_receivers

        # DOT cascades ``Application.user`` (FK on_delete=CASCADE),
        # so an app owned by the user we're about to delete vanishes
        # before ``post_delete`` runs and Application.objects.filter
        # finds nothing. Realistic ops scenario: an admin (different
        # user) owns the app and only ``self.user1`` had a session
        # with it.
        creds = make_app(
            owner=self.user2,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self._make_active_token(app=creds.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.delete()
        delete_calls = [
            (pk, r) for (pk, r) in cap.calls if r == "user_deleted"
        ]
        self.assertEqual(delete_calls, [(creds.app.pk, "user_deleted")])
        # Weakref dict is cleaned up — no instance keys leak after
        # delete completes. The dict is module-level so we read it
        # directly.
        self.assertEqual(len(bcl_receivers._PENDING_LOGOUTS), 0)

    # ---------- AC-31 — multi-RP fanout skips blank URI ----------

    def test_ac31_multi_rp_fanout_skips_blank_uri(self) -> None:
        """
        Plan §5.4 AC-31: 3 apps (A: uri set, B: blank, C: uri set);
        a single trigger event signals exactly 2 RPs — the blank URI
        is invisible to the fanout because every RP's signal is
        gated downstream by the dispatcher's
        ``backchannel_logout_uri`` check (logout.py:230).

        We watch the receiver-side signal here; the dispatcher's
        URI-blank gate is unit-tested separately in
        ``TestBackChannelLogoutCeleryTask`` (the task is only
        enqueued when the URI is non-blank).
        """
        creds_a = make_app(
            owner=self.user2,
            backchannel_logout_uri="https://rp-a.example.com/bcl",
        )
        creds_b = make_app(owner=self.user2, backchannel_logout_uri="")
        creds_c = make_app(
            owner=self.user2,
            backchannel_logout_uri="https://rp-c.example.com/bcl",
        )
        self._make_active_token(app=creds_a.app, user=self.user1)
        self._make_active_token(app=creds_b.app, user=self.user1)
        self._make_active_token(app=creds_c.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.is_active = False
            self.user1.save()
        # Filter to the trigger reason this test exercises (AA's
        # state-recompute cascade can add unrelated ``state_changed``
        # signals — see test_ac13). Receivers fire for every RP the
        # user has tokens with; the URI-blank skip happens one layer
        # deeper inside ``dispatch_backchannel_logout``.
        deact_apps = {pk for (pk, r) in cap.calls if r == "user_deactivated"}
        self.assertEqual(
            deact_apps,
            {creds_a.app.pk, creds_b.app.pk, creds_c.app.pk},
        )

    def test_ac31_dispatcher_drops_blank_uri(self) -> None:
        """
        AC-31 sibling: the dispatcher itself MUST skip when
        ``backchannel_logout_uri`` is blank — ``apply_async`` is
        never invoked for that RP.
        """
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        blank_app = make_app(owner=self.user2, backchannel_logout_uri="").app
        with (
            mock.patch(
                "allianceauth_oidc.tasks.send_logout_token.apply_async"
            ) as apply_async,
            self.captureOnCommitCallbacks(execute=True),
        ):
            dispatch_backchannel_logout(
                sender=type(self.user1),
                user=self.user1,
                application=blank_app,
                reason="user_revoked",
            )
        apply_async.assert_not_called()

    # ---------- AC-32 — state scoping: only affected RPs ----------

    def test_ac32_group_removal_scopes_to_gated_apps_only(self) -> None:
        """
        Plan §5.4 AC-32: user removed from group X. Apps that gate on
        group X (and which the user is therefore newly denied for)
        get tasks; apps with no policy constraints do not.

        ``self.user1`` needs the ``access_oidc`` global permission
        otherwise ``AccessPolicy.is_allowed`` denies UNIVERSALLY
        (not "newly denied") and both apps would fire — which would
        defeat the scope-narrowing assertion this test makes.
        """
        from django.contrib.auth.models import Group

        self.grant_oidc_access(self.user1)
        grp = Group.objects.create(name="bcl-scoping-x")
        self.user1.groups.add(grp)
        gated = make_app(
            owner=self.user2,
            groups=["bcl-scoping-x"],
            backchannel_logout_uri="https://rp-gated.example.com/bcl",
        )
        open_app = make_app(
            owner=self.user2,
            backchannel_logout_uri="https://rp-open.example.com/bcl",
        )
        self._make_active_token(app=gated.app, user=self.user1)
        self._make_active_token(app=open_app.app, user=self.user1)
        with _CapturedDispatches() as cap:
            self.user1.groups.remove(grp)
        groups_changed = [pk for (pk, r) in cap.calls if r == "groups_changed"]
        self.assertEqual(groups_changed, [gated.app.pk])
        self.assertNotIn(open_app.app.pk, groups_changed)


class TestBackChannelLogoutCeleryTask(OIDCTestCase):
    """
    AC-23 / AC-24 / AC-24a / AC-25 / AC-26 / AC-26a /
    AC-27 / AC-28 / AC-28a / AC-29 / AC-29a /
    AC-31 / AC-32 / AC-39 — the worker side.
    """

    def setUp(self) -> None:
        super().setUp()
        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self.app = creds.app

    def _active_signing_kid(self) -> str:
        from jwcrypto import jwk

        pem = oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode()
        return str(jwk.JWK.from_pem(pem).thumbprint())

    def _call_task(
        self, *, status_code: int = 200, raises: Exception | None = None
    ):
        """
        Invoke the task synchronously with a stubbed
        ``requests.post`` returning ``status_code`` (or raising).
        Returns the captured oidc_logout_dispatched signals.
        """
        from allianceauth_oidc.signals import oidc_logout_dispatched
        from allianceauth_oidc.tasks import send_logout_token

        dispatches: list[dict] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            dispatches.append(
                {
                    "jti": jti,
                    "success": success,
                    "attempt_count": attempt_count,
                    "reason": kw.get("reason"),
                    "application_pk": application.pk,
                }
            )

        oidc_logout_dispatched.connect(sink, dispatch_uid="test.sink")
        try:
            with mock.patch("allianceauth_oidc.tasks.requests.post") as post:
                if raises is not None:
                    post.side_effect = raises
                else:
                    post.return_value = mock.MagicMock(status_code=status_code)
                send_logout_token(
                    user_pk=self.user1.pk,
                    application_pk=self.app.pk,
                    jti="deadbeef" * 4,
                    signing_kid=self._active_signing_kid(),
                    iat=1_700_000_000,
                )
                return dispatches, post
        finally:
            oidc_logout_dispatched.disconnect(dispatch_uid="test.sink")

    # ---------- AC-23 — task name constant ----------

    def test_ac23_task_registered_under_constant_name(self) -> None:
        from allianceauth_oidc.constants import TASK_SEND_LOGOUT_TOKEN
        from allianceauth_oidc.tasks import send_logout_token

        self.assertEqual(send_logout_token.name, TASK_SEND_LOGOUT_TOKEN)

    # ---------- AC-24 — task signature ----------

    def test_ac24_task_signature_is_arity_5(self) -> None:
        from allianceauth_oidc.tasks import send_logout_token

        # ``bind=True`` gives ``self`` as the first param; user-facing
        # args are 5 scalars (no JWT, no sid).
        params = list(send_logout_token.__wrapped__.__code__.co_varnames[:6])
        self.assertEqual(
            params,
            [
                "self",
                "user_pk",
                "application_pk",
                "jti",
                "signing_kid",
                "iat",
            ],
        )

    # ---------- AC-24a — task args are scalars ----------

    def test_ac24a_apply_async_args_are_typed_scalars(self) -> None:
        """
        Plan §5.4 AC-24a: ``apply_async.args`` MUST be exactly five
        scalars typed (int, int, str, str, int). No JWT, no
        credentials in the broker payload.
        """
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        captured: dict[str, tuple] = {}

        def fake_apply_async(*args, **kwargs):
            captured["args"] = kwargs.get("args") or args[0]

        with (
            mock.patch(
                "allianceauth_oidc.tasks.send_logout_token.apply_async",
                side_effect=fake_apply_async,
            ),
            self.captureOnCommitCallbacks(execute=True),
        ):
            dispatch_backchannel_logout(
                sender=type(self.user1),
                user=self.user1,
                application=self.app,
                reason="user_revoked",
            )
        args = captured["args"]
        self.assertEqual(len(args), 5)
        # (user_pk, application_pk, jti, signing_kid, iat)
        self.assertIsInstance(args[0], int)
        self.assertIsInstance(args[1], int)
        self.assertIsInstance(args[2], str)
        self.assertIsInstance(args[3], str)
        self.assertIsInstance(args[4], int)

    # ---------- AC-26 — outbound HTTP discipline ----------

    def test_ac26_posts_form_encoded_with_logout_token_field(self) -> None:
        _dispatches, post = self._call_task(status_code=200)
        post.assert_called_once()
        kwargs = post.call_args.kwargs
        self.assertEqual(
            kwargs["headers"]["Content-Type"],
            "application/x-www-form-urlencoded",
        )
        self.assertIn(
            "allianceauth-oidc/",
            kwargs["headers"]["User-Agent"],
        )
        self.assertIn("logout_token", kwargs["data"])
        # AC-26a: no follow-redirects, bounded timeouts.
        self.assertEqual(kwargs["allow_redirects"], False)
        self.assertEqual(kwargs["timeout"], (5, 10))

    # ---------- AC-27 — 2xx success ----------

    def test_ac27_2xx_fires_success(self) -> None:
        dispatches, _ = self._call_task(status_code=204)
        self.assertEqual(len(dispatches), 1)
        self.assertTrue(dispatches[0]["success"])
        self.assertIsNone(dispatches[0]["reason"])

    # ---------- AC-28 — 4xx no retry ----------

    def test_ac28_4xx_no_retry(self) -> None:
        dispatches, _ = self._call_task(status_code=404)
        self.assertEqual(len(dispatches), 1)
        self.assertFalse(dispatches[0]["success"])
        self.assertEqual(dispatches[0]["reason"], "rp_client_error")

    # ---------- AC-28a — 3xx blocked ----------

    def test_ac28a_3xx_blocked(self) -> None:
        dispatches, _ = self._call_task(status_code=302)
        self.assertEqual(dispatches[0]["reason"], "redirect_blocked")
        self.assertFalse(dispatches[0]["success"])

    # ---------- AC-29 — 5xx final retry exhaustion ----------

    def test_ac29_5xx_retries_exhausted_emits_audit(self) -> None:
        """
        Plan §5.4 AC-29: when ``self.request.retries`` has reached
        ``self.max_retries`` and the RP still returns 5xx, the task
        records ``reason="retries_exhausted"`` and returns without
        re-raising (which would re-fire Celery autoretry).
        """
        from allianceauth_oidc.signals import oidc_logout_dispatched
        from allianceauth_oidc.tasks import send_logout_token

        dispatches: list[dict] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            dispatches.append(
                {
                    "success": success,
                    "reason": kw.get("reason"),
                    "attempt_count": attempt_count,
                }
            )

        # The task descriptor exposes ``request`` as a property on the
        # bound Task instance; the production body reads
        # ``self.request.retries`` and ``self.max_retries``. Patching
        # the property descriptor on the class works around Celery's
        # PromiseProxy ``__setattr__`` block. Using ``side_effect=`` on
        # a sentinel ``Request`` keeps the test framework's own
        # bookkeeping (``self.update_state`` etc.) untouched.
        max_retries = send_logout_token.max_retries
        fake_request = mock.MagicMock()
        fake_request.retries = max_retries

        # ``send_logout_token`` is a Celery ``PromiseProxy``; the real
        # Task class lives behind ``_get_current_object()``. Patch
        # ``request`` on THAT class — the property descriptor is what
        # the production task body reads via ``self.request.retries``.
        task_cls = type(send_logout_token._get_current_object())

        oidc_logout_dispatched.connect(sink, dispatch_uid="test.sink.ac29")
        try:
            with (
                mock.patch.object(
                    task_cls,
                    "request",
                    new_callable=mock.PropertyMock,
                    return_value=fake_request,
                ),
                mock.patch("allianceauth_oidc.tasks.requests.post") as post,
            ):
                post.return_value = mock.MagicMock(status_code=503)
                send_logout_token(
                    user_pk=self.user1.pk,
                    application_pk=self.app.pk,
                    jti="deadbeef" * 4,
                    signing_kid=self._active_signing_kid(),
                    iat=1_700_000_000,
                )
        finally:
            oidc_logout_dispatched.disconnect(dispatch_uid="test.sink.ac29")
        self.assertEqual(len(dispatches), 1)
        self.assertFalse(dispatches[0]["success"])
        self.assertEqual(dispatches[0]["reason"], "retries_exhausted")

    # ---------- AC-29a — signing kid retired ----------

    def test_ac29a_signing_kid_retired(self) -> None:
        from allianceauth_oidc.signals import oidc_logout_dispatched
        from allianceauth_oidc.tasks import send_logout_token

        dispatches: list[dict] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            dispatches.append(
                {
                    "success": success,
                    "reason": kw.get("reason"),
                }
            )

        oidc_logout_dispatched.connect(sink, dispatch_uid="test.sink.kid")
        try:
            # Pass a kid that exists in NEITHER active nor inactive
            # key stores — build_logout_token raises
            # SigningKeyRetiredError; the task catches it.
            with mock.patch("allianceauth_oidc.tasks.requests.post") as post:
                send_logout_token(
                    user_pk=self.user1.pk,
                    application_pk=self.app.pk,
                    jti="deadbeef" * 4,
                    signing_kid="not-a-real-kid",
                    iat=1_700_000_000,
                )
                post.assert_not_called()  # AC-29a — no HTTP call
        finally:
            oidc_logout_dispatched.disconnect(dispatch_uid="test.sink.kid")
        self.assertEqual(
            dispatches,
            [{"success": False, "reason": "signing_kid_retired"}],
        )

    # ---------- AC-30 (helper covered by US-BCL-004) ----------
    # The byte-identical retry already verified in
    # TestBackChannelLogoutTokenBuilder; the worker just plumbs the
    # arguments through.

    # ---------- AC-39 — broker_unavailable ----------

    def test_ac39_broker_unavailable_fires_audit_signal(self) -> None:
        from allianceauth_oidc.logout import dispatch_backchannel_logout
        from allianceauth_oidc.signals import oidc_logout_dispatched

        dispatches: list[dict] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            dispatches.append({"reason": kw.get("reason")})

        oidc_logout_dispatched.connect(sink, dispatch_uid="test.sink.broker")
        # ``transaction.on_commit`` callbacks are deferred to the
        # OUTERMOST commit, which never fires under ``TestCase``
        # (transactions are rolled back). ``captureOnCommitCallbacks(
        # execute=True)`` is the documented way to run them
        # synchronously inside a test.
        try:
            with (
                mock.patch(
                    "allianceauth_oidc.tasks.send_logout_token.apply_async",
                    side_effect=RuntimeError("broker down"),
                ),
                self.captureOnCommitCallbacks(execute=True),
            ):
                dispatch_backchannel_logout(
                    sender=type(self.user1),
                    user=self.user1,
                    application=self.app,
                    reason="user_revoked",
                )
            self.assertEqual(dispatches, [{"reason": "broker_unavailable"}])
        finally:
            oidc_logout_dispatched.disconnect(dispatch_uid="test.sink.broker")


class TestBackChannelLogoutDiscovery(OIDCTestCase):
    """
    AC-33 / AC-34 — discovery doc emits exactly
    ``backchannel_logout_supported: true`` and NEVER
    ``backchannel_logout_session_supported``.
    """

    DISCOVERY_URL = "/o/.well-known/openid-configuration/"

    def test_ac33_backchannel_logout_supported_true(self) -> None:
        import json

        resp = self.client.get(self.DISCOVERY_URL)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertIs(data.get("backchannel_logout_supported"), True)

    def test_ac34_backchannel_logout_session_supported_absent(self) -> None:
        """v5 path-b regression: session-scoped flag MUST NOT leak."""
        import json

        resp = self.client.get(self.DISCOVERY_URL)
        data = json.loads(resp.content)
        self.assertNotIn("backchannel_logout_session_supported", data)

    def test_existing_discovery_fields_preserved(self) -> None:
        """Negative regression — pre-existing fields stay intact."""
        import json

        resp = self.client.get(self.DISCOVERY_URL)
        data = json.loads(resp.content)
        for key in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "grant_types_supported",
            "claim_types_supported",
            "access_token_signing_alg_values_supported",
        ):
            self.assertIn(key, data, msg=key)


class TestBackChannelLogoutLogging(OIDCTestCase):
    """
    AC-35 / AC-36 / AC-38 — all BCL log lines route through
    ``build_logout_debug_meta``; no token/secret material leaks
    into captured log output.

    AC-36 covers four code paths: success (2xx), redirect (3xx),
    RP client error (4xx), and signing-kid retired. Three of these
    are exercised below via ``assertLogs(level=WARNING)``; the 2xx
    branch deliberately emits no WARN-level line at
    ``tasks.py:send_logout_token`` (success is an audit-only event,
    not a log event), so a fourth ``assertLogs`` test would error
    with "no logs captured" instead of asserting absence. The audit-
    signal coverage for success lives in
    ``test_ac38_dispatched_signal_fires_on_success`` below.
    """

    def setUp(self) -> None:
        super().setUp()
        creds = make_app(
            owner=self.user1,
            debug_mode=True,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self.app = creds.app
        self.client_secret = creds.client_secret

    # ---------- AC-35 — TypedDict shape ----------

    def test_ac35_logout_debug_meta_keys_are_allow_listed(self) -> None:
        from allianceauth_oidc.utils import (
            LogoutDebugMeta,
            build_logout_debug_meta,
        )

        meta = build_logout_debug_meta(
            application=self.app,
            jti="deadbeef" * 4,
            status_code=200,
            reason="ok",
        )
        # The TypedDict's documented keys are the allow-list.
        self.assertEqual(
            set(meta.keys()),
            set(typing.get_type_hints(LogoutDebugMeta).keys()),
        )
        # Spot-check field plumbing.
        self.assertEqual(meta["application_pk"], self.app.pk)
        self.assertEqual(
            meta["backchannel_logout_uri"],
            "https://rp.example.com/bcl",
        )
        self.assertEqual(meta["jti"], "deadbeef" * 4)
        self.assertEqual(meta["status_code"], 200)
        self.assertEqual(meta["reason"], "ok")

    def test_ac35_helper_handles_missing_application(self) -> None:
        from allianceauth_oidc.utils import build_logout_debug_meta

        meta = build_logout_debug_meta(jti="x", reason="r")
        self.assertIsNone(meta["application_pk"])
        self.assertIsNone(meta["application_name"])
        self.assertIsNone(meta["backchannel_logout_uri"])

    # ---------- AC-36 — secret-pin across all dispatch branches ----------

    def _exercise_status_branch(self, *, status_code: int) -> str:
        from allianceauth_oidc.tasks import send_logout_token

        with (
            self.assertLogs(
                "extensions.allianceauth_oidc.tasks", level=logging.WARNING
            ) as captured,
            mock.patch("allianceauth_oidc.tasks.requests.post") as post,
        ):
            post.return_value = mock.MagicMock(status_code=status_code)
            send_logout_token(
                user_pk=self.user1.pk,
                application_pk=self.app.pk,
                jti="deadbeef" * 4,
                signing_kid=_active_kid(),
                iat=1_700_000_000,
            )
        return "\n".join(captured.output)

    def test_ac36_3xx_branch_log_has_no_token_material(self) -> None:
        joined = self._exercise_status_branch(status_code=302)
        for forbidden in (
            self.client_secret,
            "logout_token=",  # JWT body markers in form-encoded body
            "access_token",
            "refresh_token",
            "id_token",
        ):
            self.assertNotIn(forbidden, joined, msg=joined)

    def test_ac36_4xx_branch_log_has_no_token_material(self) -> None:
        joined = self._exercise_status_branch(status_code=404)
        for forbidden in (
            self.client_secret,
            "logout_token=",
            "access_token",
            "refresh_token",
            "id_token",
        ):
            self.assertNotIn(forbidden, joined, msg=joined)

    def test_ac36_kid_retired_branch_log_has_no_token_material(self) -> None:
        from allianceauth_oidc.tasks import send_logout_token

        with (
            self.assertLogs(
                "extensions.allianceauth_oidc.tasks", level=logging.WARNING
            ) as captured,
            mock.patch("allianceauth_oidc.tasks.requests.post") as post,
        ):
            send_logout_token(
                user_pk=self.user1.pk,
                application_pk=self.app.pk,
                jti="deadbeef" * 4,
                signing_kid="not-a-real-kid",
                iat=1_700_000_000,
            )
            post.assert_not_called()
        joined = "\n".join(captured.output)
        for forbidden in (
            self.client_secret,
            "access_token",
            "refresh_token",
            "id_token",
        ):
            self.assertNotIn(forbidden, joined, msg=joined)

    # ---------- AC-38 — audit signal fires on every attempt ----------

    def test_ac38_dispatched_signal_fires_on_success(self) -> None:
        from allianceauth_oidc.signals import oidc_logout_dispatched
        from allianceauth_oidc.tasks import send_logout_token

        seen: list[bool] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            seen.append(success)

        oidc_logout_dispatched.connect(sink, dispatch_uid="test.sink.ac38")
        try:
            with mock.patch("allianceauth_oidc.tasks.requests.post") as post:
                post.return_value = mock.MagicMock(status_code=200)
                send_logout_token(
                    user_pk=self.user1.pk,
                    application_pk=self.app.pk,
                    jti="deadbeef" * 4,
                    signing_kid=_active_kid(),
                    iat=1_700_000_000,
                )
        finally:
            oidc_logout_dispatched.disconnect(dispatch_uid="test.sink.ac38")
        self.assertEqual(seen, [True])


def _active_kid() -> str:
    """RFC 7638 thumbprint of the test settings' active signing key."""
    from jwcrypto import jwk

    pem = oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode()
    return str(jwk.JWK.from_pem(pem).thumbprint())


# ----------------------------------------------------------------------
# US-OROF — backchannel_logout_on_revoke_only per-app flag
# Plan: .omc/plans/bcl-on-revoke-only-plan-v1.md
# ----------------------------------------------------------------------


class TestBackChannelLogoutOnRevokeOnlyModel(OIDCTestCase):
    """US-OROF-001 — model field shape (AC-1)."""

    def test_field_exists_default_false_with_help_text(self) -> None:
        field = AllianceAuthApplication._meta.get_field(
            "backchannel_logout_on_revoke_only"
        )
        from django.db.models import BooleanField

        self.assertIsInstance(field, BooleanField)
        self.assertEqual(field.default, False)
        # ``verbose_name`` / ``help_text`` are __proxy__ objects when
        # wrapped in ``gettext_lazy``; cast to str to compare content
        # and ensure they are non-empty (i18n hooks present).
        self.assertTrue(str(field.verbose_name))
        self.assertTrue(str(field.help_text))


def _make_app_with_flag(
    test_case: OIDCTestCase,
    *,
    on_revoke_only: bool,
    uri: str = "https://rp.example.com/bcl",
) -> AllianceAuthApplication:
    """
    Factory wrapper — create an app with the on_revoke_only flag set
    AND a non-blank BCL URI (otherwise the blank-URI check short-
    circuits the dispatcher and gating never runs).
    """
    creds = make_app(owner=test_case.user1, backchannel_logout_uri=uri)
    creds.app.backchannel_logout_on_revoke_only = on_revoke_only
    creds.app.save()
    return creds.app


class TestBackChannelLogoutOnRevokeOnlyFlag(OIDCTestCase):
    """
    US-OROF-002 / US-OROF-003 / US-OROF-004 / US-OROF-005 —
    dispatcher gating, default-False regression, flag=True paths.

    Tests call ``dispatch_backchannel_logout`` directly (the default
    receiver wired into ``oidc_logout_required`` at app init) and
    assert on the ``send_logout_token.apply_async`` mock the same
    way ``test_ac24a_apply_async_args_are_typed_scalars`` does.
    """

    def _dispatch(
        self,
        *,
        app: AllianceAuthApplication,
        reason: str,
    ) -> mock.MagicMock:
        """
        Invoke ``dispatch_backchannel_logout`` with a stubbed
        ``send_logout_token.apply_async`` and return the mock so
        callers can inspect call_count / call_args.
        """
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        with (
            mock.patch(
                "allianceauth_oidc.tasks.send_logout_token.apply_async"
            ) as apply_async,
            self.captureOnCommitCallbacks(execute=True),
        ):
            dispatch_backchannel_logout(
                sender=type(self.user1),
                user=self.user1,
                application=app,
                reason=reason,
            )
        return apply_async

    # ---------- US-OROF-003 — default False preserves v1 behavior ----------

    def _default_false_fires_for(self, reason: str) -> None:
        app = _make_app_with_flag(self, on_revoke_only=False)
        apply_async = self._dispatch(app=app, reason=reason)
        apply_async.assert_called_once()

    def test_default_false_preserves_v1_behavior_for_user_revoked(
        self,
    ) -> None:
        self._default_false_fires_for("user_revoked")

    def test_default_false_preserves_v1_behavior_for_user_deactivated(
        self,
    ) -> None:
        self._default_false_fires_for("user_deactivated")

    def test_default_false_preserves_v1_behavior_for_groups_changed(
        self,
    ) -> None:
        self._default_false_fires_for("groups_changed")

    def test_default_false_preserves_v1_behavior_for_state_changed(
        self,
    ) -> None:
        self._default_false_fires_for("state_changed")

    def test_default_false_preserves_v1_behavior_for_user_deleted(
        self,
    ) -> None:
        self._default_false_fires_for("user_deleted")

    # ---------- US-OROF-004 — flag=True allows explicit revoke ----------

    def test_flag_true_allows_user_revoked(self) -> None:
        app = _make_app_with_flag(self, on_revoke_only=True)
        apply_async = self._dispatch(app=app, reason="user_revoked")
        apply_async.assert_called_once()

    # ---------- US-OROF-005 — flag=True skips 4 lifecycle reasons ----------

    def _flag_true_skips(self, reason: str) -> None:
        app = _make_app_with_flag(self, on_revoke_only=True)
        apply_async = self._dispatch(app=app, reason=reason)
        apply_async.assert_not_called()

    def test_flag_true_skips_user_deactivated(self) -> None:
        self._flag_true_skips("user_deactivated")

    def test_flag_true_skips_groups_changed(self) -> None:
        self._flag_true_skips("groups_changed")

    def test_flag_true_skips_state_changed(self) -> None:
        self._flag_true_skips("state_changed")

    def test_flag_true_skips_user_deleted(self) -> None:
        self._flag_true_skips("user_deleted")

    # ---------- US-OROF-005 / AC-7 — silent skip (no audit signal) ----------

    def test_skipped_events_emit_no_dispatched_signal(self) -> None:
        """
        AC-7: when gating skips, ``oidc_logout_dispatched`` MUST NOT
        be emitted. Audit log stays clean for default-False
        deployments and only carries real dispatch outcomes.
        """
        from allianceauth_oidc.signals import oidc_logout_dispatched

        app = _make_app_with_flag(self, on_revoke_only=True)
        captured: list[dict] = []

        def sink(sender, application, jti, success, attempt_count, **kw):
            captured.append(
                {
                    "reason": kw.get("reason"),
                    "success": success,
                    "application_pk": application.pk,
                }
            )

        oidc_logout_dispatched.connect(
            sink, dispatch_uid="test.sink.onrevokeonly"
        )
        try:
            self._dispatch(app=app, reason="user_deactivated")
            self._dispatch(app=app, reason="groups_changed")
            self._dispatch(app=app, reason="state_changed")
            self._dispatch(app=app, reason="user_deleted")
        finally:
            oidc_logout_dispatched.disconnect(
                dispatch_uid="test.sink.onrevokeonly"
            )
        self.assertEqual(
            captured,
            [],
            "AC-7: skipped events MUST NOT emit oidc_logout_dispatched",
        )

    # ---------- US-OROF-002 — gating is centralized in the dispatcher ----------

    def test_custom_signal_sender_with_non_revoke_reason_is_gated(
        self,
    ) -> None:
        """
        AC-6: gating lives in the dispatcher, not the receivers.
        A custom signal sender that picks an unrecognised reason
        (e.g. ``"custom_audit_event"``) is treated as non-revoke
        and silently skipped when the flag is True.
        """
        app = _make_app_with_flag(self, on_revoke_only=True)
        apply_async = self._dispatch(app=app, reason="custom_audit_event")
        apply_async.assert_not_called()


class TestBackChannelLogoutOnRevokeOnlyLogging(OIDCTestCase):
    """US-OROF-006 — debug_mode-gated log on skipped events (AC-8)."""

    _LOG_NAME = "extensions.allianceauth_oidc.logout"
    _SKIP_SUBSTR = "skipped by on_revoke_only flag"

    def _dispatch_skipped(
        self,
        *,
        debug_mode: bool,
        reason: str = "user_deactivated",
    ) -> AllianceAuthApplication:
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        creds.app.backchannel_logout_on_revoke_only = True
        creds.app.debug_mode = debug_mode
        creds.app.save()
        with self.captureOnCommitCallbacks(execute=True):
            dispatch_backchannel_logout(
                sender=type(self.user1),
                user=self.user1,
                application=creds.app,
                reason=reason,
            )
        return creds.app

    def test_skip_logged_at_info_when_debug_mode(self) -> None:
        """
        AC-8a: with ``debug_mode=True`` on the RP, ``app_log`` routes
        to INFO. The captured INFO log MUST contain the literal
        substring marker AND the reason value.
        """
        with self.assertLogs(self._LOG_NAME, level=logging.INFO) as ctx:
            self._dispatch_skipped(debug_mode=True, reason="user_deactivated")
        joined = "\n".join(ctx.output)
        self.assertIn(self._SKIP_SUBSTR, joined)
        self.assertIn("user_deactivated", joined)

    def test_skip_silent_when_debug_mode_false(self) -> None:
        """
        AC-8b: with ``debug_mode=False`` on the RP, ``app_log`` routes
        to DEBUG. Capturing at INFO level MUST find NO log entries
        bearing the skip substring marker.
        """
        # ``assertNoLogs`` raises if any log at the given level is
        # emitted; pair it with a captured-output check at INFO to
        # confirm the skip marker is absent.
        logger = logging.getLogger(self._LOG_NAME)
        handler = logging.StreamHandler(StringIO())
        handler.setLevel(logging.INFO)
        prior_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            self._dispatch_skipped(debug_mode=False, reason="user_deactivated")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(prior_level)
        captured = typing.cast("StringIO", handler.stream).getvalue()
        self.assertNotIn(self._SKIP_SUBSTR, captured)


class TestBackChannelLogoutOnRevokeOnlyAdmin(OIDCTestCase):
    """US-OROF-007 — admin exposes flag in list_filter (AC-9)."""

    def test_admin_lists_field_in_list_filter(self) -> None:
        from allianceauth_oidc.admin import ApplicationAdmin

        self.assertIn(
            "backchannel_logout_on_revoke_only",
            ApplicationAdmin.list_filter,
        )


class TestBackChannelLogoutOnRevokeOnlyDocs(OIDCTestCase):
    """US-OROF-008 / US-OROF-009 — docs describe the flag (AC-10)."""

    _DOCS_EN = "docs/BACK_CHANNEL_LOGOUT.md"
    _DOCS_RU = "docs/BACK_CHANNEL_LOGOUT.ru.md"

    def _read_doc(self, relpath: str) -> str:
        from pathlib import Path

        # Tests run from the project root; the docs directory is a
        # sibling of ``tests/`` and ``allianceauth_oidc/``.
        root = Path(__file__).resolve().parent.parent
        return (root / relpath).read_text(encoding="utf-8")

    def test_docs_describe_on_revoke_only_flag_en(self) -> None:
        content = self._read_doc(self._DOCS_EN)
        self.assertIn("backchannel_logout_on_revoke_only", content)
        self.assertIn("Per-app trigger filtering", content)

    def test_docs_describe_on_revoke_only_flag_ru(self) -> None:
        content = self._read_doc(self._DOCS_RU)
        self.assertIn("backchannel_logout_on_revoke_only", content)
        # AC-10b: a localised Russian section heading exists.
        # ``"Фильтрация"`` is the section-title keyword; matching
        # the noun alone keeps the test resilient to wording
        # variations like "Фильтрация триггеров" / "Фильтрация по
        # reason" / "Фильтрация для RP".
        self.assertIn("Фильтрация", content)


# ============================================================
# Dead-letter audit feature (BCL-DL)
# ============================================================
#
# US-BCLDL-001 — model exists with the expected shape.
# US-BCLDL-002 — receiver records failure events by default.
# US-BCLDL-003 — receiver skips successes by default; opts in via setting.
# US-BCLDL-004 — receiver wired in apps.py:ready() under the documented UID.
# US-BCLDL-005 — admin registration is read-only.
# US-BCLDL-006 — signal contract exposes ``user_pk``.
# US-BCLDL-007 — EN + RU docs describe the feature.


class TestBackChannelLogoutAttemptModel(OIDCTestCase):
    """US-BCLDL-001 — ``BackChannelLogoutAttempt`` model shape."""

    def test_model_fields_present_with_expected_attributes(self) -> None:
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        names = {f.name for f in BackChannelLogoutAttempt._meta.get_fields()}
        # ``application`` is the FK; ``user_pk`` is a plain int (not
        # FK — see model docstring); ``jti``, ``success``,
        # ``attempt_count``, ``reason``, ``created_at`` round out the
        # per-event audit row.
        self.assertTrue(
            {
                "application",
                "user_pk",
                "jti",
                "success",
                "attempt_count",
                "reason",
                "created_at",
            }.issubset(names),
            f"Expected dead-letter fields missing; got {names!r}",
        )

    def test_model_ordering_newest_first(self) -> None:
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        self.assertEqual(
            BackChannelLogoutAttempt._meta.ordering, ("-created_at",)
        )

    def test_user_pk_is_nullable_int_not_fk(self) -> None:
        """
        Crucial for the ``user_deleted`` trigger: by the time the
        dead-letter row lands, ``User`` is already gone, so an FK
        would either crash or set NULL on cascade. A plain
        ``PositiveIntegerField`` keeps history honest.
        """
        from django.db.models import (
            ForeignKey,
            PositiveIntegerField,
        )

        from allianceauth_oidc.models import BackChannelLogoutAttempt

        field = BackChannelLogoutAttempt._meta.get_field("user_pk")
        self.assertIsInstance(field, PositiveIntegerField)
        self.assertNotIsInstance(field, ForeignKey)
        self.assertTrue(field.null)


class TestBackChannelLogoutAttemptReceiver(OIDCTestCase):
    """
    US-BCLDL-002 / US-BCLDL-003 — receiver records failures by
    default, skips successes unless opted in.
    """

    def _send_signal(
        self,
        *,
        application,
        user_pk,
        jti: str,
        success: bool,
        reason: str | None = None,
        attempt_count: int = 1,
    ) -> None:
        """Direct signal emit — bypasses the dispatcher to keep tests focused."""
        from allianceauth_oidc.signals import (
            BackChannelLogoutSender,
            oidc_logout_dispatched,
        )

        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=application,
            user_pk=user_pk,
            jti=jti,
            success=success,
            attempt_count=attempt_count,
            reason=reason,
        )

    def test_failure_event_creates_row_with_all_fields(self) -> None:
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        BackChannelLogoutAttempt.objects.all().delete()
        self._send_signal(
            application=creds.app,
            user_pk=self.user1.pk,
            jti="cafebabe" * 4,
            success=False,
            reason="rp_client_error",
            attempt_count=2,
        )
        rows = list(BackChannelLogoutAttempt.objects.all())
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.application_id, creds.app.pk)
        self.assertEqual(row.user_pk, self.user1.pk)
        self.assertEqual(row.jti, "cafebabe" * 4)
        self.assertFalse(row.success)
        self.assertEqual(row.reason, "rp_client_error")
        self.assertEqual(row.attempt_count, 2)
        self.assertIsNotNone(row.created_at)

    def test_success_event_is_skipped_by_default(self) -> None:
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        BackChannelLogoutAttempt.objects.all().delete()
        self._send_signal(
            application=creds.app,
            user_pk=self.user1.pk,
            jti="deadbeef" * 4,
            success=True,
        )
        self.assertEqual(BackChannelLogoutAttempt.objects.count(), 0)

    @override_settings(ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True)
    def test_success_event_recorded_when_setting_true(self) -> None:
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        BackChannelLogoutAttempt.objects.all().delete()
        self._send_signal(
            application=creds.app,
            user_pk=self.user1.pk,
            jti="11111111" * 4,
            success=True,
            reason="user_revoked",
        )
        self.assertEqual(BackChannelLogoutAttempt.objects.count(), 1)
        row = BackChannelLogoutAttempt.objects.get()
        self.assertTrue(row.success)

    def test_user_pk_none_is_persisted_as_null(self) -> None:
        """``user_deleted`` flow may emit signals with ``user_pk=None``."""
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        BackChannelLogoutAttempt.objects.all().delete()
        self._send_signal(
            application=creds.app,
            user_pk=None,
            jti="22222222" * 4,
            success=False,
            reason="broker_unavailable",
        )
        row = BackChannelLogoutAttempt.objects.get()
        self.assertIsNone(row.user_pk)

    def test_empty_jti_recorded_as_blank(self) -> None:
        """signing_kid_resolve_failed fires before a jti is minted."""
        from allianceauth_oidc.models import BackChannelLogoutAttempt

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        BackChannelLogoutAttempt.objects.all().delete()
        self._send_signal(
            application=creds.app,
            user_pk=self.user1.pk,
            jti="",
            success=False,
            reason="signing_kid_resolve_failed",
            attempt_count=0,
        )
        row = BackChannelLogoutAttempt.objects.get()
        self.assertEqual(row.jti, "")
        self.assertEqual(row.attempt_count, 0)

    def test_receiver_swallows_db_errors(self) -> None:
        """
        Audit MUST NOT break the dispatcher. If row insertion fails
        for any reason, the receiver logs and returns normally —
        otherwise a flaky DB would propagate up into the Celery task
        and turn a logged failure into an unhandled exception.
        """
        from allianceauth_oidc.receivers import (
            record_backchannel_logout_attempt,
        )

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        with mock.patch(
            "allianceauth_oidc.models.BackChannelLogoutAttempt.objects.create",
            side_effect=RuntimeError("DB on fire"),
        ):
            # Must not raise.
            record_backchannel_logout_attempt(
                sender=object,
                application=creds.app,
                user_pk=self.user1.pk,
                jti="33333333" * 4,
                success=False,
                attempt_count=1,
                reason="rp_client_error",
            )


class TestBackChannelLogoutAttemptWiring(OIDCTestCase):
    """US-BCLDL-004 — receiver is connected by ``apps.ready()``."""

    def test_receiver_connected_under_documented_uid(self) -> None:
        """
        Idempotent re-connect under the documented UID MUST be a
        no-op (Django dedups receivers by ``dispatch_uid``). A delta
        of 0 proves the AppConfig already wired
        ``record_backchannel_logout_attempt`` under
        ``BCL_AUDIT_DISPATCH_UID``; any drift in the UID constant
        would let the connect call insert a fresh receiver, making
        the delta non-zero.
        """
        from allianceauth_oidc.constants import BCL_AUDIT_DISPATCH_UID
        from allianceauth_oidc.receivers import (
            record_backchannel_logout_attempt,
        )
        from allianceauth_oidc.signals import oidc_logout_dispatched

        receivers_list = (
            oidc_logout_dispatched.receivers  # type: ignore[attr-defined]
        )
        before = len(receivers_list)
        oidc_logout_dispatched.connect(
            record_backchannel_logout_attempt,
            dispatch_uid=BCL_AUDIT_DISPATCH_UID,
            weak=False,
        )
        after = len(receivers_list)
        self.assertEqual(
            before, after, "duplicate receiver registration (UID drift?)"
        )


class TestBackChannelLogoutAttemptAdmin(OIDCTestCase):
    """US-BCLDL-005 — admin is registered and read-only."""

    def test_admin_registered(self) -> None:
        from django.contrib import admin as django_admin

        from allianceauth_oidc.models import BackChannelLogoutAttempt

        self.assertIn(BackChannelLogoutAttempt, django_admin.site._registry)

    def test_admin_is_read_only(self) -> None:
        from django.contrib import admin as django_admin

        from allianceauth_oidc.models import BackChannelLogoutAttempt

        admin_cls = django_admin.site._registry[BackChannelLogoutAttempt]
        # ``request=None`` is fine — both methods are constant in
        # this admin and do not inspect the request.
        self.assertFalse(admin_cls.has_add_permission(None))
        self.assertFalse(admin_cls.has_change_permission(None))

    def test_admin_lists_failure_diagnostics(self) -> None:
        from django.contrib import admin as django_admin

        from allianceauth_oidc.models import BackChannelLogoutAttempt

        admin_cls = django_admin.site._registry[BackChannelLogoutAttempt]
        for column in ("success", "reason", "user_pk", "application"):
            self.assertIn(
                column,
                admin_cls.list_display,
                f"{column!r} missing from list_display",
            )


class TestBackChannelLogoutAttemptDocs(OIDCTestCase):
    """US-BCLDL-007 — EN + RU docs describe the dead-letter feature."""

    _DOCS_EN = "docs/BACK_CHANNEL_LOGOUT.md"
    _DOCS_RU = "docs/BACK_CHANNEL_LOGOUT.ru.md"

    def _read_doc(self, relpath: str) -> str:
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        return (root / relpath).read_text(encoding="utf-8")

    def test_docs_describe_dead_letter_en(self) -> None:
        content = self._read_doc(self._DOCS_EN)
        self.assertIn("BackChannelLogoutAttempt", content)
        self.assertIn("Dead-letter", content)
        self.assertIn("ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS", content)

    def test_docs_describe_dead_letter_ru(self) -> None:
        content = self._read_doc(self._DOCS_RU)
        self.assertIn("BackChannelLogoutAttempt", content)
        self.assertIn("ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS", content)
        # ``"Журнал"`` is the section-title keyword for the
        # dead-letter section; matching the noun keeps the test
        # resilient to title wording variants
        # ("Журнал неудачных доставок", "Журнал dead-letter", ...).
        self.assertIn("Журнал", content)
