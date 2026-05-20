"""
RFC 9068 JWT access tokens — audit signal and grant-type integrations.

Sibling concerns live in test_jwt_shape.py, test_jwt_dispatcher.py,
test_jwt_grants.py, and test_jwt_validation.py. Shared helpers
(split_jwt / mode-switch dicts / lookalike generator) live in
tests/_jwt_helpers.py.
"""

from __future__ import annotations

from typing import Any

from django.test import override_settings

from allianceauth_oidc.signals import oidc_token_issued

from ._jwt_helpers import (
    _jwt_mode_oauth2_provider,
    _opaque_mode_oauth2_provider,
    split_jwt,
)
from ._oidc_testcase import OIDCTestCase


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestAuditSignal(OIDCTestCase):
    """
    Verify ``oidc_token_issued`` payload includes ``format="jwt"`` so
    SIEM receivers can route on issued format. Default receiver
    ignores the field (only logs ``grant_type`` / ``scope``); custom
    receivers wire ``body.get("format")`` themselves.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)
        self.captured: list[dict[str, Any]] = []

        def capture(sender: Any, **kwargs: Any) -> None:
            self.captured.append(kwargs)

        self._capture_receiver = capture
        oidc_token_issued.connect(capture, weak=False)
        self.addCleanup(oidc_token_issued.disconnect, capture)

    def test_audit_signal_payload_includes_format_jwt(self) -> None:
        self.run_code_flow(self.user1)
        formats = [
            kwargs.get("body", {}).get("format")
            for kwargs in self.captured
            if "body" in kwargs and isinstance(kwargs["body"], dict)
        ]
        self.assertIn("jwt", formats)


@override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider())
class TestAuditSignalOpaque(OIDCTestCase):
    """Companion: opaque mode emits ``format="opaque"``."""

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)
        self.captured: list[dict[str, Any]] = []

        def capture(sender: Any, **kwargs: Any) -> None:
            self.captured.append(kwargs)

        oidc_token_issued.connect(capture, weak=False)
        self.addCleanup(oidc_token_issued.disconnect, capture)

    def test_audit_signal_payload_includes_format_opaque(self) -> None:
        self.run_code_flow(self.user1)
        formats = [
            kwargs.get("body", {}).get("format")
            for kwargs in self.captured
            if "body" in kwargs and isinstance(kwargs["body"], dict)
        ]
        self.assertIn("opaque", formats)


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestClientCredentials(OIDCTestCase):
    """
    RFC 9068 §3 + OAuth 2.0 §4.4 fallback: ``sub=client_id`` for
    client_credentials grants because there is no end user.
    ``auth_time`` is omitted in this branch — there is no
    authentication event to timestamp.
    """

    def setUp(self) -> None:
        super().setUp()
        from oauth2_provider.models import AbstractApplication

        from ._factories import make_app

        self.grant_oidc_access(self.user1)
        cc_app, cc_id, cc_secret = make_app(
            owner=self.user1,
            authorization_grant_type=(
                AbstractApplication.GRANT_CLIENT_CREDENTIALS
            ),
            client_type=AbstractApplication.CLIENT_CONFIDENTIAL,
            pkce_required=False,
            access_token_format="jwt",
        )
        self.cc_app = cc_app
        self.cc_id = cc_id
        self.cc_secret = cc_secret

    def _issue(self) -> str:
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "client_credentials",
                "client_id": self.cc_id,
                "client_secret": self.cc_secret,
                "scope": "openid",
            },
        )
        self.assertEqual(200, resp.status_code, resp.content)
        body = self.json_body(resp, expected_status=None)
        return body["access_token"]

    def test_sub_eq_client_id_when_user_is_none(self) -> None:
        token = self._issue()
        _, payload = split_jwt(token)
        self.assertEqual(self.cc_id, payload.get("sub"))
        self.assertEqual(self.cc_id, payload.get("client_id"))
        self.assertEqual(self.cc_id, payload.get("aud"))

    def test_no_auth_time_for_client_credentials(self) -> None:
        token = self._issue()
        _, payload = split_jwt(token)
        self.assertNotIn("auth_time", payload)

    def test_client_credentials_response_omits_id_token(self) -> None:
        """
        OIDC Core 1.0 §3 + RFC 6749 §4.4 — ``client_credentials`` is an
        end-user-less grant. There is no authenticated subject whose
        identity an id_token could attest to, so the token response
        MUST NOT include one even when ``scope=openid`` is requested.

        Without this pin, a future regression that mis-routes the
        id_token generation hook (DOT historically did this on at
        least one minor) would fabricate an id_token with
        ``sub=<client_id>`` and any RP that trusts it would treat
        the *client* as an authenticated end user.
        """
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "client_credentials",
                "client_id": self.cc_id,
                "client_secret": self.cc_secret,
                "scope": "openid",
            },
        )
        self.assertEqual(200, resp.status_code, resp.content)
        body = self.json_body(resp, expected_status=None)
        self.assertNotIn(
            "id_token",
            body,
            "client_credentials response MUST NOT carry id_token "
            "(no end user to attest to)",
        )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestPasswordGrant(OIDCTestCase):
    """
    Password grant under JWT mode: should produce a JWT with
    ``sub=user.pk`` (an authenticated user is involved), unlike
    client_credentials.
    """

    def setUp(self) -> None:
        super().setUp()
        from oauth2_provider.models import AbstractApplication

        from ._factories import make_app

        self.grant_oidc_access(self.user1)
        # Password grant requires a known cleartext password on the
        # user; AA's ``AuthUtils.create_user`` does not expose one
        # convenient for tests, so set one explicitly.
        self.user1.set_password("secret-pw-123")  # nosec B106 - test fixture
        self.user1.save(update_fields=["password"])
        pw_app, pw_id, pw_secret = make_app(
            owner=self.user1,
            authorization_grant_type=AbstractApplication.GRANT_PASSWORD,
            client_type=AbstractApplication.CLIENT_CONFIDENTIAL,
            pkce_required=False,
            access_token_format="jwt",
        )
        self.pw_app = pw_app
        self.pw_id = pw_id
        self.pw_secret = pw_secret

    def test_password_grant_produces_jwt_with_user_sub(self) -> None:
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "password",
                "username": self.user1.username,
                "password": "secret-pw-123",
                "client_id": self.pw_id,
                "client_secret": self.pw_secret,
                "scope": "openid",
            },
        )
        self.assertEqual(200, resp.status_code, resp.content)
        body = self.json_body(resp, expected_status=None)
        token = body["access_token"]
        header, payload = split_jwt(token)
        self.assertEqual("at+jwt", header.get("typ"))
        self.assertEqual(str(self.user1.pk), payload.get("sub"))


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestRefreshRotation(OIDCTestCase):
    """
    Refresh-token rotation under JWT mode: the rotated AT must also
    be a JWT (signed with the current ``kid``).
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_refresh_token_rotation_yields_jwt(self) -> None:
        body = self.run_code_flow(self.user1)
        original_refresh = body["refresh_token"]

        resp = self.refresh_token(refresh_token=original_refresh)
        rotated = self.json_body(resp, expected_status=None)
        rotated_at = rotated["access_token"]
        # Rotated AT is itself a JWT.
        header, _ = split_jwt(rotated_at)
        self.assertEqual("at+jwt", header.get("typ"))
        self.assertEqual("RS256", header.get("alg"))


class TestRefreshFormatFlip(OIDCTestCase):
    """
    Format-flip-on-refresh: tokens are issued anew per request, so
    flipping the global default between issuance and refresh changes
    the format of the rotated AT.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_jwt_refresh_with_format_flip_yields_new_format(self) -> None:
        # Step 1: issue under JWT mode → AT is a JWT.
        with override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            self.assertIn(".", body["access_token"])
            refresh = body["refresh_token"]

        # Step 2: flip to opaque, refresh → rotated AT is opaque.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            resp = self.refresh_token(refresh_token=refresh)
            rotated = self.json_body(resp, expected_status=None)
            rotated_at = rotated["access_token"]
        # Opaque tokens never have 3 dot-separated segments.
        self.assertNotEqual(
            3,
            rotated_at.count(".") + 1,
            "expected opaque (random-string) AT after format flip",
        )


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestBackcompatLifecycle(OIDCTestCase):
    """
    Existing AT rows from a deployment that ran under opaque mode
    must remain introspectable and revocable after a flip to JWT.
    The dispatcher only governs ISSUANCE, so old rows pass through
    DOT's ``_load_access_token`` unchanged.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def test_existing_opaque_tokens_remain_valid_after_global_flip(
        self,
    ) -> None:
        # Issue under opaque mode.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            opaque_at = body["access_token"]
        # Flip to JWT (decorator already applies). Now introspect the
        # opaque token.
        intro = self.introspect_token(opaque_at)
        self.assertTrue(
            intro.get("active"),
            f"expected legacy opaque token to remain valid; got {intro!r}",
        )


# ---------------------------------------------------------------------------
# US-012 — Follow-up coverage from second-pass review (M-1, G-1, G-2, G-3)
# ---------------------------------------------------------------------------


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestJWTRevocation(OIDCTestCase):
    """
    RFC 7009 ``/o/revoke_token/`` works on the persisted ``AccessToken``
    row, not on the wire format. Revocation must succeed for a JWT
    that was just issued, AND for an opaque token issued *before*
    flipping the global default to JWT.

    Closes G-3 from the second-pass review.
    """

    def setUp(self) -> None:
        super().setUp()
        self.grant_oidc_access(self.user1)

    def _revoke(self, token: str) -> int:
        resp = self.client.post(
            "/o/revoke_token/",
            data={
                "token": token,
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
            },
        )
        return resp.status_code

    def test_revoke_jwt_access_token(self) -> None:
        body = self.run_code_flow(self.user1)
        jwt_at = body["access_token"]
        # Sanity: it really is a JWT under JWT mode.
        header, _ = split_jwt(jwt_at)
        self.assertEqual("at+jwt", header.get("typ"))

        # Token starts active.
        self.assertTrue(self.introspect_token(jwt_at).get("active"))
        # RFC 7009 §2.2: success is 200 with empty body.
        self.assertEqual(200, self._revoke(jwt_at))
        # Post-revocation, introspection reports inactive.
        self.assertFalse(self.introspect_token(jwt_at).get("active"))

    def test_revoke_legacy_opaque_token_after_format_flip(self) -> None:
        # Issue under opaque mode; the JWT-mode decorator is overridden
        # for this block only.
        with override_settings(OAUTH2_PROVIDER=_opaque_mode_oauth2_provider()):
            body = self.run_code_flow(self.user1)
            opaque_at = body["access_token"]
        # The class-level decorator (JWT mode) is back in effect.
        self.assertTrue(self.introspect_token(opaque_at).get("active"))
        self.assertEqual(200, self._revoke(opaque_at))
        self.assertFalse(self.introspect_token(opaque_at).get("active"))
