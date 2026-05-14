"""
Tests for /o/logout/ — RP-initiated logout and post_logout_redirect_uri
allowlist enforcement.
"""

from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings

from ._oidc_testcase import REDIRECT_STATUSES, SCOPE_PROFILE, OIDCTestCase


def _enable_rp_logout():
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.setdefault("OIDC_ENABLED", True)
    cfg["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
    return cfg


class TestRPInitiatedLogout(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Every test in this class flips OIDC_RP_INITIATED_LOGOUT_ENABLED via
        # override_settings + oauth2_settings.reload(); register the cleanup
        # once so individual tests don't repeat try/finally boilerplate.
        self.addCleanup(oauth2_settings.reload)

    def _issue_id_token(self) -> str:
        """
        Run the auth-code flow to get an id_token for use as
        id_token_hint.
        """
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(
            self.user1, scope=SCOPE_PROFILE, state="logout-issue"
        )["id_token"]

    def test_logout_allows_only_configured_post_logout_redirect_uri(self):
        """
        /o/logout/ must respect the per-app post_logout_redirect_uris
        allowlist.

        DOT versions differ on the exact status (302/400), but must never
        redirect to an unlisted URI.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            denied = "http://localhost/post-logout-bad/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            # 1) allowed URI -> redirects there (or at least no 500).
            resp_ok = self.client.get(
                "/o/logout/", data={"post_logout_redirect_uri": allowed}
            )
            self.assertNotEqual(500, resp_ok.status_code)
            if resp_ok.status_code in REDIRECT_STATUSES:
                self.assertTrue(
                    resp_ok.headers.get("Location", "").startswith(allowed)
                )

            # 2) denied URI -> never redirects there.
            resp_bad = self.client.get(
                "/o/logout/", data={"post_logout_redirect_uri": denied}
            )
            self.assertNotEqual(500, resp_bad.status_code)
            if resp_bad.status_code in REDIRECT_STATUSES:
                self.assertFalse(
                    resp_bad.headers.get("Location", "").startswith(denied)
                )
            else:
                # Many DOT versions return 400 on invalid redirect uri.
                self.assertIn(resp_bad.status_code, (200, 400))

    def test_rp_logout_with_valid_id_token_hint_redirects_to_allowed_uri(self):
        """
        With a valid id_token_hint and an allowed post_logout_redirect_uri,
        /o/logout/ redirects to the configured URI (302/303).

        Some DOT
        versions render a confirmation template (200) — the invariant we
        enforce: never error 500 and never redirect anywhere except the
        allowed URI.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            id_token = self._issue_id_token()

            resp = self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": allowed,
                },
            )
            self.assertNotEqual(500, resp.status_code)
            if resp.status_code in REDIRECT_STATUSES:
                loc = resp.headers.get("Location", "")
                self.assertTrue(
                    loc.startswith(allowed),
                    f"Location {loc!r} does not start with {allowed!r}",
                )

    def test_rp_logout_with_id_token_hint_for_unlisted_redirect_uri(self):
        """
        Even with a valid id_token_hint, an unlisted
        post_logout_redirect_uri must not redirect there — the allowlist is the
        security boundary, not the hint.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            denied = "http://localhost/post-logout-bad/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            id_token = self._issue_id_token()

            resp = self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": denied,
                },
            )
            self.assertNotEqual(500, resp.status_code)
            if resp.status_code in REDIRECT_STATUSES:
                loc = resp.headers.get("Location", "")
                self.assertFalse(
                    loc.startswith(denied),
                    f"Location leaked to denied URI {loc!r}",
                )


class TestRPLogoutIdTokenHintValidation(OIDCTestCase):
    """
    /o/logout/ ``id_token_hint`` validation contracts.

    OIDC RP-Initiated Logout 1.0 §3: ``id_token_hint`` is an OPTIONAL
    parameter; if present it identifies the End-User. The spec
    explicitly permits *expired* hints (the user is already logged in;
    the hint just disambiguates ``sub``).

    Three negative paths that MUST NOT bypass the post-logout
    redirect_uri allowlist:

    1. Unsigned hint (``alg=none``) — classic JWT-confusion vector.
    2. Forged signature (HS256 with a key the AS does not know).
    3. Hint issued for a different ``aud`` / different client.

    For each, the contract pinned is "no 5xx, never redirect to a URI
    outside the per-app allowlist". A hint that fails validation may
    be ignored (DOT default — render the confirm template) or rejected
    outright; both are spec-compliant.
    """

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(oauth2_settings.reload)

    def _logout_with_hint(self, hint: str, *, post_logout: str):
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            self.oauth_app.post_logout_redirect_uris = post_logout
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()
            return self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": hint,
                    "post_logout_redirect_uri": post_logout,
                },
            )

    def test_unsigned_id_token_hint_no_5xx_and_respects_allowlist(
        self,
    ) -> None:
        """
        ``alg=none`` JWT presented as id_token_hint. The AS may
        ignore (200 confirm page) or reject (400) — what it MUST NOT
        do is 500 or redirect to an attacker-supplied URI.
        """
        from base64 import urlsafe_b64encode

        def _b64(raw: bytes) -> str:
            return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        unsigned_header = _b64(b'{"alg":"none","typ":"JWT"}')
        unsigned_payload = _b64(
            b'{"sub":"1","aud":"victim","iss":"https://evil.example/"}'
        )
        unsigned_jwt = f"{unsigned_header}.{unsigned_payload}."

        allowed = "http://localhost/post-logout-ok/"
        resp = self._logout_with_hint(unsigned_jwt, post_logout=allowed)
        self.assertNotEqual(500, resp.status_code)
        if resp.status_code in REDIRECT_STATUSES:
            loc = resp.headers.get("Location", "")
            self.assertTrue(
                loc.startswith((allowed, "/")),
                f"unsigned hint must not redirect outside allowlist; "
                f"got {loc!r}",
            )

    def test_garbage_id_token_hint_no_5xx(self) -> None:
        """
        Hint that does not look like a JWT at all (``not-a-jwt``).
        DOT must surface a controlled error, never 500.
        """
        allowed = "http://localhost/post-logout-ok/"
        resp = self._logout_with_hint("not-a-jwt", post_logout=allowed)
        self.assertNotEqual(500, resp.status_code)

    def test_forged_hs256_id_token_hint_no_5xx_and_respects_allowlist(
        self,
    ) -> None:
        """
        HS256-signed JWT using an attacker-controlled secret. The AS
        does not know the secret, signature verification fails. The
        contract is identical to the unsigned case: no 5xx, no
        attacker-controlled redirect.
        """
        import hashlib
        import hmac
        from base64 import urlsafe_b64encode

        def _b64(raw: bytes) -> str:
            return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        header = _b64(b'{"alg":"HS256","typ":"JWT","kid":"forged"}')
        payload = _b64(
            b'{"sub":"1","aud":"victim","iss":"https://evil.example/"}'
        )
        signing_input = f"{header}.{payload}".encode("ascii")
        # Attacker uses any secret they like — AS cannot match it.
        sig = hmac.new(b"attacker-key", signing_input, hashlib.sha256).digest()
        forged = f"{header}.{payload}.{_b64(sig)}"

        allowed = "http://localhost/post-logout-ok/"
        resp = self._logout_with_hint(forged, post_logout=allowed)
        self.assertNotEqual(500, resp.status_code)
        if resp.status_code in REDIRECT_STATUSES:
            loc = resp.headers.get("Location", "")
            self.assertTrue(
                loc.startswith((allowed, "/")),
                f"forged hint must not redirect outside allowlist; "
                f"got {loc!r}",
            )
