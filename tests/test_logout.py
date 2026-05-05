"""Tests for /o/logout/ — RP-initiated logout and post_logout_redirect_uri
allowlist enforcement.
"""

from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings

from ._oidc_testcase import SCOPE_PROFILE, OIDCTestCase


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
        """Run the auth-code flow to get an id_token for use as
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
            if resp_ok.status_code in (301, 302, 303, 307, 308):
                self.assertTrue(
                    resp_ok.headers.get("Location", "").startswith(allowed)
                )

            # 2) denied URI -> never redirects there.
            resp_bad = self.client.get(
                "/o/logout/", data={"post_logout_redirect_uri": denied}
            )
            self.assertNotEqual(500, resp_bad.status_code)
            if resp_bad.status_code in (301, 302, 303, 307, 308):
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
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self.assertTrue(
                    loc.startswith(allowed),
                    f"Location {loc!r} does not start with {allowed!r}",
                )

    def test_rp_logout_with_id_token_hint_for_unlisted_redirect_uri(self):
        """Even with a valid id_token_hint, an unlisted
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
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                self.assertFalse(
                    loc.startswith(denied),
                    f"Location leaked to denied URI {loc!r}",
                )
