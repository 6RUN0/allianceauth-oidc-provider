"""
Tests for /o/logout/ — RP-initiated logout and post_logout_redirect_uri
allowlist enforcement.
"""

from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings

from ._oidc_testcase import OIDCTestCase


def _enable_rp_logout():
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.setdefault("OIDC_ENABLED", True)
    cfg["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
    return cfg


class TestRPInitiatedLogout(OIDCTestCase):
    def test_logout_allows_only_configured_post_logout_redirect_uri(self):
        """
        /o/logout/ should only redirect to post_logout_redirect_uri if it is
        allowed by the application allowlist
        (AllianceAuthApplication.post_logout_redirect_uris).

        Different DOT versions may respond with 302 or 400, but must never
        redirect to an unlisted URI.
        """
        try:
            with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
                oauth2_settings.reload()
                # Ensure app has allowed post-logout redirect
                allowed = "http://localhost/post-logout-ok/"
                denied = "http://localhost/post-logout-bad/"

                self.oauth_app.post_logout_redirect_uris = f"{allowed}"
                self.oauth_app.save()
                self.oauth_app.refresh_from_db()

                # 1) allowed URI -> should redirect there (often 302), or at
                #    least not error 500
                resp_ok = self.client.get(
                    "/o/logout/", data={"post_logout_redirect_uri": allowed}
                )
                self.assertNotEqual(500, resp_ok.status_code)

                if resp_ok.status_code in (301, 302, 303, 307, 308):
                    loc = resp_ok.headers.get("Location", "")
                    self.assertTrue(loc.startswith(allowed))

                # 2) denied URI -> must NOT redirect there
                resp_bad = self.client.get(
                    "/o/logout/", data={"post_logout_redirect_uri": denied}
                )
                self.assertNotEqual(500, resp_bad.status_code)

                if resp_bad.status_code in (301, 302, 303, 307, 308):
                    loc = resp_bad.headers.get("Location", "")
                    self.assertFalse(loc.startswith(denied))
                else:
                    # Many versions return 400 on invalid redirect uri
                    self.assertIn(resp_bad.status_code, (200, 400))
        finally:
            # Avoid leaking overridden OIDC flags into other tests.
            oauth2_settings.reload()
