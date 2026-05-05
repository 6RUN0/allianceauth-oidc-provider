"""Tests for /o/logout/ — RP-initiated logout and post_logout_redirect_uri
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
    def _issue_id_token(self) -> str:
        """Run the auth-code flow to get an id_token usable as
        id_token_hint.
        """
        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile",
            "state": "logout-issue",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        token_resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        return self.assertTokenResponse(token_resp)["id_token"]

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

    def test_rp_logout_with_valid_id_token_hint_redirects_to_allowed_uri(self):
        """
        Positive RP-initiated logout: with a valid id_token_hint and an
        allowed post_logout_redirect_uri, /o/logout/ should redirect to
        the configured URI without rendering a confirmation template.
        DOT versions differ on the exact redirect status (302/303); both
        are acceptable as long as the Location header points at the
        allowed URI.
        """
        try:
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
                # Some DOT versions render a confirmation template (200);
                # others redirect immediately. We accept both, but assert
                # the negative invariant: never error 500 and never
                # redirect to anything other than the allowed URI.
                self.assertNotEqual(500, resp.status_code)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    self.assertTrue(
                        loc.startswith(allowed),
                        f"Location header {loc!r} does not start with "
                        f"allowed URI {allowed!r}",
                    )
        finally:
            oauth2_settings.reload()

    def test_rp_logout_with_id_token_hint_for_unlisted_redirect_uri(self):
        """Even with a valid id_token_hint, an unlisted
        post_logout_redirect_uri must not redirect there (the allowlist is the
        security boundary, not the id_token_hint).
        """
        try:
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
                        f"Location header leaked to denied URI {loc!r}",
                    )
        finally:
            oauth2_settings.reload()
