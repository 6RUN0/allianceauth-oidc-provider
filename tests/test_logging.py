"""Tests for OIDC debug-logging — `app.debug_mode` flag and the contract that
no raw tokens or secrets are ever written to logs, even when debug logging is
enabled.
"""

from ._oidc_testcase import OIDCTestCase


class TestDebugLogging(OIDCTestCase):
    def test_debug_logging_does_not_leak_tokens_or_secrets(self):
        """
        When app.debug_mode=True, TokenView logs safe metadata.

        Ensure raw tokens/secrets are never present in logs.
        """
        self.grant_oidc_access(self.user1)

        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid profile email",
            "state": "log-leak-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        with self.assertLogs(
            "extensions.allianceauth_oidc.views", level="INFO"
        ) as cm:
            token_resp = self.exchange_code_for_token(
                code=code,
                redirect_uri="http://localhost/redir/",
                expected_status=200,
            )

        tokens = self.assertTokenResponse(token_resp)

        log_text = "\n".join(cm.output)

        self.assertIn("OIDC DEBUG token issued", log_text)

        self.assertNotIn(tokens["access_token"], log_text)
        self.assertNotIn(tokens["refresh_token"], log_text)
        self.assertNotIn(tokens["id_token"], log_text)

        self.assertNotIn(code, log_text)

        self.assertNotIn(self.oauth_secret, log_text)
