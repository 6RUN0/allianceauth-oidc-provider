"""Tests for OIDC debug-logging — `app.debug_mode` flag and the contract that
no raw tokens or secrets are ever written to logs, even when debug logging is
enabled.
"""

import logging

from ._oidc_testcase import OIDCTestCase

VIEWS_LOGGER = "extensions.allianceauth_oidc.views"


class TestDebugLogging(OIDCTestCase):
    def _run_token_flow_capturing_logs(
        self, *, scope: str = "openid profile email"
    ) -> tuple[list[logging.LogRecord], dict, str, str]:
        """
        Run the full code-flow and capture log records on the views logger
        regardless of level.

        Returns (records, tokens_dict, code, log_text). Centralized so positive
        and negative debug_mode tests share setup.
        """
        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scope,
            "state": "log-flow",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )
        # NOTSET captures any record propagating to the views logger so we
        # can assert *absence* of an INFO line, which assertLogs(...)
        # cannot do (it requires at least one record to be emitted).
        with self.assertLogs(VIEWS_LOGGER, level="NOTSET") as cm:
            # Emit one DEBUG record we expect to see, so assertLogs has
            # something to attach to and the inner block can still fail
            # for the right reason.
            logging.getLogger(VIEWS_LOGGER).debug("test-anchor")
            token_resp = self.exchange_code_for_token(
                code=code,
                redirect_uri="http://localhost/redir/",
                expected_status=200,
            )
        tokens = self.assertTokenResponse(token_resp)
        return cm.records, tokens, code, "\n".join(cm.output)

    def test_debug_logging_does_not_leak_tokens_or_secrets(self):
        """
        When app.debug_mode=True, TokenView logs safe metadata.

        Ensure raw tokens/secrets are never present in logs.
        """
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        records, tokens, code, log_text = self._run_token_flow_capturing_logs()

        # Positive: the INFO line is actually emitted (otherwise the
        # `assertNotIn` on tokens below would pass on an empty log buffer).
        info_lines = [
            r
            for r in records
            if r.levelno >= logging.INFO and r.name == VIEWS_LOGGER
        ]
        self.assertTrue(
            info_lines,
            "expected at least one INFO record on the views logger when "
            "debug_mode=True",
        )
        self.assertIn("OIDC DEBUG token issued", log_text)

        # Tokens, code, secret must never be in the captured output.
        self.assertNotIn(tokens["access_token"], log_text)
        self.assertNotIn(tokens["refresh_token"], log_text)
        self.assertNotIn(tokens["id_token"], log_text)
        self.assertNotIn(code, log_text)
        self.assertNotIn(self.oauth_secret, log_text)

    def test_debug_logging_emits_no_info_when_debug_mode_is_false(self):
        """
        Negative counterpart: with `debug_mode=False` (the default), the
        TokenView must not emit the "OIDC DEBUG token issued" INFO line at
        all. Catches the regression where someone flips the per-app gate
        into a global one.
        """
        self.oauth_app.debug_mode = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        records, _, _, log_text = self._run_token_flow_capturing_logs()

        info_lines = [
            r
            for r in records
            if r.levelno >= logging.INFO and r.name == VIEWS_LOGGER
        ]
        self.assertEqual(
            [],
            info_lines,
            f"unexpected INFO log on views logger with debug_mode=False: "
            f"{[r.getMessage() for r in info_lines]}",
        )
        self.assertNotIn("OIDC DEBUG token issued", log_text)

    def test_debug_logging_uses_debug_mode_at_token_exchange_time(self):
        """
        debug_mode is read on the token-exchange request, not at code issuance.

        If an admin flips debug_mode True after the code is issued but before
        /o/token/, the INFO line must appear; flipping it False between
        authorize and token must suppress it.
        """
        # 1) authorize while False
        self.oauth_app.debug_mode = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": "openid",
            "state": "toggle-test",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1, data=data
        )

        # 2) flip True before exchange
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        with self.assertLogs(VIEWS_LOGGER, level="INFO") as cm:
            self.exchange_code_for_token(
                code=code,
                redirect_uri="http://localhost/redir/",
                expected_status=200,
            )
        self.assertTrue(
            any("OIDC DEBUG token issued" in line for line in cm.output)
        )
