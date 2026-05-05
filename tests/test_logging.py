"""
Tests for OIDC debug-logging — `app.debug_mode` flag and the contract that
no raw tokens or secrets are ever written to logs, even when debug logging is
enabled.
"""

import logging

from oauth2_provider.models import get_access_token_model

from ._oidc_testcase import SCOPE_OPENID, OIDCTestCase

VIEWS_LOGGER = "extensions.allianceauth_oidc.views"


class TestDebugLogging(OIDCTestCase):
    def _capture_views_log_during_exchange(
        self, code: str
    ) -> tuple[list[logging.LogRecord], str]:
        """
        Exchange ``code`` for a token while capturing every record that
        reaches the views logger.

        Returns ``(records, joined_text)``. Uses ``level=NOTSET`` plus an
        anchor DEBUG record so we can assert *absence* of INFO records; plain
        ``assertLogs(..., level=INFO)`` would itself fail when no INFO record
        is emitted (which is precisely what the negative debug_mode test wants
        to verify).
        """
        with self.assertLogs(VIEWS_LOGGER, level="NOTSET") as cm:
            logging.getLogger(VIEWS_LOGGER).debug("test-anchor")
            self.exchange_code_for_token(
                code=code,
                redirect_uri="http://localhost/redir/",
                expected_status=200,
            )
        return cm.records, "\n".join(cm.output)

    @staticmethod
    def _info_lines(records: list[logging.LogRecord]) -> list[str]:
        return [
            r.getMessage()
            for r in records
            if r.levelno >= logging.INFO and r.name == VIEWS_LOGGER
        ]

    def test_debug_logging_does_not_leak_tokens_or_secrets(self):
        """
        With app.debug_mode=True, TokenView emits safe metadata only — raw
        tokens/code/secret must never reach the log buffer.
        """
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="log-leak")

        records, log_text = self._capture_views_log_during_exchange(code)

        # The INFO line is actually emitted (so the "no leak" assertions
        # below are not passing vacuously on an empty buffer).
        self.assertTrue(
            self._info_lines(records),
            "expected at least one INFO record when debug_mode=True",
        )
        self.assertIn("OIDC DEBUG token issued", log_text)

        # The exchange does not return tokens here (we only capture logs);
        # pull the persisted row by user to verify nothing leaked.
        token = get_access_token_model().objects.get(user=self.user1)
        self.assertNotIn(token.token, log_text)
        self.assertNotIn(code, log_text)
        self.assertNotIn(self.oauth_secret, log_text)

    def test_debug_logging_emits_no_info_when_debug_mode_is_false(self):
        """
        Negative counterpart: with debug_mode=False (the default), TokenView
        must not emit the OIDC DEBUG INFO line at all.

        Catches a regression where the per-app gate is accidentally widened
        into a global one.
        """
        self.oauth_app.debug_mode = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="log-noinfo")

        records, log_text = self._capture_views_log_during_exchange(code)

        leaked = self._info_lines(records)
        self.assertEqual(
            [],
            leaked,
            f"unexpected INFO records with debug_mode=False: {leaked}",
        )
        self.assertNotIn("OIDC DEBUG token issued", log_text)

    def test_debug_logging_appears_when_toggled_on_between_steps(self):
        """
        debug_mode is sampled on the token-exchange request, not cached at
        authorize-time.

        Flipping it ``False → True`` between authorize and exchange must
        surface the INFO line on exchange.
        """
        self.oauth_app.debug_mode = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(
            self.user1, scope=SCOPE_OPENID, state="toggle-on"
        )

        # Flip True before exchange.
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        records, log_text = self._capture_views_log_during_exchange(code)
        self.assertTrue(self._info_lines(records))
        self.assertIn("OIDC DEBUG token issued", log_text)

    def test_debug_logging_disappears_when_toggled_off_between_steps(self):
        """
        Symmetric negative case: ``True → False`` between authorize and
        exchange must suppress the INFO line on exchange.

        Closes the symmetry gap surfaced by the second-pass review.
        """
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(
            self.user1, scope=SCOPE_OPENID, state="toggle-off"
        )

        self.oauth_app.debug_mode = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        records, log_text = self._capture_views_log_during_exchange(code)
        leaked = self._info_lines(records)
        self.assertEqual(
            [],
            leaked,
            f"INFO record leaked after debug_mode flipped False: {leaked}",
        )
        self.assertNotIn("OIDC DEBUG token issued", log_text)
