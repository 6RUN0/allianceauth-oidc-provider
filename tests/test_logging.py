"""
Tests for OIDC debug-logging — `app.debug_mode` flag and the contract that
no raw tokens or secrets are ever written to logs, even when debug logging is
enabled.
"""

import json
import logging

from django.test import RequestFactory, SimpleTestCase, override_settings
from oauth2_provider.models import get_access_token_model

from allianceauth_oidc.views_token import TokenView

from ._jwt_helpers import _jwt_mode_oauth2_provider, split_jwt
from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    OIDCTestCase,
)

TOKEN_VIEW_LOGGER = "extensions.allianceauth_oidc.views_token"


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
        with self.assertLogs(TOKEN_VIEW_LOGGER, level="NOTSET") as cm:
            logging.getLogger(TOKEN_VIEW_LOGGER).debug("test-anchor")
            self.exchange_code_for_token(
                code=code,
                redirect_uri=REDIRECT_URI,
                expected_status=200,
            )
        return cm.records, "\n".join(cm.output)

    @staticmethod
    def _info_lines(records: list[logging.LogRecord]) -> list[str]:
        # The debug-mode INFO line is emitted by TokenAudit, which
        # lives in ``views_token``. Capture target and originating
        # logger match exactly — no parent/child propagation needed.
        return [
            r.getMessage()
            for r in records
            if r.levelno >= logging.INFO and r.name == TOKEN_VIEW_LOGGER
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


@override_settings(OAUTH2_PROVIDER=_jwt_mode_oauth2_provider())
class TestDebugLoggingJWTMode(OIDCTestCase):
    """
    Same no-leak contract as :class:`TestDebugLogging`, but exercised
    against a JWT-mode AT.

    A JWT carries identity claims (``email``, ``name``, ``groups``)
    plaintext-base64url-encoded in segment 2 — so a future contributor
    who relaxes ``build_oidc_debug_meta`` (e.g. adds a ``payload=%s``
    field for diagnosis) leaks structured PII, not just a random
    bearer string. The opaque-mode regression test would happily pass
    that change. This class locks the JWT-mode side of the contract.
    """

    def _capture_views_log_during_exchange(self, code: str) -> str:
        with self.assertLogs(TOKEN_VIEW_LOGGER, level="NOTSET") as cm:
            logging.getLogger(TOKEN_VIEW_LOGGER).debug("test-anchor")
            resp = self.exchange_code_for_token(
                code=code,
                redirect_uri=REDIRECT_URI,
                expected_status=200,
            )
        body = json.loads(resp.content.decode("utf-8"))
        return body["access_token"], "\n".join(cm.output)

    def test_debug_logging_does_not_leak_jwt_or_decoded_claims(self) -> None:
        """
        With ``debug_mode=True`` AND JWT mode active, neither the raw
        JWT, the decoded ``email``, the decoded ``name``, nor any
        decoded ``groups`` member must reach the views log buffer.
        """
        self.oauth_app.debug_mode = True
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()
        self.grant_oidc_access(self.user1)
        # SCOPE_FULL = "openid profile email" → identity claims will
        # be present in the JWT payload, maximising the leak surface.
        code = self.authorize_to_code(
            self.user1, scope=SCOPE_FULL, state="jwt-leak"
        )

        token_str, log_text = self._capture_views_log_during_exchange(code)

        # The exchange returned a JWT (3 segments).
        header, payload = split_jwt(token_str)
        self.assertEqual("at+jwt", header.get("typ"))

        # The OIDC DEBUG INFO line was actually emitted (so the
        # negative assertions are not passing vacuously on an empty
        # buffer). Mirrors the opaque-mode regression test.
        self.assertIn("OIDC DEBUG token issued", log_text)

        # 1. Raw JWT must not appear in the buffer.
        self.assertNotIn(token_str, log_text)
        # 2. Each individual segment is also a leak — guards against
        #    a hypothetical "log header for diagnosis" regression that
        #    would still expose ``kid`` correlation across requests.
        for segment in token_str.split("."):
            self.assertNotIn(segment, log_text)

        # 3. Decoded identity claims must not leak. ``user1`` ships
        #    with the ``character.name1`` main char and an empty
        #    email; assertions are guarded by ``if claim`` so they
        #    only fire when the fixture actually carries a value.
        for claim_key in ("email", "name", "preferred_username"):
            value = payload.get(claim_key)
            if isinstance(value, str) and value:
                self.assertNotIn(
                    value,
                    log_text,
                    f"identity claim {claim_key!r}={value!r} leaked to log",
                )
        # ``groups`` is a list of strings — each member must be absent.
        for grp in payload.get("groups") or []:
            if isinstance(grp, str) and grp:
                self.assertNotIn(
                    grp,
                    log_text,
                    f"group {grp!r} from JWT claims leaked to log",
                )

        # 4. The client_secret stays redacted under JWT mode, same as
        #    opaque. The masking pipeline shares one code path; this
        #    assertion just locks the JWT-mode side.
        self.assertNotIn(self.oauth_secret, log_text)


class TestTokenViewSensitivePostParameters(SimpleTestCase):
    """
    F-4 regression: the ``sensitive_post_parameters`` decorator on
    :meth:`TokenView.post` must cover every credential the token
    endpoint may receive — not only ``password``. Django consults
    ``request.sensitive_post_parameters`` from the 500-debug page
    renderer and from third-party error reporters that honour the
    marker (Sentry, Rollbar); an unredacted ``client_secret`` /
    ``code`` / ``refresh_token`` / ``assertion`` on a captured POST
    body becomes an immediate credential leak.
    """

    def test_post_marks_all_oauth_secrets_as_sensitive(self):
        # The decorator sets ``request.sensitive_post_parameters``
        # BEFORE the view body runs. Stub ``create_token_response``
        # with a synthetic 4-tuple so the body completes without
        # needing a real OAuth context; the marker is still set on
        # the request by the decorator chain.
        from unittest.mock import patch

        factory = RequestFactory()
        request = factory.post("/o/token/", {"grant_type": "password"})
        view = TokenView()
        view.setup(request)
        with patch.object(
            view, "create_token_response", return_value=(None, {}, b"{}", 400)
        ):
            view.post(request)

        self.assertEqual(
            request.sensitive_post_parameters,
            (
                "password",
                "client_secret",
                "code",
                "code_verifier",
                "refresh_token",
                "assertion",
            ),
            "PKCE ``code_verifier`` MUST be marked sensitive — leaking "
            "the verifier together with the code defeats PKCE entirely "
            "(RFC 7636 §4.5).",
        )
