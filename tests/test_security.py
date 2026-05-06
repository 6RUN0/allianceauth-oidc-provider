"""
Unit tests for ``allianceauth_oidc.security.AccessPolicy.decide`` —
the pure-Python decision method that drives
``AuthAuthorizationView.dispatch``.

These reuse the existing ``OIDCTestCase`` fixture rather than mocking
out ``has_perm`` / queryset manager so the policy hits real ORM
behaviour. The composition (which ``DenyReason`` for which path,
``app`` echo semantics) is what's being tested here — the underlying
gate rules have their own coverage in the HTTP-level
``test_authorize`` suite.
"""

from types import SimpleNamespace

from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext

from allianceauth_oidc.security import (
    DEFAULT_POLICY,
    AccessDecision,
    AccessPolicy,
    DenyReason,
)

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase

policy = AccessPolicy()


class TestEvaluateAccessPure(SimpleTestCase):
    """Pure-Python branches that don't need DB-backed querysets."""

    def test_user_without_has_perm_is_denied_global(self):
        # ``check_user_global_oidc_access`` rejects objects without a
        # callable ``has_perm`` — synthetic users / bad mocks can hit
        # this in production-adjacent code paths.
        user = SimpleNamespace(is_superuser=False)  # no has_perm attr
        decision = policy.decide(user, app=None)
        self.assertEqual(
            AccessDecision(
                allowed=False, deny_reason=DenyReason.GLOBAL, app=None
            ),
            decision,
        )

    def test_superuser_with_no_app_is_allowed(self):
        # Superusers bypass both checks; no app means no app-level gate.
        user = SimpleNamespace(is_superuser=True)
        decision = policy.decide(user, app=None)
        self.assertEqual(
            AccessDecision(allowed=True, deny_reason=None, app=None),
            decision,
        )

    def test_app_none_returns_allowed_when_global_passes(self):
        # Regression: ``app=None`` (no client_id in the request, or
        # unknown client) must NOT be treated as a denial — DOT's
        # AuthorizationView downstream surfaces the missing-client_id
        # error itself, with consistent wording.
        user = SimpleNamespace(is_superuser=True)
        decision = policy.decide(user, app=None)
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.app)


class TestEvaluateAccessAgainstFixture(OIDCTestCase):
    """Composition checks that need real users + Application rows."""

    def test_unprivileged_user_denied_global(self):
        # User1 has no ``access_oidc`` permission by default.
        decision = policy.decide(self.user1, self.oauth_app)
        self.assertFalse(decision.allowed)
        self.assertIs(DenyReason.GLOBAL, decision.deny_reason)
        # Anti-enumeration invariant from test_authorize.py:
        # global denial must NOT leak the app back to the renderer.
        self.assertIsNone(decision.app)

    def test_user_with_global_perm_and_unrestricted_app_allowed(self):
        # oauth_app from the fixture has no states/groups configured,
        # so any user with the global perm passes the app check.
        self.grant_oidc_access(self.user1)
        decision = policy.decide(self.user1, self.oauth_app)
        self.assertEqual(
            AccessDecision(allowed=True, deny_reason=None, app=self.oauth_app),
            decision,
        )

    def test_app_restriction_failure_echoes_app_back(self):
        # App constrained to "Blue" state; user1 is "Member" → denied
        # at the app stage, and the app object must be echoed back so
        # the renderer can show its name on the denial page.
        self.grant_oidc_access(self.user1)
        self.oauth_app.states.set(
            self.oauth_app.states.model.objects.filter(name="Blue")
        )
        decision = policy.decide(self.user1, self.oauth_app)
        self.assertFalse(decision.allowed)
        self.assertIs(DenyReason.APP, decision.deny_reason)
        self.assertIs(self.oauth_app, decision.app)


class TestPkceRequired(OIDCTestCase):
    """
    Per-app PKCE resolution via ``AccessPolicy.pkce_required``.

    The adapter
    ``allianceauth_oidc.pkce.per_app_pkce_required`` delegates to
    ``DEFAULT_POLICY.pkce_required(client_id)`` directly — **not**
    through ``validator.policy``. Future tests that wish to mock the
    policy must patch ``allianceauth_oidc.pkce.DEFAULT_POLICY`` (or
    ``allianceauth_oidc.security.DEFAULT_POLICY`` upstream), not the
    validator's ``policy`` attribute. The adapter is module-level and
    binds to ``DEFAULT_POLICY`` at import time.
    """

    def test_pkce_required_true_returns_true(self):
        creds = make_app(owner=self.user1, pkce_required=True)
        self.assertTrue(DEFAULT_POLICY.pkce_required(creds.client_id))

    def test_pkce_required_false_returns_false(self):
        creds = make_app(owner=self.user1, pkce_required=False)
        self.assertFalse(DEFAULT_POLICY.pkce_required(creds.client_id))

    def test_unknown_client_id_falls_back_to_true(self):
        self.assertTrue(DEFAULT_POLICY.pkce_required("does-not-exist"))

    def test_query_is_bounded_to_single_select(self):
        creds = make_app(owner=self.user1, pkce_required=True)
        with CaptureQueriesContext(connection) as captured:
            DEFAULT_POLICY.pkce_required(creds.client_id)
        self.assertEqual(1, len(captured.captured_queries))
        sql = captured.captured_queries[0]["sql"].lower()
        # The query must not pull non-essential columns. We assert the
        # negative — `redirect_uri`, `client_secret`, `hashed` (DOT's
        # secret-hash column variant). Asserting positive presence of
        # `pkce_required` would couple to alias rewrites; the negative
        # form is what `.only("pkce_required")` actually buys us.
        for column in ("redirect_uri", "client_secret", "hashed"):
            self.assertNotIn(
                column, sql, f"unexpected {column!r} in SELECT: {sql}"
            )

    def test_unknown_client_id_logs_warning(self):
        with self.assertLogs(
            "extensions.allianceauth_oidc.security", level="WARNING"
        ) as cm:
            DEFAULT_POLICY.pkce_required("unknown-cid-xyz")
        self.assertTrue(
            any("unknown-cid-xyz" in line for line in cm.output),
            f"unknown client_id not surfaced in log: {cm.output}",
        )


class TestSettingsWiring(OIDCTestCase):
    """
    Confirm DOT picks up the per-app callable verbatim.

    The adapter ``allianceauth_oidc.pkce.per_app_pkce_required``
    delegates to ``DEFAULT_POLICY.pkce_required(client_id)`` directly,
    **not** through ``validator.policy``. Future stubbing tests that
    wish to mock the policy must patch
    ``allianceauth_oidc.pkce.DEFAULT_POLICY``, not the validator's
    ``policy`` attribute. The adapter is module-level and binds to
    ``DEFAULT_POLICY`` at import time.
    """

    def test_oauth2_settings_pkce_required_is_adapter(self):
        from oauth2_provider.settings import oauth2_settings

        from allianceauth_oidc.pkce import per_app_pkce_required

        self.assertIs(oauth2_settings.PKCE_REQUIRED, per_app_pkce_required)
