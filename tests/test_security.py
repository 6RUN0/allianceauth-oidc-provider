"""
Unit tests for ``allianceauth_oidc.security.evaluate_access`` —
the pure-Python decision function extracted from
``AuthAuthorizationView.dispatch``.

These reuse the existing ``OIDCTestCase`` fixture rather than mocking
out ``has_perm`` / queryset manager so the check functions hit real
ORM behaviour. The composition (which ``DenyReason`` for which path,
``app`` echo semantics) is what's being tested here — the underlying
``check_user_*`` rules have their own coverage in the HTTP-level
``test_authorize`` suite.
"""

from types import SimpleNamespace

from django.test import SimpleTestCase

from allianceauth_oidc.security import (
    AccessDecision,
    DenyReason,
    evaluate_access,
)

from ._oidc_testcase import OIDCTestCase


class TestEvaluateAccessPure(SimpleTestCase):
    """Pure-Python branches that don't need DB-backed querysets."""

    def test_user_without_has_perm_is_denied_global(self):
        # ``check_user_global_oidc_access`` rejects objects without a
        # callable ``has_perm`` — synthetic users / bad mocks can hit
        # this in production-adjacent code paths.
        user = SimpleNamespace(is_superuser=False)  # no has_perm attr
        decision = evaluate_access(user, app=None)
        self.assertEqual(
            AccessDecision(
                allowed=False, deny_reason=DenyReason.GLOBAL, app=None
            ),
            decision,
        )

    def test_superuser_with_no_app_is_allowed(self):
        # Superusers bypass both checks; no app means no app-level gate.
        user = SimpleNamespace(is_superuser=True)
        decision = evaluate_access(user, app=None)
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
        decision = evaluate_access(user, app=None)
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.app)


class TestEvaluateAccessAgainstFixture(OIDCTestCase):
    """Composition checks that need real users + Application rows."""

    def test_unprivileged_user_denied_global(self):
        # User1 has no ``access_oidc`` permission by default.
        decision = evaluate_access(self.user1, self.oauth_app)
        self.assertFalse(decision.allowed)
        self.assertIs(DenyReason.GLOBAL, decision.deny_reason)
        # Anti-enumeration invariant from test_authorize.py:
        # global denial must NOT leak the app back to the renderer.
        self.assertIsNone(decision.app)

    def test_user_with_global_perm_and_unrestricted_app_allowed(self):
        # oauth_app from the fixture has no states/groups configured,
        # so any user with the global perm passes the app check.
        self.grant_oidc_access(self.user1)
        decision = evaluate_access(self.user1, self.oauth_app)
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
        decision = evaluate_access(self.user1, self.oauth_app)
        self.assertFalse(decision.allowed)
        self.assertIs(DenyReason.APP, decision.deny_reason)
        self.assertIs(self.oauth_app, decision.app)
