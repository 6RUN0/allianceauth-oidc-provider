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


class TestPkceRequiredPolicy(SimpleTestCase):
    """
    ``AccessPolicy.pkce_required(app)`` — the pure-logic decision.

    The DI seam: synthetic ``SimpleNamespace`` doubles satisfy the
    ``AppLike`` Protocol so the policy method stays testable without
    spinning up ORM. ORM-lookup behaviour lives one frame up in
    ``TestPkceRequiredAdapter``.
    """

    def test_app_with_required_true(self):
        app = SimpleNamespace(
            pkce_required=True, debug_mode=False, states=None, groups=None
        )
        self.assertTrue(policy.pkce_required(app))

    def test_app_with_required_false(self):
        app = SimpleNamespace(
            pkce_required=False, debug_mode=False, states=None, groups=None
        )
        self.assertFalse(policy.pkce_required(app))

    def test_app_missing_attr_falls_back_to_true(self):
        # An object that doesn't expose ``pkce_required`` at all
        # (a partial mock or a future shape change) must take the
        # strict path — RFC 9700 secure-by-default.
        app = SimpleNamespace(debug_mode=False, states=None, groups=None)
        self.assertTrue(policy.pkce_required(app))

    def test_app_none_falls_back_to_true(self):
        # ``None`` means "no app resolved" — strict path.
        self.assertTrue(policy.pkce_required(None))


class TestPkceRequiredAdapter(OIDCTestCase):
    """
    ``allianceauth_oidc.pkce.per_app_pkce_required`` — the DOT adapter.

    Tests cover the resolver's ORM-lookup behaviour: known client_id
    delegates to the policy, unknown / ``None`` / empty fail-safe to
    ``True`` with a ``WARNING`` log, and the lookup query is bounded
    to a single column.

    Tests that wish to mock the policy must patch
    ``allianceauth_oidc.pkce.DEFAULT_POLICY`` (or
    ``allianceauth_oidc.security.DEFAULT_POLICY`` upstream), not the
    validator's ``policy`` attribute. The adapter is module-level and
    binds to ``DEFAULT_POLICY`` at import time.
    """

    def test_known_client_with_pkce_required_true(self):
        from allianceauth_oidc.pkce import per_app_pkce_required

        creds = make_app(owner=self.user1, pkce_required=True)
        self.assertTrue(per_app_pkce_required(creds.client_id))

    def test_known_client_with_pkce_required_false(self):
        from allianceauth_oidc.pkce import per_app_pkce_required

        creds = make_app(owner=self.user1, pkce_required=False)
        self.assertFalse(per_app_pkce_required(creds.client_id))

    def test_unknown_client_id_falls_back_to_true(self):
        from allianceauth_oidc.pkce import per_app_pkce_required

        self.assertTrue(per_app_pkce_required("does-not-exist"))

    def test_query_is_bounded_to_single_select(self):
        from allianceauth_oidc.pkce import per_app_pkce_required

        creds = make_app(owner=self.user1, pkce_required=True)
        with CaptureQueriesContext(connection) as captured:
            per_app_pkce_required(creds.client_id)
        self.assertEqual(1, len(captured.captured_queries))
        sql = captured.captured_queries[0]["sql"].lower()
        # Negative-form: SELECT must skip heavy / sensitive columns.
        # Pairs with the positive sanity-check below: a regression that
        # accidentally drops the ``.only(...)`` would expand the column
        # list well past 4 entries (the deferred set the model carries
        # post-init: id, pkce_required + a couple of pk-related stubs).
        for column in ("redirect_uri", "client_secret", "hashed"):
            self.assertNotIn(
                column, sql, f"unexpected {column!r} in SELECT: {sql}"
            )
        # Sanity: ``.only("pkce_required")`` produces a small column
        # list; a regression dropping it produces ~20 columns. Use
        # comma count as a robust proxy for column count without
        # coupling to alias renames.
        self.assertLess(
            sql.count(","),
            5,
            f"SELECT looks unbounded ({sql.count(',')} commas): {sql}",
        )

    def test_unknown_client_id_logs_warning(self):
        from allianceauth_oidc.pkce import per_app_pkce_required

        with self.assertLogs(
            "extensions.allianceauth_oidc.pkce", level="WARNING"
        ) as cm:
            per_app_pkce_required("unknown-cid-xyz")
        self.assertTrue(
            any("unknown-cid-xyz" in line for line in cm.output),
            f"unknown client_id not surfaced in log: {cm.output}",
        )
        # %a formatter renders ASCII-safe; injected control characters
        # in client_id must not propagate as raw bytes to log storage.
        for line in cm.output:
            self.assertNotIn("\n", line.split(":", 2)[-1].strip())

    def test_none_client_id_falls_back_to_true(self):
        """
        ``None`` may arrive from a malformed validator path. Django's
        ORM turns it into ``WHERE client_id IS NULL`` — different SQL
        path from a string lookup, but same ``DoesNotExist`` outcome
        on a column with ``unique=True``. The resolver must fail-safe
        to ``True``, not propagate as a 500.
        """
        from allianceauth_oidc.pkce import per_app_pkce_required

        self.assertTrue(per_app_pkce_required(None))

    def test_empty_client_id_falls_back_to_true(self):
        """
        Empty string is a yet-different SQL path
        (``WHERE client_id = ''``) and is functionally unknown. Same
        fail-safe contract.
        """
        from allianceauth_oidc.pkce import per_app_pkce_required

        self.assertTrue(per_app_pkce_required(""))


class TestSettingsWiring(OIDCTestCase):
    """Confirm DOT picks up the per-app callable verbatim."""

    def test_dot_picks_up_per_app_pkce_callable(self):
        from oauth2_provider.settings import oauth2_settings

        from allianceauth_oidc.pkce import per_app_pkce_required

        self.assertIs(oauth2_settings.PKCE_REQUIRED, per_app_pkce_required)
