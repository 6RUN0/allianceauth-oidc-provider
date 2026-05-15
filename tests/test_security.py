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

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from typing import Any
from unittest import mock

from django.db import connection
from django.test import SimpleTestCase
from django.test.utils import CaptureQueriesContext

from allianceauth_oidc.security import (
    AccessPolicy,
    AllowedDecision,
    AppDeny,
    AppLike,
    DenyReason,
    GlobalDeny,
    OAuthRequestLike,
    TokenLike,
    UserLike,
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
        self.assertEqual(GlobalDeny(), decision)

    def test_superuser_with_no_app_is_allowed(self):
        # Superusers bypass both checks; no app means no app-level gate.
        user = SimpleNamespace(is_superuser=True)
        decision = policy.decide(user, app=None)
        self.assertEqual(AllowedDecision(app=None), decision)

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
        self.assertEqual(AllowedDecision(app=self.oauth_app), decision)

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
    ``AccessPolicy.requires_pkce(app)`` — the pure-logic decision.

    The DI seam: synthetic ``SimpleNamespace`` doubles satisfy the
    ``AppLike`` Protocol so the policy method stays testable without
    spinning up ORM. ORM-lookup behaviour lives one frame up in
    ``TestPkceRequiredAdapter``.
    """

    def test_app_with_required_true(self):
        app = SimpleNamespace(
            pkce_required=True, debug_mode=False, states=None, groups=None
        )
        self.assertTrue(policy.requires_pkce(app))

    def test_app_with_required_false(self):
        app = SimpleNamespace(
            pkce_required=False, debug_mode=False, states=None, groups=None
        )
        self.assertFalse(policy.requires_pkce(app))

    def test_app_missing_attr_falls_back_to_true(self):
        # An object that doesn't expose ``pkce_required`` at all
        # (a partial mock or a future shape change) must take the
        # strict path — RFC 9700 secure-by-default.
        app = SimpleNamespace(debug_mode=False, states=None, groups=None)
        self.assertTrue(policy.requires_pkce(app))

    def test_app_none_falls_back_to_true(self):
        # ``None`` means "no app resolved" — strict path.
        self.assertTrue(policy.requires_pkce(None))


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


class TestAccessDecisionStructuralInvariants(SimpleTestCase):
    """
    Pin the structural invariants of the three AccessDecision dataclasses.

    Without these tests, mutating ``frozen=True``, ``slots=True``,
    ``init=False`` or the ``field(default=True/False, init=False)``
    defaults all survive the suite: every consumer reads
    ``decision.allowed``, but no existing test asserts the
    constructor-set invariants themselves. Cosmic-ray spots that
    gap immediately.

    Each dataclass advertises three guarantees the rest of the
    codebase relies on: the boolean ``allowed`` is fixed at class
    level (not constructor-overridable), the instance is frozen
    (downstream code can pass decisions around as value objects),
    and ``slots=True`` keeps the type cheap and forbids stray
    attribute assignment.
    """

    @staticmethod
    def _stub_app():
        return SimpleNamespace(name="stub")

    # The decision trio shares three invariants — ``allowed`` and
    # ``deny_reason`` defaults, ``frozen=True`` immutability,
    # ``slots=True`` __dict__-absence — plus a kwarg-rejection
    # contract on the ``init=False`` fields. One sweep per
    # invariant pins all three classes; the two genuinely
    # asymmetric facts (``GlobalDeny.app is None`` for
    # anti-enumeration, ``AppDeny`` echoes its constructor arg)
    # remain as dedicated tests below.

    def test_decision_pins_allowed_and_deny_reason_defaults(self):
        """
        field(default=…, init=False) pin for every decision.

        A mutation that flips ``default=True`` on AllowedDecision
        to ``False`` (or vice versa on a deny path) would silently
        invert the policy answer. The three rows lock both
        ``allowed`` and ``deny_reason`` against any such flip.
        """
        stub = self._stub_app()
        cases: tuple[tuple[str, Any, bool, Any], ...] = (
            ("AllowedDecision", AllowedDecision(app=stub), True, None),
            ("GlobalDeny", GlobalDeny(), False, DenyReason.GLOBAL),
            ("AppDeny", AppDeny(app=stub), False, DenyReason.APP),
        )
        for label, decision, expected_allowed, expected_reason in cases:
            with self.subTest(decision=label):
                self.assertIs(expected_allowed, decision.allowed)
                if expected_reason is None:
                    self.assertIsNone(decision.deny_reason)
                else:
                    self.assertIs(expected_reason, decision.deny_reason)

    def test_decision_rejects_disallowed_kwargs(self):
        """
        ``init=False`` fields must TypeError on constructor override.

        A caller hand-rolling ``AllowedDecision(allowed=False)``
        or ``GlobalDeny(app=…)`` would create an incoherent
        decision; ``init=False`` forbids it by design and the
        type system surfaces the violation as TypeError.
        """
        stub = self._stub_app()
        cases: tuple[tuple[str, Any], ...] = (
            (
                "AllowedDecision allowed=",
                lambda: AllowedDecision(  # type: ignore[call-arg]
                    app=stub, allowed=False
                ),
            ),
            (
                "AllowedDecision deny_reason=",
                lambda: AllowedDecision(  # type: ignore[call-arg]
                    app=stub, deny_reason=DenyReason.GLOBAL
                ),
            ),
            (
                "GlobalDeny allowed=",
                lambda: GlobalDeny(allowed=True),  # type: ignore[call-arg]
            ),
            (
                "GlobalDeny app=",
                lambda: GlobalDeny(app=stub),  # type: ignore[call-arg]
            ),
            (
                "AppDeny allowed=",
                lambda: AppDeny(  # type: ignore[call-arg]
                    app=stub, allowed=True
                ),
            ),
        )
        for label, factory in cases:
            with (
                self.subTest(case=label),
                self.assertRaises(TypeError),
            ):
                factory()

    def test_decision_is_frozen(self):
        """
        ``frozen=True`` forbids in-place mutation post-construction.

        Removing the decorator or flipping ``frozen=True`` to
        ``False`` allows in-place mutation and breaks the
        "decisions are values, not state" contract validators
        rely on. Any field write must raise FrozenInstanceError.
        """
        stub = self._stub_app()
        decisions = (
            ("AllowedDecision", AllowedDecision(app=stub)),
            ("GlobalDeny", GlobalDeny()),
            ("AppDeny", AppDeny(app=stub)),
        )
        for label, decision in decisions:
            with (
                self.subTest(decision=label),
                self.assertRaises(FrozenInstanceError),
            ):
                decision.app = None  # type: ignore[misc]

    def test_decision_uses_slots(self):
        """
        ``slots=True`` keeps instances dict-less.

        Mutating slots=True to False would silently let
        downstream code attach random attributes to a decision
        and rely on them.
        """
        stub = self._stub_app()
        decisions = (
            ("AllowedDecision", AllowedDecision(app=stub)),
            ("GlobalDeny", GlobalDeny()),
            ("AppDeny", AppDeny(app=stub)),
        )
        for label, decision in decisions:
            with self.subTest(decision=label):
                self.assertFalse(hasattr(decision, "__dict__"))

    # ---- Asymmetric, decision-specific invariants -----------------

    def test_global_deny_pins_app_none(self):
        # Anti-enumeration: GlobalDeny.app must be None so the
        # renderer cannot distinguish "client exists, you lack perm"
        # from "client does not exist". Mutating the field default
        # would re-introduce the leak.
        self.assertIsNone(GlobalDeny().app)

    def test_app_deny_echoes_app(self):
        # Symmetry with AllowedDecision: AppDeny carries the
        # offending app so the renderer can show its name. The
        # ``app`` field IS init=True (no default), unlike the
        # allowed/deny_reason pair.
        app = self._stub_app()
        self.assertIs(app, AppDeny(app=app).app)


class TestAccessPolicyStructure(SimpleTestCase):
    """
    ``AccessPolicy`` itself is a ``@dataclass(frozen=True, slots=True)``.

    Three orthogonal invariants worth pinning, all flagged as
    surviving cosmic-ray mutants when only the decision-paths were
    tested:

    1. The class is a dataclass at all (``RemoveDecorator`` survives
       if no test exercises a dataclass-specific behaviour like
       ``replace()`` or hash-by-value).
    2. ``frozen=True`` — instances are immutable, so callers can
       share decisions across threads without defensive copies.
    3. ``slots=True`` — instances have no ``__dict__``, so a typo'd
       attribute assignment fails loudly rather than silently shadowing.
    """

    def test_policy_is_frozen(self):
        policy = AccessPolicy()
        with self.assertRaises(FrozenInstanceError):
            policy.log = mock.Mock()  # type: ignore[misc]

    def test_policy_uses_slots(self):
        self.assertFalse(hasattr(AccessPolicy(), "__dict__"))

    def test_policy_equality_by_value(self):
        # Two instances built with the same injected log are equal.
        # Removing @dataclass strips the value-equality
        # implementation and equality falls back to ``id``-based
        # identity, breaking ``policy_a == policy_b``.
        shared_log = mock.Mock()
        self.assertEqual(
            AccessPolicy(log=shared_log), AccessPolicy(log=shared_log)
        )


class TestProtocolsAreRuntimeCheckable(SimpleTestCase):
    """
    The four ``@runtime_checkable`` Protocols enable ``isinstance``
    probes at policy boundaries (the module docstring documents the
    contract explicitly). Without an actual ``isinstance`` call in
    the suite, ``RemoveDecorator`` mutants on those four classes
    survive because the Protocol class works either way at static
    type-checking time — only the runtime check distinguishes them.
    """

    def test_userlike_is_runtime_checkable(self):
        # ``UserLike`` also requires a callable ``has_perm`` —
        # ``SimpleNamespace`` doesn't auto-add methods, so wire a
        # lambda explicitly.
        user_stub = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            has_perm=lambda perm: False,
        )
        # ``isinstance(x, Protocol)`` raises TypeError unless the
        # Protocol carries ``@runtime_checkable``; the assertion
        # succeeding == decorator is present.
        self.assertIsInstance(user_stub, UserLike)

    def test_applike_is_runtime_checkable(self):
        app_stub = SimpleNamespace(
            states=mock.Mock(),
            groups=mock.Mock(),
            debug_mode=False,
            pkce_required=True,
            access_token_format="opaque",
        )
        self.assertIsInstance(app_stub, AppLike)

    def test_tokenlike_is_runtime_checkable(self):
        token_stub = SimpleNamespace(
            application=None, user=None, id=1, scope="openid"
        )
        self.assertIsInstance(token_stub, TokenLike)

    def test_oauthrequestlike_is_runtime_checkable(self):
        request_stub = SimpleNamespace(
            user=None,
            client=None,
            application=None,
            POST={},
        )
        self.assertIsInstance(request_stub, OAuthRequestLike)


class TestIsSuperuserDefault(SimpleTestCase):
    """
    ``AccessPolicy.is_superuser`` reads ``user.is_superuser`` with a
    safe-by-default of ``False`` for missing attributes. Mutating
    that ``False`` default to ``True`` (cosmic-ray's
    ``ReplaceFalseWithTrue``) would silently grant superuser
    privilege to any object that doesn't expose the attribute —
    e.g. an unauthenticated stub or a malformed mock.
    """

    def test_user_without_is_superuser_attr_is_not_superuser(self):
        # ``object()`` has no ``is_superuser``; ``getattr(..., False)``
        # falls back to False. Flipping the default lets the function
        # return True for any attribute-less object.
        self.assertFalse(AccessPolicy.is_superuser(object()))


class TestAccessTokenFormatComparison(SimpleTestCase):
    """
    The per-app override compares against the literal strings
    ``"jwt"`` and ``"opaque"`` using ``==``. Cosmic-ray emits a
    ``ReplaceComparisonOperator_Eq_Is`` mutation that swaps ``==``
    for ``is``. For string literals embedded in source code CPython
    typically interns them and ``is`` happens to return the same
    truth value, masking the mutation.

    Forcing the comparison to run against a **non-interned** value
    (built at runtime via concatenation) distinguishes the two
    operators: ``==`` returns True (same characters), ``is`` returns
    False (different object identity). The mutation now produces an
    observable behaviour change and is killed.
    """

    @staticmethod
    def _non_interned(literal: str) -> str:
        # Concatenating two halves of a literal at runtime yields a
        # fresh string object, defeating CPython's compile-time
        # interning of literal constants.
        half = len(literal) // 2
        return literal[:half] + literal[half:]

    def test_per_app_jwt_via_non_interned_string(self):
        app = SimpleNamespace(access_token_format=self._non_interned("jwt"))
        self.assertEqual("jwt", AccessPolicy().access_token_format(app))

    def test_per_app_opaque_via_non_interned_string(self):
        app = SimpleNamespace(access_token_format=self._non_interned("opaque"))
        self.assertEqual("opaque", AccessPolicy().access_token_format(app))

    def test_global_default_jwt_via_non_interned_string(self):
        # Force the fallthrough to the OAUTH2_PROVIDER global default.
        # ``app=None`` skips the per-app override, leaving the
        # ``global_default == "jwt"`` comparison on the global path
        # as the only ``Eq_Is`` mutation site that matters.
        from django.test.utils import override_settings

        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": self._non_interned(
                    "jwt"
                ),
            }
        ):
            self.assertEqual("jwt", AccessPolicy().access_token_format(None))


class TestCheckAppGuards(SimpleTestCase):
    """
    Boolean guards inside ``AccessPolicy._check_app`` that survive otherwise.

    * ``if app_states_mgr is None or app_groups_mgr is None:`` —
      flipping ``or`` to ``and`` lets a half-broken app object slip
      through (one manager present, one missing → AttributeError
      downstream). The defensive guard must reject both shapes.

    * The default of ``getattr(app, "debug_mode", False)`` — flipping
      to ``True`` silently turns debug logging on for any
      attribute-less application. The default behaviour must stay
      "quiet unless explicitly opted-in".
    """

    def test_app_missing_states_manager_is_denied(self):
        # Mutation ``or → and`` would let this pass (one is non-None
        # via the groups manager). The guard must trip.
        from django.core.exceptions import PermissionDenied

        app = SimpleNamespace(
            states=None,
            groups=mock.Mock(),
            debug_mode=False,
        )
        user = SimpleNamespace(is_superuser=False)
        with self.assertRaises(PermissionDenied):
            AccessPolicy()._check_app(user, app)

    def test_app_missing_groups_manager_is_denied(self):
        # Symmetric: ``states`` present, ``groups`` missing.
        from django.core.exceptions import PermissionDenied

        app = SimpleNamespace(
            states=mock.Mock(),
            groups=None,
            debug_mode=False,
        )
        user = SimpleNamespace(is_superuser=False)
        with self.assertRaises(PermissionDenied):
            AccessPolicy()._check_app(user, app)

    def test_debug_mode_default_silences_log_when_attr_absent(self):
        # With debug_mode missing from the app object, the
        # ``getattr(app, "debug_mode", False)`` default keeps logging
        # silent. Mutating the default to True would flip the
        # STATE/GROUP info lines on for every app without the
        # explicit attribute — exactly the regression we're guarding
        # against.
        from django.core.exceptions import PermissionDenied

        state_obj = SimpleNamespace(pk=1, name="Blue")
        states_qs = mock.Mock()
        states_qs.all.return_value = [state_obj]
        groups_qs = mock.Mock()
        groups_qs.all.return_value = []
        app = SimpleNamespace(
            states=states_qs,
            groups=groups_qs,
            # no debug_mode attribute — getattr default applies
        )
        user = SimpleNamespace(
            is_superuser=False,
            profile=SimpleNamespace(state=SimpleNamespace(pk=999)),
            groups=mock.Mock(all=list),
        )
        captured_log = mock.Mock()
        captured_log.isEnabledFor.return_value = True
        policy_with_log = AccessPolicy(log=captured_log)
        with self.assertRaises(PermissionDenied):
            policy_with_log._check_app(user, app)
        captured_log.info.assert_not_called()
