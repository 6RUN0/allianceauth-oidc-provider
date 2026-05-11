"""
Unit tests for ``AllianceAuthOAuth2Validator``'s policy hooks.

These tests stay below the HTTP layer: ``_enforce_policy`` and
``save_bearer_token`` are exercised against synthetic request objects so the
AnonymousUser branch can be reached without spinning up the client_credentials
grant flow (which DOT does not register by default in the test settings).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth.models import AnonymousUser
from django.test import SimpleTestCase, override_settings

from allianceauth_oidc.auth_provider import AllianceAuthOAuth2Validator

from ._oidc_testcase import OIDCTestCase


def _stub_policy(*, is_allowed: bool = True) -> MagicMock:
    """Build a ``MagicMock`` that mimics the ``AccessPolicy`` surface."""
    pol = MagicMock(name="StubAccessPolicy")
    pol.is_allowed.return_value = is_allowed
    pol.enforce.return_value = None
    return pol


class TestEnforcePolicyAuthGuard(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Policy gate runs against the application object; only its
        # presence is checked here, the policy itself is stubbed out
        # via ``patch.object(AllianceAuthOAuth2Validator, "policy", ...)``.
        self.client_obj = self.oauth_app
        self.validator = AllianceAuthOAuth2Validator()

    def test_anonymous_user_skips_policy_check(self):
        """
        ``AnonymousUser`` must not be funnelled through the per-app
        state/group gate.

        client_credentials and similar end-user-less grants present
        ``AnonymousUser`` (or ``None``) on ``request.user``. Letting
        the policy run on those tokens would deny every
        machine-to-machine token because anonymous users carry no
        Django state/groups.
        """
        request = SimpleNamespace(user=AnonymousUser())
        pol = _stub_policy()
        with patch.object(AllianceAuthOAuth2Validator, "policy", pol):
            allowed = self.validator._enforce_policy(request, self.client_obj)
        self.assertTrue(allowed)
        pol.is_allowed.assert_not_called()

    def test_none_user_skips_policy_check(self):
        """
        ``request.user is None`` must not be funnelled either — regression
        for the original guard before the ``is_authenticated`` tightening.
        """
        request = SimpleNamespace(user=None)
        pol = _stub_policy()
        with patch.object(AllianceAuthOAuth2Validator, "policy", pol):
            allowed = self.validator._enforce_policy(request, self.client_obj)
        self.assertTrue(allowed)
        pol.is_allowed.assert_not_called()

    def test_authenticated_user_runs_policy_check(self):
        """
        Authenticated user with a permissive policy ⇒ ``is_allowed`` runs
        once and the policy passes.
        """
        request = SimpleNamespace(user=self.user1)
        pol = _stub_policy(is_allowed=True)
        with patch.object(AllianceAuthOAuth2Validator, "policy", pol):
            allowed = self.validator._enforce_policy(request, self.client_obj)
        self.assertTrue(allowed)
        pol.is_allowed.assert_called_once_with(self.user1, self.client_obj)

    def test_authenticated_user_denied_returns_false(self):
        """
        Denying policy ⇒ ``_enforce_policy`` returns False (the OAuth
        flow then translates this into ``invalid_grant``).
        """
        request = SimpleNamespace(user=self.user1)
        pol = _stub_policy(is_allowed=False)
        with patch.object(AllianceAuthOAuth2Validator, "policy", pol):
            allowed = self.validator._enforce_policy(request, self.client_obj)
        self.assertFalse(allowed)


class TestSaveBearerTokenAuthGuard(OIDCTestCase):
    """
    ``save_bearer_token`` mirrors ``_enforce_policy``'s guard but uses
    the raise-form (``policy.enforce``) so PermissionDenied → 401
    translation lives at the boundary.

    Direct unit test rather than driving the full client_credentials
    flow: we stub the DOT super() call so the test stays focused on
    the AA-specific guard behaviour.
    """

    def setUp(self) -> None:
        super().setUp()
        self.validator = AllianceAuthOAuth2Validator()

    def test_anonymous_user_does_not_invoke_policy_gate(self):
        request = SimpleNamespace(
            user=AnonymousUser(),
            client=self.oauth_app,
            application=None,
        )
        pol = _stub_policy()
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            patch(
                "oauth2_provider.oauth2_validators.OAuth2Validator.save_bearer_token",
                return_value=None,
            ) as super_save,
        ):
            self.validator.save_bearer_token({"access_token": "x"}, request)
        pol.enforce.assert_not_called()
        super_save.assert_called_once()


class TestOidcClaimScopeBinding(SimpleTestCase):
    """
    ``oidc_claim_scope`` reads from a process-level cache keyed on
    the ``OIDCSettings`` snapshot. Settings flips (via
    ``@override_settings``) produce a new snapshot → cache miss →
    fresh map; same-settings reads share one dict across all
    validator instances.
    """

    def test_default_settings_emit_eve_prefix_under_profile(self):
        validator = AllianceAuthOAuth2Validator()
        self.assertEqual("profile", validator.oidc_claim_scope["groups"])
        self.assertEqual(
            "profile", validator.oidc_claim_scope["eve_character_id"]
        )

    @override_settings(
        ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX="custom_",
        ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE="eve",
    )
    def test_override_settings_reflected_per_validator_instance(self):
        # Regression: with the previous class-level binding,
        # @override_settings was invisible — every test saw whatever
        # had been snapshotted at import. The cache now hangs off the
        # OIDCSettings snapshot, which is rebuilt on setting_changed.
        validator = AllianceAuthOAuth2Validator()
        self.assertEqual(
            "eve", validator.oidc_claim_scope["custom_character_id"]
        )
        self.assertNotIn("eve_character_id", validator.oidc_claim_scope)

    def test_map_is_shared_across_instances_under_same_settings(self):
        # Class-level cache: two validators built without changing
        # settings receive the IDENTICAL dict object, not a copy.
        # Saves a redundant rebuild on every per-request validator.
        v1 = AllianceAuthOAuth2Validator()
        v2 = AllianceAuthOAuth2Validator()
        self.assertIs(v1.oidc_claim_scope, v2.oidc_claim_scope)

    def test_override_settings_swaps_map_for_all_instances(self):
        # Inverse of the previous per-instance test: under
        # @override_settings, both pre-existing AND new validators
        # see the new map (the cache key changes with the snapshot,
        # not with validator identity).
        v1 = AllianceAuthOAuth2Validator()
        self.assertIn("eve_character_id", v1.oidc_claim_scope)
        with override_settings(
            ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX="custom_",
        ):
            v2 = AllianceAuthOAuth2Validator()
            # Both instances pick up the new prefix.
            self.assertIn("custom_character_id", v1.oidc_claim_scope)
            self.assertIn("custom_character_id", v2.oidc_claim_scope)


class TestResolveUserAndClient(SimpleTestCase):
    """
    Direct tests for the ``_resolve_user_and_client`` helper.

    The helper is the only place where the (user, client) tuple that
    feeds the policy gate is built; every validator that runs the
    gate (``validate_code``, ``validate_refresh_token``,
    ``save_bearer_token``) ends up here. Surviving cosmic-ray mutants
    target the ``is_authenticated`` default (``ReplaceFalseWithTrue``)
    and the three-way ``or``-chain (``ReplaceOrWithAnd``).
    """

    def test_user_missing_is_authenticated_attr_is_treated_as_anon(self):
        # ``getattr(user, "is_authenticated", False)``: a stub that
        # lacks the attribute MUST take the False branch (return
        # ``(None, None)``). Flipping the default to True would
        # silently treat any attribute-less object as authenticated.
        user_stub = SimpleNamespace()  # no is_authenticated, no client either
        request = SimpleNamespace(
            user=user_stub, client=object(), application=None
        )
        u, c = AllianceAuthOAuth2Validator._resolve_user_and_client(request)
        self.assertIsNone(u)
        self.assertIsNone(c)

    def test_client_arg_short_circuits_or_chain(self):
        # ``client_arg or request.client or request.application`` —
        # ``or`` returns the first truthy operand. Mutating to ``and``
        # forces evaluation of all three and returns the LAST operand
        # instead, which here is ``None``.
        sentinel_arg = SimpleNamespace(label="arg-wins")
        request = SimpleNamespace(
            user=SimpleNamespace(is_authenticated=True),
            client=SimpleNamespace(label="request.client"),
            application=None,
        )
        u, c = AllianceAuthOAuth2Validator._resolve_user_and_client(
            request, client_arg=sentinel_arg
        )
        self.assertIs(sentinel_arg, c)
        self.assertIs(request.user, u)

    def test_falls_through_to_request_application_when_others_missing(self):
        # No client_arg, request.client is None — must take
        # request.application. The ``or`` short-circuit must visit all
        # three operands when the first two are falsy.
        sentinel_app = SimpleNamespace(label="application")
        request = SimpleNamespace(
            user=SimpleNamespace(is_authenticated=True),
            client=None,
            application=sentinel_app,
        )
        _, c = AllianceAuthOAuth2Validator._resolve_user_and_client(request)
        self.assertIs(sentinel_app, c)


class TestEnforcePolicyLogs(OIDCTestCase):
    """
    ``_enforce_policy`` warns on denial. The ``if not allowed:`` guard
    has two surviving cosmic-ray mutants — ``AddNot`` (would skip
    logging on actual denies) and ``Delete_Not`` (would log on every
    *allow*). Both produce wrong audit traffic.
    """

    def setUp(self) -> None:
        super().setUp()
        self.validator = AllianceAuthOAuth2Validator()

    def test_denied_request_emits_warning(self):
        # Without the assertion, mutating ``if not allowed`` to ``if
        # allowed`` (Delete_Not) survives — the function still
        # returns False, but the log line goes silent.
        request = SimpleNamespace(user=self.user1)
        pol = _stub_policy(is_allowed=False)
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            self.assertLogs(
                "extensions.allianceauth_oidc.auth_provider", level="WARNING"
            ) as cap,
        ):
            self.assertFalse(
                self.validator._enforce_policy(request, self.oauth_app)
            )
        self.assertTrue(
            any("DENIED: validator" in m for m in cap.output),
            f"denied warning missing in {cap.output!r}",
        )

    def test_allowed_request_does_not_emit_warning(self):
        # Mirror: Delete_Not would flip the branch and emit a denial
        # warning on every allow, drowning real signals.
        request = SimpleNamespace(user=self.user1)
        pol = _stub_policy(is_allowed=True)
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            self.assertNoLogs(
                "extensions.allianceauth_oidc.auth_provider", level="WARNING"
            ),
        ):
            self.assertTrue(
                self.validator._enforce_policy(request, self.oauth_app)
            )


class TestSaveBearerTokenExceptionGuard(OIDCTestCase):
    """
    ``save_bearer_token`` wraps ``policy.enforce(...)`` in ``try /
    except PermissionDenied``. The narrow exception type is the
    correctness contract: any other exception (programmer error,
    config bug) MUST propagate to a real 500 rather than be
    swallowed into ``invalid_grant``. ``ExceptionReplacer`` widens or
    narrows the caught type — both directions break the contract.
    """

    def setUp(self) -> None:
        super().setUp()
        self.validator = AllianceAuthOAuth2Validator()

    def test_permission_denied_translates_to_invalid_grant(self):
        # Original contract: PermissionDenied is caught and re-raised
        # as InvalidGrantError. A mutant that narrows the catch (e.g.
        # to a subclass that never fires) would let PermissionDenied
        # escape as a 500 to the OAuth client.
        from django.core.exceptions import PermissionDenied
        from oauthlib.oauth2.rfc6749 import errors as oauth_errors

        request = SimpleNamespace(
            user=self.user1, client=self.oauth_app, application=None
        )
        pol = _stub_policy()
        pol.enforce.side_effect = PermissionDenied("nope")
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            patch(
                "oauth2_provider.oauth2_validators.OAuth2Validator"
                ".save_bearer_token",
                return_value=None,
            ),
            self.assertRaises(oauth_errors.InvalidGrantError),
        ):
            self.validator.save_bearer_token({"access_token": "x"}, request)

    def test_unrelated_exception_propagates_unwrapped(self):
        # A widening mutant (``except Exception``) would swallow
        # ``RuntimeError`` and convert it into ``InvalidGrantError``,
        # masking a real bug. The narrow ``except PermissionDenied``
        # MUST let unrelated exceptions surface.
        request = SimpleNamespace(
            user=self.user1, client=self.oauth_app, application=None
        )
        pol = _stub_policy()
        pol.enforce.side_effect = RuntimeError("config bug")
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            patch(
                "oauth2_provider.oauth2_validators.OAuth2Validator"
                ".save_bearer_token",
                return_value=None,
            ),
            self.assertRaises(RuntimeError),
        ):
            self.validator.save_bearer_token({"access_token": "x"}, request)


class TestSaveBearerTokenNoClientSkip(OIDCTestCase):
    """
    ``save_bearer_token`` skips the policy gate on grants that do not
    carry a client on the oauthlib request, but emits an INFO marker
    so operators can spot the skip after a regression that nulled
    out ``client`` upstream. Pins both the ``user is not None and
    client is None`` guard (where ``and`` → ``or`` mutants would log
    on the wrong shape) and the log message itself.
    """

    def setUp(self) -> None:
        super().setUp()
        self.validator = AllianceAuthOAuth2Validator()

    def test_user_present_but_no_client_logs_skip(self):
        # The defensive ``elif user is not None and client is None``
        # branch is only reachable when the resolver returns
        # ``(user, None)`` — a shape it does not naturally produce
        # today (the resolver collapses both halves missing into
        # ``(None, None)``). Patching the resolver to that shape
        # exercises the elif branch directly so the log marker and
        # the ``and`` boolean operator on its guard are pinned.
        request = SimpleNamespace(
            user=self.user1, client=None, application=None
        )
        pol = _stub_policy()
        with (
            patch.object(AllianceAuthOAuth2Validator, "policy", pol),
            patch.object(
                AllianceAuthOAuth2Validator,
                "_resolve_user_and_client",
                return_value=(self.user1, None),
            ),
            patch(
                "oauth2_provider.oauth2_validators.OAuth2Validator"
                ".save_bearer_token",
                return_value=None,
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.auth_provider", level="INFO"
            ) as cap,
        ):
            self.validator.save_bearer_token({"access_token": "x"}, request)
        self.assertTrue(
            any("no_client" in m for m in cap.output),
            f"skip-INFO missing in {cap.output!r}",
        )
        pol.enforce.assert_not_called()


class TestValidateSilentAuthorization(OIDCTestCase):
    """
    Pin the short-circuit branches of ``validate_silent_authorization``.

    Four surviving cosmic-ray mutants live on the short-circuit chain:

    * ``getattr(client, "skip_authorization", False)`` default —
      missing attr must NOT trigger the trusted-client fast path.
    * ``user is None or not getattr(user, "is_authenticated", False)``
      — both halves of the ``or`` must fire.
    * Empty-scopes early return — empty must be False.

    Combining narrow stubs with a real `AllianceAuthOAuth2Validator`
    avoids reaching the DB ``AccessToken.filter`` line for these
    branches (the DB path is covered indirectly by the prompt=none
    tests in test_authorize.py).
    """

    def setUp(self) -> None:
        super().setUp()
        self.validator = AllianceAuthOAuth2Validator()

    def test_client_without_skip_authorization_attr_does_not_short_circuit(
        self,
    ):
        # Missing ``skip_authorization`` ⇒ default False ⇒ continue.
        # If the path took the True fast-path on a missing attr,
        # an anonymous user would be silently approved.
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="c"),  # no skip_authorization
            user=None,
            scopes=["openid"],
        )
        self.assertFalse(self.validator.validate_silent_authorization(request))

    def test_skip_authorization_true_short_circuits_to_allow(self):
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="c", skip_authorization=True),
            user=None,  # would otherwise deny
            scopes=["openid"],
        )
        self.assertTrue(self.validator.validate_silent_authorization(request))

    def test_anonymous_user_denies_silent_consent(self):
        # ``user is None`` — left side of the ``or`` fires.
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="c", skip_authorization=False),
            user=None,
            scopes=["openid"],
        )
        self.assertFalse(self.validator.validate_silent_authorization(request))

    def test_unauthenticated_user_denies_silent_consent(self):
        # User present but ``is_authenticated`` is False — right side
        # of the ``or`` fires. The two together pin ``or`` against
        # ``and``: the ``and``-mutant requires BOTH branches True
        # simultaneously (impossible) and would silently approve every
        # unauthenticated request that has a user object attached.
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="c", skip_authorization=False),
            user=SimpleNamespace(is_authenticated=False),
            scopes=["openid"],
        )
        self.assertFalse(self.validator.validate_silent_authorization(request))

    def test_empty_scopes_denies_silent_consent(self):
        # Empty scope set is not positive proof of prior consent —
        # let oauthlib drive. ``ReplaceFalseWithTrue`` on the early
        # return would turn empty-scopes into auto-approve.
        request = SimpleNamespace(
            client=SimpleNamespace(client_id="c", skip_authorization=False),
            user=self.user1,  # authenticated real user
            scopes=[],
        )
        self.assertFalse(self.validator.validate_silent_authorization(request))
