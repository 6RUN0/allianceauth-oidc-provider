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
