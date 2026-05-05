"""
Unit tests for ``AllianceAuthOAuth2Validator``'s policy hooks.

These tests stay below the HTTP layer: ``_enforce_policy`` and
``save_bearer_token`` are exercised against synthetic request objects
so the AnonymousUser branch can be reached without spinning up the
client_credentials grant flow (which DOT does not register by
default in the test settings).
"""

from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied

from allianceauth_oidc.auth_provider import AllianceAuthOAuth2Validator

from ._oidc_testcase import OIDCTestCase


class TestEnforcePolicyAuthGuard(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Policy gate runs against the application object; only its
        # presence is checked here, the gate itself is mocked out.
        self.client_obj = self.oauth_app

    def test_anonymous_user_skips_policy_check(self):
        """``AnonymousUser`` must not be funnelled through the per-app
        state/group gate.

        client_credentials and similar end-user-less grants present
        ``AnonymousUser`` (or ``None``) on ``request.user``. Letting
        ``check_user_state_and_groups`` run on those tokens would deny
        every machine-to-machine token because anonymous users carry
        no Django state/groups.
        """
        request = SimpleNamespace(user=AnonymousUser())
        with patch(
            "allianceauth_oidc.auth_provider.check_user_state_and_groups"
        ) as gate:
            allowed = AllianceAuthOAuth2Validator._enforce_policy(
                request, self.client_obj
            )
        self.assertTrue(allowed)
        gate.assert_not_called()

    def test_none_user_skips_policy_check(self):
        """``request.user is None`` must not be funnelled either —
        regression for the original guard before the
        ``is_authenticated`` tightening.
        """
        request = SimpleNamespace(user=None)
        with patch(
            "allianceauth_oidc.auth_provider.check_user_state_and_groups"
        ) as gate:
            allowed = AllianceAuthOAuth2Validator._enforce_policy(
                request, self.client_obj
            )
        self.assertTrue(allowed)
        gate.assert_not_called()

    def test_authenticated_user_runs_policy_check(self):
        """Authenticated user with a permissive gate ⇒ the gate runs
        once and the policy passes.
        """
        request = SimpleNamespace(user=self.user1)
        with patch(
            "allianceauth_oidc.auth_provider.check_user_state_and_groups"
        ) as gate:
            allowed = AllianceAuthOAuth2Validator._enforce_policy(
                request, self.client_obj
            )
        self.assertTrue(allowed)
        gate.assert_called_once_with(self.user1, self.client_obj)

    def test_authenticated_user_denied_returns_false(self):
        """``PermissionDenied`` from the gate ⇒ policy returns False
        (the OAuth flow then translates this into ``invalid_grant``).
        """
        request = SimpleNamespace(user=self.user1)
        with patch(
            "allianceauth_oidc.auth_provider.check_user_state_and_groups",
            side_effect=PermissionDenied("blocked"),
        ):
            allowed = AllianceAuthOAuth2Validator._enforce_policy(
                request, self.client_obj
            )
        self.assertFalse(allowed)


class TestSaveBearerTokenAuthGuard(OIDCTestCase):
    """``save_bearer_token`` mirrors ``_enforce_policy``'s guard.

    Direct unit test rather than driving the full client_credentials
    flow: we mock the DOT super() call so the test stays focused on
    the AA-specific guard behavior.
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
        with (
            patch(
                "allianceauth_oidc.auth_provider.check_user_state_and_groups"
            ) as gate,
            patch(
                "oauth2_provider.oauth2_validators.OAuth2Validator.save_bearer_token",
                return_value=None,
            ) as super_save,
        ):
            self.validator.save_bearer_token({"access_token": "x"}, request)
        gate.assert_not_called()
        super_save.assert_called_once()
