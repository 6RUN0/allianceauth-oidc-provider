"""
``AllianceAuthOIDC.ready`` settings-default tests.

The AppConfig flips a sensible default-on for
``OIDC_RP_INITIATED_LOGOUT_ENABLED`` because DOT's default (``False``)
both 404s ``/o/logout/`` and drops ``end_session_endpoint`` from
discovery — a half-paved street since our own discovery view already
advertises ``backchannel_logout_supported=True``. ``setdefault``
preserves operator opt-out so an explicit ``False`` stays ``False``.

Sibling ``_check_jwt_wiring`` coverage lives in
``tests.test_jwt_validation.TestStartupWiringCheck`` — identical
override-settings pattern is reused here so DOT's
``OAuth2ProviderSettings`` reload-on-signal flow is exercised the
same way.
"""

from __future__ import annotations

from django.conf import settings as django_settings
from django.test import TestCase, override_settings

from ._settings_helpers import override_settings_no_dot_reload


class TestApplyDefaultOauth2ProviderSettings(TestCase):
    """
    Three branches of ``_apply_default_oauth2_provider_settings``:
    fill-the-gap default-on, respect operator opt-out, and the
    no-OAUTH2_PROVIDER-dict shape that runs silently.
    """

    KEY = "OIDC_RP_INITIATED_LOGOUT_ENABLED"

    def _provider_without(self) -> dict:
        provider = dict(django_settings.OAUTH2_PROVIDER)
        provider.pop(self.KEY, None)
        return provider

    def test_default_on_when_key_absent(self) -> None:
        """
        Setting absent from ``OAUTH2_PROVIDER`` → helper writes ``True``
        AND propagates the value onto DOT's cached ``oauth2_settings``
        attribute (DOT's reader caches on first access, so dict
        mutation alone would silently desync).
        """
        provider = self._provider_without()
        with override_settings(OAUTH2_PROVIDER=provider):
            from oauth2_provider.settings import oauth2_settings

            from allianceauth_oidc.apps import (
                _apply_default_oauth2_provider_settings,
            )

            _apply_default_oauth2_provider_settings()
            self.assertTrue(provider[self.KEY])
            self.assertTrue(oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED)

    def test_respects_explicit_false_opt_out(self) -> None:
        """Operator-set ``False`` is preserved (no overwrite)."""
        provider = self._provider_without()
        provider[self.KEY] = False
        with override_settings(OAUTH2_PROVIDER=provider):
            from oauth2_provider.settings import oauth2_settings

            from allianceauth_oidc.apps import (
                _apply_default_oauth2_provider_settings,
            )

            _apply_default_oauth2_provider_settings()
            self.assertFalse(provider[self.KEY])
            self.assertFalse(oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED)

    def test_respects_explicit_true(self) -> None:
        """
        Explicit ``True`` set by operator stays ``True`` (idempotent).
        ``setdefault`` returns the existing value rather than the
        default; verify the value is still ``True`` after the call.
        """
        provider = self._provider_without()
        provider[self.KEY] = True
        with override_settings(OAUTH2_PROVIDER=provider):
            from oauth2_provider.settings import oauth2_settings

            from allianceauth_oidc.apps import (
                _apply_default_oauth2_provider_settings,
            )

            _apply_default_oauth2_provider_settings()
            self.assertTrue(provider[self.KEY])
            self.assertTrue(oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED)

    def test_no_op_when_oauth2_provider_is_not_dict(self) -> None:
        """
        Degraded shape (``OAUTH2_PROVIDER=None``) returns silently —
        no exception, no mutation. Operators in this state already
        have bigger problems (DOT will not configure itself), but the
        helper must not amplify the failure.
        """
        with override_settings_no_dot_reload(OAUTH2_PROVIDER=None):
            from allianceauth_oidc.apps import (
                _apply_default_oauth2_provider_settings,
            )

            # Plain function call — no exception means pass.
            _apply_default_oauth2_provider_settings()
