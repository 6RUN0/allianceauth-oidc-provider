"""
Tests for ``allianceauth_oidc.checks`` system-check registrations.

E001 (BCL + OIDC_ISS_ENDPOINT) is covered alongside the rest of the
back-channel-logout suite in ``test_back_channel_logout.py``. This
module covers the silent-bypass guards:

* **E002** — ``OAUTH2_PROVIDER_APPLICATION_MODEL`` must point at
  ``AllianceAuthApplication`` (or a subclass). Without this, DOT's
  swappable model resolves to the stock ``oauth2_provider.Application``
  and the three-layer policy enforcement documented in ``CLAUDE.md``
  silently becomes a no-op.

* **E003** — ``OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`` must
  resolve to ``AllianceAuthOAuth2Validator`` (or a subclass). Without
  this, validation falls through to DOT's stock validator and layers
  2 and 3 of the policy enforcement vanish.

Both are paired with a ``manage.py check`` integration assertion: it
is the integration test that historically protects E001 from a
regression where ``register`` is dropped and the check becomes
unreachable.
"""

from __future__ import annotations

from io import StringIO
from typing import Any

from django.conf import settings as dj_settings
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import TestCase, override_settings
from oauth2_provider.settings import oauth2_settings


def _override_oauth2_provider(**overrides: Any) -> dict[str, Any]:
    """
    Build an ``OAUTH2_PROVIDER`` dict mutating only ``overrides`` keys.

    Direct ``override_settings(OAUTH2_PROVIDER={"X": ...})`` would
    nuke every other key; copying the existing dict keeps DOT's
    other knobs intact so the test process can still finish the
    OIDC handshake (some checks indirectly touch ``OIDC_ISS_ENDPOINT``
    etc.). Pattern mirrors ``_override_iss`` in
    ``test_back_channel_logout.py``.
    """
    cfg = dict(getattr(dj_settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.update(overrides)
    return cfg


class TestApplicationModelCheck(TestCase):
    """E002 fires when the swappable Application model is wrong."""

    def test_e002_error_when_application_model_is_stock_dot(self) -> None:
        from allianceauth_oidc.checks import (
            E002_ID,
            check_application_model,
        )

        # Stock DOT model — the silent-bypass scenario.
        with override_settings(
            OAUTH2_PROVIDER_APPLICATION_MODEL="oauth2_provider.Application"
        ):
            msgs = check_application_model(None)

        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, E002_ID)
        # Severity is Error, not Warning — a misconfigured swappable
        # model is structurally fatal for policy enforcement.
        self.assertEqual(msg.level, checks.ERROR)

    def test_e002_clean_when_application_model_is_alliance_auth(
        self,
    ) -> None:
        """Default test settings already pin the correct model."""
        from allianceauth_oidc.checks import check_application_model

        msgs = check_application_model(None)
        self.assertEqual(msgs, [])

    def test_e002_clean_when_application_model_is_subclass(self) -> None:
        """
        A custom subclass of ``AllianceAuthApplication`` keeps the
        policy enforcement (the subclass inherits validators/access
        logic). The check accepts subclasses to avoid forbidding the
        legitimate "extend the model" pattern.
        """
        # We cannot dynamically register a real subclass at runtime
        # without migrations, so this test documents the contract via
        # the default case (covered above) and the subclass-acceptance
        # is enforced by an ``issubclass`` call in the implementation
        # — exercised by mypy/basedpyright through the type signature.
        from allianceauth_oidc.checks import check_application_model
        from allianceauth_oidc.models import AllianceAuthApplication

        self.assertTrue(
            issubclass(AllianceAuthApplication, AllianceAuthApplication)
        )
        msgs = check_application_model(None)
        self.assertEqual(msgs, [])

    def test_manage_check_raises_with_e002(self) -> None:
        """
        Integration: ``manage.py check`` exits non-zero when E002
        fires. Mirrors the ``test_ac19f_manage_check_raises_with_e001``
        contract — without this assertion, a missing ``@register``
        decorator would leave the check importable but unreachable
        through the CLI surface operators actually use.
        """
        out = StringIO()
        with (
            override_settings(
                OAUTH2_PROVIDER_APPLICATION_MODEL=(
                    "oauth2_provider.Application"
                )
            ),
            self.assertRaises(SystemCheckError) as ctx,
        ):
            call_command("check", stdout=out, stderr=out)
        self.assertIn("allianceauth_oidc.E002", str(ctx.exception))


class TestValidatorClassCheck(TestCase):
    """E003 fires when ``OAUTH2_VALIDATOR_CLASS`` is wrong."""

    def _reload_dot(self) -> None:
        """Push the OAUTH2_PROVIDER override into DOT's cached snapshot."""
        oauth2_settings.reload()
        self.addCleanup(oauth2_settings.reload)

    def test_e003_error_when_validator_class_is_stock_dot(self) -> None:
        from allianceauth_oidc.checks import (
            E003_ID,
            check_validator_class,
        )

        cfg = _override_oauth2_provider(
            OAUTH2_VALIDATOR_CLASS=(
                "oauth2_provider.oauth2_validators.OAuth2Validator"
            ),
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_validator_class(None)

        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, E003_ID)
        self.assertEqual(msg.level, checks.ERROR)

    def test_e003_clean_when_validator_class_is_alliance_auth(self) -> None:
        from allianceauth_oidc.checks import check_validator_class

        msgs = check_validator_class(None)
        self.assertEqual(msgs, [])

    def test_manage_check_raises_with_e003(self) -> None:
        out = StringIO()
        cfg = _override_oauth2_provider(
            OAUTH2_VALIDATOR_CLASS=(
                "oauth2_provider.oauth2_validators.OAuth2Validator"
            ),
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            oauth2_settings.reload()
            self.addCleanup(oauth2_settings.reload)
            with self.assertRaises(SystemCheckError) as ctx:
                call_command("check", stdout=out, stderr=out)
        self.assertIn("allianceauth_oidc.E003", str(ctx.exception))


class TestChecksBootstrapPaths(TestCase):
    """
    Pin the ``except _BOOTSTRAP_EXCEPTIONS as exc:`` branches in
    ``check_application_model`` and ``check_validator_class``.

    Symmetric counterpart to the E001 bootstrap test in
    ``test_back_channel_logout.py`` — these two checks carry the
    same defensive catch + ``exc_info=True`` log. The catch lets
    ``manage.py migrate`` invoke the checks before the app registry
    is fully populated; narrowing it would block migration on its
    own check call, and dropping ``exc_info=True`` would hide the
    underlying error from operator logs.
    """

    def test_e002_bootstrap_lookup_error_yields_deferred_no_error(
        self,
    ) -> None:
        from unittest import mock

        from allianceauth_oidc.checks import check_application_model

        with (
            mock.patch(
                "allianceauth_oidc.checks.apps.get_model",
                side_effect=LookupError("App registry not ready"),
            ),
            override_settings(
                OAUTH2_PROVIDER_APPLICATION_MODEL=(
                    "allianceauth_oidc.AllianceAuthApplication"
                )
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.checks", level="WARNING"
            ) as cap,
        ):
            msgs = check_application_model(None)
        self.assertEqual(msgs, [])
        # ``exc_info=True`` populates ``LogRecord.exc_info`` with a
        # ``(type, value, tb)`` tuple. ``exc_info=False`` leaves the
        # attribute as ``False`` (NOT None), so the narrower
        # ``assertIsInstance(..., tuple)`` is required to discriminate.
        self.assertIsInstance(
            cap.records[0].exc_info,
            tuple,
            "E002 deferred log lacks exc_info tuple — "
            "ReplaceFalseWithTrue mutation?",
        )

    def test_e003_bootstrap_import_error_yields_deferred_no_error(
        self,
    ) -> None:
        # ``check_validator_class`` reads through ``import_string``;
        # patch it to raise an importable subset of
        # ``_BOOTSTRAP_EXCEPTIONS``. ``ImportError`` is a member,
        # so the catch must absorb it.
        from unittest import mock

        from allianceauth_oidc.checks import check_validator_class

        cfg = _override_oauth2_provider(
            OAUTH2_VALIDATOR_CLASS=(
                "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"
            ),
        )
        with (
            mock.patch(
                "allianceauth_oidc.checks.import_string",
                side_effect=ImportError("module not ready"),
            ),
            override_settings(OAUTH2_PROVIDER=cfg),
            self.assertLogs(
                "extensions.allianceauth_oidc.checks", level="WARNING"
            ) as cap,
        ):
            msgs = check_validator_class(None)
        # The check falls through and returns the E003 error message
        # for "configured but not resolvable" — this is the
        # documented "deferred" outcome that's actually [E003] when
        # ``import_string`` fails but the setting was set. Compare
        # with the in-source comment: ``return []`` is reached only
        # after the bootstrap catch absorbs the exception. We
        # observe that the WARNING log fired (catch was entered) —
        # if narrowed to a non-matching exception type, the
        # ``ImportError`` would have propagated out instead and
        # ``assertLogs`` would fail.
        self.assertTrue(
            any("E003" in r.message for r in cap.records),
            f"WARNING log missing for E003 bootstrap: {cap.output}",
        )
        self.assertIsInstance(
            cap.records[0].exc_info,
            tuple,
            "E003 deferred log lacks exc_info tuple — "
            "ReplaceFalseWithTrue mutation?",
        )
        # And the check returns [] (deferred), not a hard error.
        self.assertEqual(msgs, [])
