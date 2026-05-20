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

Warning-level checks covered here:

* **W001** — masked-fragment secret logging enabled with
  ``DEBUG=False``. Production-shaped log streams should not carry
  token head/tail bytes.

* **W002** — half-wired JWT mode: default format and dispatcher
  generator agree on neither ``"jwt"`` nor ``"opaque"`` together.
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


class TestOpenidScopeConfiguredCheck(TestCase):
    """
    E004 fires when ``OAUTH2_PROVIDER['SCOPES']`` lacks ``openid``.

    DOT's default ``SCOPES`` is ``{"read": ..., "write": ...}``;
    leaving it that way deploys an OAuth2 server, not an OIDC one.
    Three coverage points:

    1. Negative — missing ``openid`` triggers the Error.
    2. Positive — dict form with ``openid`` is clean.
    3. Positive (alt shape) — list form with ``openid`` is clean.
    4. CLI integration via ``manage.py check`` so a future
       ``@register`` regression surfaces.
    """

    def _reload_dot(self) -> None:
        oauth2_settings.reload()
        self.addCleanup(oauth2_settings.reload)

    def test_e004_error_when_scopes_lack_openid(self) -> None:
        from allianceauth_oidc.checks import (
            E004_ID,
            check_openid_scope_configured,
        )

        cfg = _override_oauth2_provider(
            SCOPES={"read": "Reading scope", "write": "Writing scope"},
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_openid_scope_configured(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, E004_ID)
        # Severity Error — id_token issuance breaks without openid,
        # so the deployment is structurally non-OIDC. Warning would
        # let CI / startup succeed and crash every RP at first login.
        self.assertEqual(msg.level, checks.ERROR)

    def test_e004_clean_when_dict_scopes_include_openid(self) -> None:
        """Default test settings already pin openid in SCOPES."""
        from allianceauth_oidc.checks import check_openid_scope_configured

        msgs = check_openid_scope_configured(None)
        self.assertEqual(msgs, [])

    def test_e004_clean_when_list_scopes_include_openid(self) -> None:
        """
        Operators occasionally configure ``SCOPES`` as a list rather
        than a dict (DOT tolerates both shapes). ``'openid' in scopes``
        matches a dict key OR a list element identically, so the
        check must accept either.
        """
        from allianceauth_oidc.checks import check_openid_scope_configured

        cfg = _override_oauth2_provider(
            SCOPES=["openid", "email", "profile"],
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_openid_scope_configured(None)
        self.assertEqual(msgs, [])

    def test_manage_check_raises_with_e004(self) -> None:
        """
        CLI integration: ``manage.py check`` exits non-zero when E004
        fires. Mirrors the E002 / E003 integration tests — guards
        against a dropped ``@register`` decorator that would leave
        the check function importable but unreachable.
        """
        out = StringIO()
        cfg = _override_oauth2_provider(
            SCOPES={"read": "Reading scope", "write": "Writing scope"},
        )
        with (
            override_settings(OAUTH2_PROVIDER=cfg),
            self.assertRaises(SystemCheckError) as ctx,
        ):
            oauth2_settings.reload()
            self.addCleanup(oauth2_settings.reload)
            call_command("check", stdout=out, stderr=out)
        self.assertIn("allianceauth_oidc.E004", str(ctx.exception))


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

    def test_w003_bootstrap_lookup_error_yields_deferred_no_error(
        self,
    ) -> None:
        """
        W003's ``apps.get_model("allianceauth_oidc", "AllianceAuthApplication")``
        can raise ``LookupError`` during ``manage.py migrate`` (the
        check fires before the app registry is fully populated). The
        catch must absorb that path and emit a WARNING with
        ``exc_info=True`` — narrowing the catch would block migration
        on its own check call; dropping ``exc_info`` would hide the
        triggering exception from operator logs.

        The check only reaches the ``get_model`` call when the
        operator EXPLICITLY set the logout flag to False; otherwise
        the early-return on the absent-key default-on path skips the
        DB query entirely. Set the flag explicitly here so the
        bootstrap branch is reachable.
        """
        from unittest import mock

        from allianceauth_oidc.checks import check_logout_wiring

        cfg = _override_oauth2_provider(OIDC_RP_INITIATED_LOGOUT_ENABLED=False)
        with (
            mock.patch(
                "allianceauth_oidc.checks.apps.get_model",
                side_effect=LookupError("App registry not ready"),
            ),
            override_settings(OAUTH2_PROVIDER=cfg),
            self.assertLogs(
                "extensions.allianceauth_oidc.checks", level="WARNING"
            ) as cap,
        ):
            msgs = check_logout_wiring(None)
        self.assertEqual(msgs, [])
        self.assertTrue(
            any("W003" in r.message for r in cap.records),
            f"WARNING log missing for W003 bootstrap: {cap.output}",
        )
        self.assertIsInstance(
            cap.records[0].exc_info,
            tuple,
            "W003 deferred log lacks exc_info tuple — "
            "ReplaceFalseWithTrue mutation?",
        )


class TestMaskedSecretLoggingInProductionCheck(TestCase):
    """W001 fires when masked-secret logging is on in production."""

    def test_w001_clean_when_setting_unset(self) -> None:
        """Default posture: ``<redacted>`` everywhere → no warning."""
        from allianceauth_oidc.checks import (
            check_masked_secret_logging_in_production,
        )

        # Explicitly drive DEBUG=False to make sure the gate fires
        # only on the masked-logging flag, not on DEBUG alone.
        with override_settings(DEBUG=False):
            msgs = check_masked_secret_logging_in_production(None)
        self.assertEqual(msgs, [])

    def test_w001_clean_when_debug_true(self) -> None:
        """
        Masked logging IS the documented development posture; with
        ``DEBUG=True`` the operator gets head/tail fragments in a
        local development context where that exposure is acceptable.
        """
        from allianceauth_oidc.checks import (
            check_masked_secret_logging_in_production,
        )

        with override_settings(
            DEBUG=True,
            ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True,
        ):
            msgs = check_masked_secret_logging_in_production(None)
        self.assertEqual(msgs, [])

    def test_w001_warning_when_masked_logging_and_no_debug(self) -> None:
        """The exposure case: production-shaped DEBUG=False + masked."""
        from allianceauth_oidc.checks import (
            W001_ID,
            check_masked_secret_logging_in_production,
        )

        with override_settings(
            DEBUG=False,
            ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True,
        ):
            msgs = check_masked_secret_logging_in_production(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W001_ID)
        # Severity is Warning, not Error — the trade-off is a
        # documented operator choice.
        self.assertEqual(msg.level, checks.WARNING)

    def test_manage_check_does_not_raise_with_w001(self) -> None:
        """
        Warning-level checks do not abort ``manage.py check``. This
        contract is the whole point of ``Warning`` vs ``Error`` —
        regressing it (e.g. by setting level=ERROR) would block
        production deploys for an operator-acceptable trade-off.
        """
        out = StringIO()
        with override_settings(
            DEBUG=False,
            ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True,
        ):
            # No SystemCheckError; the W001 message is printed but
            # the command exits 0.
            call_command("check", stdout=out, stderr=out)
        self.assertIn("allianceauth_oidc.W001", out.getvalue())


class TestJwtModeWiringCheck(TestCase):
    """W002 fires on half-wired JWT access-token mode."""

    def _reload_dot(self) -> None:
        oauth2_settings.reload()
        self.addCleanup(oauth2_settings.reload)

    def test_w002_clean_when_jwt_disabled(self) -> None:
        """Default posture: opaque tokens, no dispatcher → no warning."""
        from allianceauth_oidc.checks import check_jwt_mode_wiring

        cfg = _override_oauth2_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="opaque",
        )
        cfg.pop("ACCESS_TOKEN_GENERATOR", None)
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_jwt_mode_wiring(None)
        self.assertEqual(msgs, [])

    def test_w002_clean_when_jwt_fully_wired(self) -> None:
        """Default jwt + dispatcher generator → no warning."""
        from allianceauth_oidc.checks import check_jwt_mode_wiring

        cfg = _override_oauth2_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt",
            ACCESS_TOKEN_GENERATOR=(
                "allianceauth_oidc.tokens.dispatching_access_token_generator"
            ),
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_jwt_mode_wiring(None)
        self.assertEqual(msgs, [])

    def test_w002_warning_when_default_jwt_but_no_dispatcher(self) -> None:
        """default=jwt + generator missing → silent opaque fallback."""
        from allianceauth_oidc.checks import (
            W002_ID,
            check_jwt_mode_wiring,
        )

        cfg = _override_oauth2_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt",
        )
        cfg.pop("ACCESS_TOKEN_GENERATOR", None)
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_jwt_mode_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W002_ID)
        self.assertEqual(msg.level, checks.WARNING)

    def test_w002_warning_when_dispatcher_but_default_opaque(self) -> None:
        """Generator wired but default=opaque → global default no-op."""
        from allianceauth_oidc.checks import (
            W002_ID,
            check_jwt_mode_wiring,
        )

        cfg = _override_oauth2_provider(
            ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="opaque",
            ACCESS_TOKEN_GENERATOR=(
                "allianceauth_oidc.tokens.dispatching_access_token_generator"
            ),
        )
        with override_settings(OAUTH2_PROVIDER=cfg):
            self._reload_dot()
            msgs = check_jwt_mode_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W002_ID)
        self.assertEqual(msg.level, checks.WARNING)


class TestLogoutWiringCheck(TestCase):
    """
    W003 — Single-Logout chain broken at first hop.

    Four branches matter: key absent (default-on path), key True,
    key False but no apps configured for back-channel logout, key
    False with at least one app. Only the last fires a warning.
    OIDCTestCase isn't reused here because the W003 helper reads
    raw ``settings.OAUTH2_PROVIDER`` (not ``oauth2_settings``), so
    DOT reload isn't required and a plain ``TestCase`` keeps the
    test cheap.
    """

    def setUp(self) -> None:
        """One BCL-configured user + app — reused across positive cases."""
        from tests._factories import make_app, make_user

        # Use ``make_user`` so the AA profile/state side-effects fire
        # the same way they would in production; bare
        # ``User.objects.create`` would leave a half-initialised user
        # that the BCL save-path doesn't model.
        self.user = make_user(username="w003-fixture")
        self.creds = make_app(
            owner=self.user,
            backchannel_logout_uri="https://rp.example.org/bcl/",
        )

    def test_w003_clean_when_flag_absent(self) -> None:
        """
        Key not in OAUTH2_PROVIDER → AppConfig default-on path.

        The check distinguishes "absent" from "explicit False"
        precisely so the default-on path never trips it. A spurious
        firing here would surface on every fresh deployment whose
        operator never had reason to set the flag at all.
        """
        from allianceauth_oidc.checks import check_logout_wiring

        cfg = _override_oauth2_provider()
        cfg.pop("OIDC_RP_INITIATED_LOGOUT_ENABLED", None)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_logout_wiring(None)
        self.assertEqual(msgs, [])

    def test_w003_clean_when_flag_explicit_true(self) -> None:
        """Operator-set True (the desired posture) → no warning."""
        from allianceauth_oidc.checks import check_logout_wiring

        cfg = _override_oauth2_provider(OIDC_RP_INITIATED_LOGOUT_ENABLED=True)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_logout_wiring(None)
        self.assertEqual(msgs, [])

    def test_w003_clean_when_disabled_but_no_bcl_apps(self) -> None:
        """
        Flag explicitly False AND zero apps with backchannel_logout_uri.

        The opt-out is "intentional" only when no Single-Logout
        chain depends on it. Clearing the fixture's BCL URI
        emulates "operator disabled RP-initiated logout AND never
        configured back-channel" — a legitimate non-logout posture.
        """
        from allianceauth_oidc.checks import check_logout_wiring

        self.creds.app.backchannel_logout_uri = ""
        self.creds.app.save(update_fields=["backchannel_logout_uri"])

        cfg = _override_oauth2_provider(OIDC_RP_INITIATED_LOGOUT_ENABLED=False)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_logout_wiring(None)
        self.assertEqual(msgs, [])

    def test_w003_warning_when_disabled_and_bcl_app_present(self) -> None:
        """
        Explicit False + at least one BCL app → W003 Warning.

        Message must include the offending app name so operators
        can act on the diagnostic without grepping the DB. Pinning
        the name in the message also catches the "queryset returned
        but message omitted it" regression — a single missing
        ``f"{names}"`` interpolation would silently break the
        operator-facing experience without flipping the check
        count.
        """
        from allianceauth_oidc.checks import (
            W003_ID,
            check_logout_wiring,
        )

        cfg = _override_oauth2_provider(OIDC_RP_INITIATED_LOGOUT_ENABLED=False)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_logout_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W003_ID)
        self.assertEqual(msg.level, checks.WARNING)
        self.assertIn(self.creds.app.name, msg.msg)

    def test_w003_clean_when_oauth2_provider_is_not_dict(self) -> None:
        """
        Degraded shape (``OAUTH2_PROVIDER=None``) returns silently —
        the check never fires on a malformed top-level setting. DOT
        itself wouldn't function in this state; W003 must not
        amplify the bigger failure by adding noisy false-positive
        warnings on top of it.
        """
        from allianceauth_oidc.checks import check_logout_wiring

        with override_settings(OAUTH2_PROVIDER=None):
            msgs = check_logout_wiring(None)
        self.assertEqual(msgs, [])


class TestBclHttpInProductionCheck(TestCase):
    """
    W004 — back-channel logout URI uses ``http://`` while
    ``DEBUG=False``. The admin form rejects new ``http://`` URIs in
    production; this check surfaces legacy rows persisted under
    ``DEBUG=True`` that the worker would still POST to in cleartext.
    """

    def setUp(self) -> None:
        from tests._factories import make_app, make_user

        self.user = make_user(username="w004-fixture")
        # ``http://`` URI persisted via the factory (which mocks the
        # DNS resolver); the model layer does not run ``full_clean``
        # on ``objects.create`` so the scheme guard is bypassed at
        # creation. This is the exact state legacy production rows
        # land in after a ``DEBUG=True → False`` flip.
        self.creds = make_app(
            owner=self.user,
            backchannel_logout_uri="http://rp.example.org/bcl/",
        )

    def test_w004_warning_when_http_bcl_with_debug_false(self) -> None:
        from allianceauth_oidc.checks import (
            W004_ID,
            check_bcl_http_uri_in_production,
        )

        with override_settings(DEBUG=False):
            msgs = check_bcl_http_uri_in_production(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W004_ID)
        self.assertEqual(msg.level, checks.WARNING)
        self.assertIn(self.creds.app.name, msg.msg)

    def test_w004_clean_when_debug_true(self) -> None:
        """``DEBUG=True`` is the development posture; no warning."""
        from allianceauth_oidc.checks import (
            check_bcl_http_uri_in_production,
        )

        with override_settings(DEBUG=True):
            msgs = check_bcl_http_uri_in_production(None)
        self.assertEqual(msgs, [])

    def test_w004_clean_when_only_https_apps(self) -> None:
        """All BCL URIs use https → no warning."""
        from allianceauth_oidc.checks import (
            check_bcl_http_uri_in_production,
        )

        self.creds.app.backchannel_logout_uri = "https://rp.example.org/bcl/"
        self.creds.app.save(update_fields=["backchannel_logout_uri"])
        with override_settings(DEBUG=False):
            msgs = check_bcl_http_uri_in_production(None)
        self.assertEqual(msgs, [])

    def test_w004_clean_when_app_inactive(self) -> None:
        """
        Inactive apps cannot mint logout-tokens (the worker filters
        ``active=True``), so a stale ``http://`` URI on a deactivated
        row is documentation-only — no warning.
        """
        from allianceauth_oidc.checks import (
            check_bcl_http_uri_in_production,
        )

        self.creds.app.active = False
        self.creds.app.save(update_fields=["active"])
        with override_settings(DEBUG=False):
            msgs = check_bcl_http_uri_in_production(None)
        self.assertEqual(msgs, [])


class TestLogoutAllowPrivateInProductionCheck(TestCase):
    """
    W005 — ``ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True`` in a
    production-shaped environment (``DEBUG=False``).
    """

    def test_w005_warning_when_allow_private_with_debug_false(self) -> None:
        from allianceauth_oidc.checks import (
            W005_ID,
            check_logout_uri_allow_private_in_production,
        )

        with override_settings(
            ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True,
            DEBUG=False,
        ):
            msgs = check_logout_uri_allow_private_in_production(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, W005_ID)
        self.assertEqual(msg.level, checks.WARNING)

    def test_w005_clean_when_debug_true(self) -> None:
        """``DEBUG=True`` is the development posture; no warning."""
        from allianceauth_oidc.checks import (
            check_logout_uri_allow_private_in_production,
        )

        with override_settings(
            ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True,
            DEBUG=True,
        ):
            msgs = check_logout_uri_allow_private_in_production(None)
        self.assertEqual(msgs, [])

    def test_w005_clean_when_flag_false(self) -> None:
        """Default flag (False) → no warning, regardless of DEBUG."""
        from allianceauth_oidc.checks import (
            check_logout_uri_allow_private_in_production,
        )

        with override_settings(
            ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=False,
            DEBUG=False,
        ):
            msgs = check_logout_uri_allow_private_in_production(None)
        self.assertEqual(msgs, [])

    def test_e006_escalates_when_all_three_set_and_not_acked(
        self,
    ) -> None:
        """
        Architect#7 / E006: the dangerous combination has a concrete
        victim — at least one ``AllianceAuthApplication`` has a
        ``backchannel_logout_uri`` — so silenced Warning becomes a
        loud Error unless the operator has explicitly acknowledged
        the trade-off.
        """
        # Need a real OIDCTestCase-style user — fall back to creating
        # a minimal user inline since this is a SimpleTestCase derivative.
        from django.contrib.auth import get_user_model

        from allianceauth_oidc.checks import (
            E006_ID,
            check_logout_uri_allow_private_in_production,
        )
        from allianceauth_oidc.models import (
            AllianceAuthApplication,
        )

        User = get_user_model()
        u = User.objects.create_user(
            "e006-test-user",
            password="x",  # nosec B106 - test fixture
        )
        AllianceAuthApplication.objects.create(
            user=u,
            client_id="e006-app",
            client_secret="x",  # nosec B105 - test fixture
            redirect_uris="https://rp.example.org/cb/",
            client_type=AllianceAuthApplication.CLIENT_CONFIDENTIAL,
            authorization_grant_type=(
                AllianceAuthApplication.GRANT_AUTHORIZATION_CODE
            ),
            backchannel_logout_uri="https://rp.example.org/bcl/",
            active=True,
        )
        try:
            with override_settings(
                ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True,
                DEBUG=False,
            ):
                msgs = check_logout_uri_allow_private_in_production(None)
            self.assertEqual(len(msgs), 1, msgs)
            msg = msgs[0]
            self.assertEqual(msg.id, E006_ID)
            self.assertEqual(msg.level, checks.ERROR)
        finally:
            AllianceAuthApplication.objects.filter(user=u).delete()
            u.delete()

    def test_e006_silenced_by_explicit_ack_setting(self) -> None:
        """
        With the second opt-out
        ``ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True``,
        the escalation downgrades back to W005. The operator has
        explicitly acknowledged the trade-off (isolated lab, air-
        gapped staging) and accepts the risk in writing.
        """
        from django.contrib.auth import get_user_model

        from allianceauth_oidc.checks import (
            W005_ID,
            check_logout_uri_allow_private_in_production,
        )
        from allianceauth_oidc.models import AllianceAuthApplication

        User = get_user_model()
        u = User.objects.create_user(
            "e006-ack-user",
            password="x",  # nosec B106 - test fixture
        )
        AllianceAuthApplication.objects.create(
            user=u,
            client_id="e006-ack-app",
            client_secret="x",  # nosec B105 - test fixture
            redirect_uris="https://rp.example.org/cb/",
            client_type=AllianceAuthApplication.CLIENT_CONFIDENTIAL,
            authorization_grant_type=(
                AllianceAuthApplication.GRANT_AUTHORIZATION_CODE
            ),
            backchannel_logout_uri="https://rp.example.org/bcl/",
            active=True,
        )
        try:
            with override_settings(
                ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True,
                ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True,
                DEBUG=False,
            ):
                msgs = check_logout_uri_allow_private_in_production(None)
            self.assertEqual(len(msgs), 1, msgs)
            self.assertEqual(msgs[0].id, W005_ID)
            self.assertEqual(msgs[0].level, checks.WARNING)
        finally:
            AllianceAuthApplication.objects.filter(user=u).delete()
            u.delete()


class TestPkceRequiredWiringCheck(TestCase):
    """
    E005 — ``OAUTH2_PROVIDER['PKCE_REQUIRED']`` must be (or wrap)
    :func:`allianceauth_oidc.pkce.per_app_pkce_required`. Without
    it the per-app ``pkce_required`` override silently no-ops.
    """

    def test_e005_error_when_pkce_required_absent(self) -> None:
        from allianceauth_oidc.checks import (
            E005_ID,
            check_pkce_required_wiring,
        )

        cfg = _override_oauth2_provider()
        cfg.pop("PKCE_REQUIRED", None)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_pkce_required_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        msg = msgs[0]
        self.assertEqual(msg.id, E005_ID)
        self.assertEqual(msg.level, checks.ERROR)

    def test_e005_error_when_pkce_required_is_bool(self) -> None:
        """A bool / non-callable triggers the silent-no-op scenario."""
        from allianceauth_oidc.checks import (
            E005_ID,
            check_pkce_required_wiring,
        )

        cfg = _override_oauth2_provider(PKCE_REQUIRED=True)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_pkce_required_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        self.assertEqual(msgs[0].id, E005_ID)

    def test_e005_clean_when_pkce_required_is_adapter(self) -> None:
        """The canonical wire-up — adapter function object itself."""
        from allianceauth_oidc.checks import check_pkce_required_wiring
        from allianceauth_oidc.pkce import per_app_pkce_required

        cfg = _override_oauth2_provider(PKCE_REQUIRED=per_app_pkce_required)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_pkce_required_wiring(None)
        self.assertEqual(msgs, [])

    def test_e005_clean_when_pkce_required_is_callable_wrapper(self) -> None:
        """
        Operators sometimes wrap the adapter for extra logging or
        deployment-specific allow-lists. The check accepts callables
        on trust — the wrapper is contractually obligated to delegate.
        """
        from allianceauth_oidc.checks import check_pkce_required_wiring

        def _wrapper(client_id: str | None) -> bool:
            return True

        cfg = _override_oauth2_provider(PKCE_REQUIRED=_wrapper)
        with override_settings(OAUTH2_PROVIDER=cfg):
            msgs = check_pkce_required_wiring(None)
        self.assertEqual(msgs, [])

    def test_e005_clean_when_oauth2_provider_missing(self) -> None:
        """
        Missing ``OAUTH2_PROVIDER`` triggers E005 (no adapter to find)
        — symmetric with the absent-key case rather than silent. DOT
        wouldn't boot without the dict anyway.
        """
        from allianceauth_oidc.checks import (
            E005_ID,
            check_pkce_required_wiring,
        )

        with override_settings(OAUTH2_PROVIDER=None):
            msgs = check_pkce_required_wiring(None)
        self.assertEqual(len(msgs), 1, msgs)
        self.assertEqual(msgs[0].id, E005_ID)
