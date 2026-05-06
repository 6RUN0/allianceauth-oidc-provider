"""
Migration tests for ``0010_alliance_auth_application_pkce_required``.

The data step reads ``settings.OAUTH2_PROVIDER['PKCE_REQUIRED']`` at
run time and backfills every existing row. These tests cover the
matrix:

- value=``True``  → backfilled to ``True``
- value=``False`` → backfilled to ``False``
- ``OAUTH2_PROVIDER`` empty / missing → backfilled to ``False``
- value is a callable (``operator-supplied resolver``) → fall back to
  ``True`` and emit a stderr warning
- rollback (``0010 → 0009 → 0010``) preserves row count
- clean install (no pre-existing rows) → data step is a no-op and a
  post-migrate row honours the field default (``True``)

``TransactionTestCase`` because schema mutations require committed
transactions; subclasses tear-down by re-running ``migrate`` to the
latest state so other tests in the same worker are not affected.
"""

from __future__ import annotations

import contextlib
import io
from unittest import mock

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

APP_LABEL = "allianceauth_oidc"
MIGRATION_PREVIOUS = "0009_alter_allianceauthapplication_options"
MIGRATION_TARGET = "0010_alliance_auth_application_pkce_required"


def _migrate_to(target):
    """
    Drive a forward / backward migration via ``MigrationExecutor``.

    ``target`` is a list of ``(app_label, name)`` tuples, matching
    ``MigrationExecutor.migrate``'s contract.
    """
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(target)


def _create_legacy_app(*, name: str = "legacy"):
    """
    Insert an Application row at the historical (pre-0010) schema.

    Uses ``apps.get_model`` so the call resolves the model class
    without the ``pkce_required`` field, mirroring an old deployment
    being upgraded.
    """
    executor = MigrationExecutor(connection)
    historical = executor.loader.project_state(
        [(APP_LABEL, MIGRATION_PREVIOUS)]
    ).apps
    App = historical.get_model(APP_LABEL, "AllianceAuthApplication")
    return App.objects.create(
        name=name,
        client_id=f"cid-{name}",
        client_secret="secret",  # nosec B106 - test fixture
        client_type="confidential",
        authorization_grant_type="authorization-code",
        redirect_uris="http://localhost/redir/",
        skip_authorization=False,
    )


def _live_apps_count():
    """Row count via the live model (post-0010 schema)."""
    from allianceauth_oidc.models import AllianceAuthApplication

    return AllianceAuthApplication.objects.count()


def _live_apps_pkce_value():
    """Return the set of pkce_required values seen across rows."""
    from allianceauth_oidc.models import AllianceAuthApplication

    return set(
        AllianceAuthApplication.objects.values_list("pkce_required", flat=True)
    )


class _PkceMigrationBase(TransactionTestCase):
    """Common teardown that resolves the schema back to the latest state."""

    def tearDown(self):
        super().tearDown()
        # Restore latest state so subsequent tests in the same worker
        # do not see a partially-rolled-back schema.
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])


class TestPkceRequiredBackfillFalse(_PkceMigrationBase):
    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": False})
    def test_existing_rows_backfilled_to_false(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-false")
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({False}, _live_apps_pkce_value())


class TestPkceRequiredBackfillTrue(_PkceMigrationBase):
    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": True})
    def test_existing_rows_backfilled_to_true(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-true")
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({True}, _live_apps_pkce_value())


class TestPkceRequiredBackfillEmptyOauth2Provider(_PkceMigrationBase):
    @override_settings(OAUTH2_PROVIDER={})
    def test_empty_oauth2_provider_backfills_to_false(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-empty")
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({False}, _live_apps_pkce_value())


class TestPkceRequiredBackfillCallable(_PkceMigrationBase):
    def test_callable_falls_back_to_true_with_stderr_warning(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-callable")
        captured = io.StringIO()
        with (
            override_settings(
                OAUTH2_PROVIDER={"PKCE_REQUIRED": lambda cid: False}
            ),
            contextlib.redirect_stderr(captured),
        ):
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        warning_text = captured.getvalue()
        if "PKCE_REQUIRED'] is callable" not in warning_text:
            # Some test runners rebind sys.stderr per worker, defeating
            # contextlib.redirect_stderr. Fall back to a direct patch
            # of sys.stderr — the assertion below is the same.
            _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
            replacement = io.StringIO()
            with (
                override_settings(
                    OAUTH2_PROVIDER={"PKCE_REQUIRED": lambda cid: False}
                ),
                mock.patch("sys.stderr", new=replacement),
            ):
                _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
            warning_text = replacement.getvalue()
        self.assertIn("PKCE_REQUIRED'] is callable", warning_text)
        self.assertEqual({True}, _live_apps_pkce_value())


class TestPkceRequiredRollbackPreservesRowCount(_PkceMigrationBase):
    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": True})
    def test_round_trip_preserves_count(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        for i in range(3):
            _create_legacy_app(name=f"legacy-roundtrip-{i}")
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual(3, _live_apps_count())
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        # After downgrade the column is gone, but row count survives.
        # Re-apply 0010 and reverify.
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual(3, _live_apps_count())


class TestPkceRequiredCleanInstall(_PkceMigrationBase):
    """
    Greenfield: migrate runs on a database with no pre-existing
    AllianceAuthApplication rows.

    The data step's ``update()`` matches no rows — a documented
    no-op. The recommended-greenfield case (a boolean global) must
    not emit the stderr warning; that warning is reserved for the
    callable-detected branch. Apps created post-migrate via the live
    model use ``BooleanField(default=True)`` (RFC 9700 secure-by-
    default) regardless of the global setting, which only governs
    the backfill — not the field default.
    """

    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": False})
    def test_no_rows_no_warning_no_error(self):
        captured = io.StringIO()
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        with contextlib.redirect_stderr(captured):
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual(0, _live_apps_count())
        self.assertNotIn("is callable", captured.getvalue())

    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": False})
    def test_post_migrate_row_uses_field_default_true(self):
        from allianceauth_oidc.models import AllianceAuthApplication

        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        # Row created via the LIVE model after the schema migration.
        # The global ``False`` only affected the (empty) backfill;
        # the field default is the binding contract here.
        app = AllianceAuthApplication.objects.create(
            name="greenfield",
            client_id="cid-greenfield",
            client_secret="secret",  # nosec B106 - test fixture
            client_type="confidential",
            authorization_grant_type="authorization-code",
            redirect_uris="http://localhost/redir/",
            skip_authorization=False,
        )
        self.assertTrue(app.pkce_required)
