"""
Migration tests for the per-app PKCE pair.

- ``0010_alliance_auth_application_pkce_required`` — schema (AddField).
- ``0011_backfill_pkce_required`` — data step that reads
  ``settings.OAUTH2_PROVIDER['PKCE_REQUIRED']`` and overwrites every
  existing row.

The data step honours an explicit ``bool`` value verbatim; any other
shape (callable, ``None``, missing key, non-bool) is ambiguous and
falls back to ``True`` (RFC 9700 secure-by-default) with a
``RuntimeWarning``. Greenfield (no rows) is a documented no-op — no
warning, no row mutation.

Matrix:

- value=``True``  → backfilled to ``True``
- value=``False`` → backfilled to ``False``
- ``OAUTH2_PROVIDER`` empty / missing → backfilled to ``True`` + warning
- value is ``None`` (key present but unset) → backfilled to ``True`` + warning
- value is a callable (operator-supplied resolver) → backfilled to
  ``True`` + warning
- rollback (``0011 → 0009 → 0011``) preserves row count
- clean install (no pre-existing rows) → data step is a no-op, no
  warning emitted, post-migrate row honours the field default (``True``)

``TransactionTestCase`` because schema mutations require committed
transactions; subclasses tear-down by re-running ``migrate`` to the
latest state so other tests in the same worker are not affected.
"""

from __future__ import annotations

import contextlib
import warnings

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

APP_LABEL = "allianceauth_oidc"
MIGRATION_PREVIOUS = "0009_alter_allianceauthapplication_options"
MIGRATION_SCHEMA = "0010_alliance_auth_application_pkce_required"
# ``MIGRATION_TARGET`` tracks the latest migration the suite migrates
# forward to. Tests that ``ObjectManager.create(...)`` rows via the
# LIVE model after migration need the DB schema to match the live
# model — bump this whenever a new migration is added so live-model
# INSERTs see the columns they expect. PKCE-specific assertions
# inside this file still depend on the ``0011`` data step having
# run; that's true for any chain ending at 0011 or beyond.
MIGRATION_TARGET = "0012_allianceauthapplication_access_token_format"


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
    """Row count via the live model (post-0011 schema)."""
    from allianceauth_oidc.models import AllianceAuthApplication

    return AllianceAuthApplication.objects.count()


def _live_apps_pkce_value():
    """Return the set of pkce_required values seen across rows."""
    from allianceauth_oidc.models import AllianceAuthApplication

    return set(
        AllianceAuthApplication.objects.values_list("pkce_required", flat=True)
    )


@contextlib.contextmanager
def _captured_runtime_warnings():
    """Capture RuntimeWarnings raised during ``migrate``."""
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", RuntimeWarning)
        yield captured


def _pkce_warnings(captured):
    """Filter captured warnings down to PKCE_REQUIRED-related ones."""
    return [
        w
        for w in captured
        if issubclass(w.category, RuntimeWarning)
        and "PKCE_REQUIRED" in str(w.message)
    ]


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
        with _captured_runtime_warnings() as captured:
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({False}, _live_apps_pkce_value())
        # Explicit bool is honoured verbatim — no fallback warning.
        self.assertEqual([], _pkce_warnings(captured))


class TestPkceRequiredBackfillTrue(_PkceMigrationBase):
    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": True})
    def test_existing_rows_backfilled_to_true(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-true")
        with _captured_runtime_warnings() as captured:
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({True}, _live_apps_pkce_value())
        self.assertEqual([], _pkce_warnings(captured))


class TestPkceRequiredBackfillEmptyOauth2ProviderFallsBackToTrue(
    _PkceMigrationBase
):
    """
    ``OAUTH2_PROVIDER = {}`` (or with no ``PKCE_REQUIRED`` key) is
    ambiguous: the operator may have not yet wired the new callable
    during the upgrade window, or may have a config-management bug
    that wiped the key. Either way, RFC 9700 secure-by-default wins —
    backfill ``True`` and emit a ``RuntimeWarning`` so the decision
    is visible during ``manage.py migrate``. Operator can flip
    individual apps via Django admin afterwards.
    """

    @override_settings(OAUTH2_PROVIDER={})
    def test_empty_provider_falls_back_to_true_with_warning(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-empty")
        with _captured_runtime_warnings() as captured:
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({True}, _live_apps_pkce_value())
        pkce_warnings = _pkce_warnings(captured)
        self.assertTrue(
            pkce_warnings,
            f"expected RuntimeWarning about PKCE_REQUIRED; got "
            f"{[str(w.message) for w in captured]}",
        )


class TestPkceRequiredBackfillNoneFallsBackToTrue(_PkceMigrationBase):
    """
    ``OAUTH2_PROVIDER['PKCE_REQUIRED'] = None`` is neither ``bool`` nor
    callable. Falls into the secure-by-default fallback and emits a
    warning, alongside the empty-provider / callable / unset cases.
    Pinning this rules out a future regression that re-interprets
    ``None`` as ``False`` via ``bool(None)`` coercion.
    """

    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": None})
    def test_none_falls_back_to_true_secure_by_default(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-none")
        with _captured_runtime_warnings() as captured:
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual({True}, _live_apps_pkce_value())
        self.assertTrue(_pkce_warnings(captured))


class TestPkceRequiredBackfillCallable(_PkceMigrationBase):
    def test_callable_falls_back_to_true_with_warning(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-callable")
        with (
            override_settings(
                OAUTH2_PROVIDER={"PKCE_REQUIRED": lambda cid: False}
            ),
            _captured_runtime_warnings() as captured,
        ):
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        pkce_warnings = _pkce_warnings(captured)
        self.assertTrue(
            pkce_warnings,
            f"expected RuntimeWarning about PKCE_REQUIRED; got "
            f"{[str(w.message) for w in captured]}",
        )
        self.assertIn("function", str(pkce_warnings[0].message))
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
        # Re-apply the schema + data steps and reverify.
        _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual(3, _live_apps_count())


class TestPkceRequiredCleanInstall(_PkceMigrationBase):
    """
    Greenfield: migrate runs on a database with no pre-existing
    AllianceAuthApplication rows.

    The data step's early-return matches no rows — a documented
    no-op. The recommended-greenfield case (callable PKCE_REQUIRED
    already in place per the install snippet) must NOT emit the
    ``RuntimeWarning``; that warning is reserved for the upgrade
    path where existing rows would be backfilled. Apps created
    post-migrate via the live model use ``BooleanField(default=True)``
    (RFC 9700 secure-by-default) regardless of the global setting,
    which only governs the backfill — not the field default.
    """

    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": lambda cid: True})
    def test_no_rows_no_warning_no_error(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        with _captured_runtime_warnings() as captured:
            _migrate_to([(APP_LABEL, MIGRATION_TARGET)])
        self.assertEqual(0, _live_apps_count())
        self.assertEqual(
            [],
            _pkce_warnings(captured),
            "greenfield migrate must not emit PKCE warnings",
        )

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


class TestPkceSchemaWithoutDataStep(_PkceMigrationBase):
    """
    Apply only the schema migration (``0010``) — the column should
    exist with the field default ``True``, even before the data step
    has had a chance to overwrite from the global setting. This
    exercises the architectural split: schema is reversible and
    independent from environment-dependent backfill.
    """

    @override_settings(OAUTH2_PROVIDER={"PKCE_REQUIRED": False})
    def test_schema_only_leaves_existing_rows_at_field_default_true(self):
        _migrate_to([(APP_LABEL, MIGRATION_PREVIOUS)])
        _create_legacy_app(name="legacy-schema-only")
        # Forward to the schema step, NOT the data step.
        _migrate_to([(APP_LABEL, MIGRATION_SCHEMA)])
        # AddField with default=True backfills existing rows to True at
        # schema migration time, which is exactly what the field default
        # promises. Reverse-direction tests live in
        # TestPkceRequiredRollbackPreservesRowCount.
        self.assertEqual({True}, _live_apps_pkce_value())
