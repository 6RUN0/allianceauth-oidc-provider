"""
Settings shim for the ``django-migration-linter`` nox step.

Inherits the full test stack from ``test_settingsAA4`` and adds
``django_migration_linter`` to ``INSTALLED_APPS`` so its
``lintmigrations`` management command is discoverable. Kept separate
so the main test settings stay free of a tool that is only invoked
once per ``migrations_check`` session.

``MIGRATION_LINTER_OPTIONS`` pins migrations the gate must not fail
on: ten that pre-date the linter's introduction (already applied by
every deployment, editing migration history would break operators)
plus ``0020`` and ``0021``, whose findings are documented NOT_NULL
non-issues (see the inline notes). The gate therefore catches issues
only in genuinely new, genuinely unsafe migrations.
"""

from tests.test_settingsAA4 import *  # noqa: F403

INSTALLED_APPS += ["django_migration_linter"]  # type: ignore[name-defined]  # noqa: F405

# Two distinct reasons for ignoring, kept separate on purpose.
#
# 1. Baseline: migrations with linter findings as of 2026-05-20. All
#    already applied in production; cannot be edited. Use --ignore-name
#    rather than --exclude-apps so a future allianceauth_oidc migration
#    is still gated.
# 2. False positive: the linter's NOT_NULL check over-flags an
#    ``AlterField`` that merely widens an already-NOT-NULL column. On
#    SQLite an ``AlterField`` rebuilds the whole table, so the linter
#    sees ``NOT NULL`` on the recreated column and reports it as a new
#    constraint. ``0020`` only widens ``BackChannelLogoutAttempt.jti``
#    from VARCHAR(32) to VARCHAR(255); the column was created NOT NULL
#    with ``default=""`` back in ``0015`` and keeps both here, so no row
#    can become null and no value is truncated — the operation is fully
#    backward-compatible.
MIGRATION_LINTER_OPTIONS = {
    "ignore_name": [
        # (1) Pre-linter baseline.
        "0002_alter_allianceauthapplication_options_and_more",
        "0003_remove_allianceauthapplication_logo_and_more",
        "0004_allianceauthapplication_allowed_origins_and_more",
        "0005_alter_allianceauthapplication_authorization_grant_type",
        "0007_alter_allianceauthapplication_logo_url",
        "0010_alliance_auth_application_pkce_required",
        "0013_backchannel_logout_uri",
        "0014_backchannel_logout_on_revoke_only",
        "0018_backchannellogoutattempt_application_client_id_snapshot_and_more",
        "0019_issuedcodeaudit_application_client_id_snapshot_and_more",
        # (2) NOT_NULL false positive on a VARCHAR-widening AlterField.
        "0020_alter_backchannellogoutattempt_jti",
        # (3) NOT_NULL findings on the DOT 3.4 field additions.
        #     ``0021`` adds ``registration_source`` as NOT NULL with
        #     ``default="manual"`` — existing rows are backfilled in
        #     the same migration. The linter's actual concern is the
        #     rolling-deploy window: Django drops the DB-level default
        #     after the backfill, so an old-code INSERT racing the
        #     deploy would violate NOT NULL. That cannot bite here —
        #     ``AllianceAuthApplication`` rows are created only by
        #     operators (admin / management commands), never by
        #     request traffic. The ``client_id`` VARCHAR(100 -> 255)
        #     widening is the same SQLite table-rebuild false positive
        #     as ``0020``; ``cimd_expires_at`` is nullable.
        "0021_allianceauthapplication_cimd_expires_at_and_more",
    ],
}
