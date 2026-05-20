"""
Settings shim for the ``django-migration-linter`` nox step.

Inherits the full test stack from ``test_settingsAA4`` and adds
``django_migration_linter`` to ``INSTALLED_APPS`` so its
``lintmigrations`` management command is discoverable. Kept separate
so the main test settings stay free of a tool that is only invoked
once per ``migrations_check`` session.

``MIGRATION_LINTER_OPTIONS`` pins ten migrations that pre-date the
linter's introduction: they have already been applied by every
deployment, editing migration history would break operators. The
gate therefore catches issues only in migrations newer than the
baseline (``0020`` onward).
"""

from tests.test_settingsAA4 import *  # noqa: F403

INSTALLED_APPS += ["django_migration_linter"]  # type: ignore[name-defined]  # noqa: F405

# Baseline: migrations with linter findings as of 2026-05-20. All
# already applied in production; cannot be edited. Use --ignore-name
# rather than --exclude-apps so a future allianceauth_oidc migration
# is still gated.
MIGRATION_LINTER_OPTIONS = {
    "ignore_name": [
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
    ],
}
