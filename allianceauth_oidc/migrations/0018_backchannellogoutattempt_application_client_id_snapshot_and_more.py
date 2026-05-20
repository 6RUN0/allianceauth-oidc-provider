"""
C-3: BCL audit FK ``on_delete=SET_NULL`` + snapshot columns.

Pre-C-3 the ``application`` FK cascaded — deleting an
``AllianceAuthApplication`` row also wiped every
``BackChannelLogoutAttempt`` row referencing it, contradicting the
``user_pk`` model docstring's promise of "historically faithful
audit log even when the originating entity no longer exists" and
silently destroying the dead-letter context operators most need
when removing a buggy or compromised RP.

This migration:

* Adds two snapshot columns (``application_client_id_snapshot`` /
  ``application_name_snapshot``) populated from the live FK
  target on new inserts (see ``receivers.record_backchannel_logout_attempt``).
* Backfills the snapshots for existing rows from their (still
  alive) ``application`` FK target so per-RP forensic queries
  continue to work after a subsequent app delete.
* Switches the FK to ``on_delete=SET_NULL`` so future RP deletions
  preserve the audit row.
"""

from __future__ import annotations

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def _backfill_snapshots(apps, schema_editor):
    """Copy live FK ``client_id`` / ``name`` into snapshot columns."""
    BackChannelLogoutAttempt = apps.get_model(
        "allianceauth_oidc", "BackChannelLogoutAttempt"
    )
    for row in BackChannelLogoutAttempt.objects.select_related(
        "application"
    ).iterator():
        app_row = row.application
        if app_row is None:
            continue
        row.application_client_id_snapshot = (
            getattr(app_row, "client_id", "") or ""
        )[:100]
        row.application_name_snapshot = (getattr(app_row, "name", "") or "")[
            :255
        ]
        row.save(
            update_fields=[
                "application_client_id_snapshot",
                "application_name_snapshot",
            ]
        )


def _drop_snapshots(apps, schema_editor):
    """Reverse no-op — column drop is handled by the AlterField reversal."""
    return


class Migration(migrations.Migration):
    dependencies = [
        ("allianceauth_oidc", "0017_issuedcodeaudit"),
    ]

    operations = [
        migrations.AddField(
            model_name="backchannellogoutattempt",
            name="application_client_id_snapshot",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Snapshot of the application's client_id at row-insert "
                    "time. Survives RP deletion (FK becomes NULL) so "
                    "per-RP forensic queries still work for historical "
                    "events."
                ),
                max_length=100,
                verbose_name="Application client_id snapshot",
            ),
        ),
        migrations.AddField(
            model_name="backchannellogoutattempt",
            name="application_name_snapshot",
            field=models.CharField(
                blank=True,
                default="",
                help_text=(
                    "Snapshot of the application's name at row-insert time."
                ),
                max_length=255,
                verbose_name="Application name snapshot",
            ),
        ),
        migrations.RunPython(_backfill_snapshots, _drop_snapshots),
        migrations.AlterField(
            model_name="backchannellogoutattempt",
            name="application",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="backchannel_logout_attempts",
                to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                verbose_name="Application",
            ),
        ),
    ]
