"""
C-4: IssuedCodeAudit FK ``on_delete=SET_NULL`` + client_id snapshot.

Symmetric to migration 0018 for BackChannelLogoutAttempt. Pre-C-4
the ``application`` FK cascaded, so admin-driven RP deletion wiped
every ``IssuedCodeAudit`` row referencing it — including
``reuse_count>=1`` rows that the model docstring explicitly
promises to preserve as forensic evidence. This migration switches
the FK to ``SET_NULL`` and adds a snapshot column so per-RP
forensic queries continue to work after the FK is gone.

The auto-cleanup task (``tasks.clear_expired_tokens``) is
unaffected — it already filters by ``reuse_count`` and time, not by
FK reachability.
"""

from __future__ import annotations

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def _backfill_snapshots(apps, schema_editor):
    """Copy live FK ``client_id`` into snapshot column on existing rows."""
    IssuedCodeAudit = apps.get_model("allianceauth_oidc", "IssuedCodeAudit")
    for row in IssuedCodeAudit.objects.select_related(
        "application"
    ).iterator():
        app_row = row.application
        if app_row is None:
            continue
        row.application_client_id_snapshot = (
            getattr(app_row, "client_id", "") or ""
        )[:100]
        row.save(update_fields=["application_client_id_snapshot"])


def _drop_snapshots(apps, schema_editor):
    """Reverse no-op."""
    return


class Migration(migrations.Migration):
    dependencies = [
        (
            "allianceauth_oidc",
            "0018_backchannellogoutattempt_application_client_id_snapshot_and_more",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="issuedcodeaudit",
            name="application_client_id_snapshot",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Snapshot of the application's client_id at row-insert "
                    "time. Survives RP deletion (FK becomes NULL) so "
                    "per-RP forensic queries still work for ``reuse_count"
                    ">=1`` rows after the originating app is gone."
                ),
                max_length=100,
                verbose_name="Application client_id snapshot",
            ),
        ),
        migrations.RunPython(_backfill_snapshots, _drop_snapshots),
        migrations.AlterField(
            model_name="issuedcodeaudit",
            name="application",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                verbose_name="Application",
            ),
        ),
    ]
