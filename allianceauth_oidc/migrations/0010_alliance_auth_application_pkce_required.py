"""
Add the ``pkce_required`` boolean column to AllianceAuthApplication.

Schema-only. The companion data migration
``0011_backfill_pkce_required`` reads
``OAUTH2_PROVIDER['PKCE_REQUIRED']`` and overwrites existing rows from
the global setting. Splitting them keeps schema operations cleanly
reversible and independent from the environment-dependent backfill.

The field default is ``True`` per RFC 9700 secure-by-default — for
post-migrate row creation (admin / ``oidc_create_app``). Pre-existing
rows get ``True`` from this ``AddField`` step and are then overwritten
by the data step in ``0011``; the boolean / non-boolean cases there
preserve behaviour vs. fail-safe respectively.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("allianceauth_oidc", "0009_alter_allianceauthapplication_options"),
    ]

    operations = [
        migrations.AddField(
            model_name="allianceauthapplication",
            name="pkce_required",
            field=models.BooleanField(
                default=True,
                help_text=(
                    "If enabled, this application must use PKCE on the "
                    "authorization endpoint (RFC 7636 / 9700). Disable "
                    "only for known-incompatible clients; new "
                    "applications default to enabled."
                ),
                verbose_name="PKCE required",
            ),
        ),
    ]
