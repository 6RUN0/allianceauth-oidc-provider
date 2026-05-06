"""
Per-app PKCE column with backfill from global setting.

This migration is environment-dependent: the data step reads
``settings.OAUTH2_PROVIDER['PKCE_REQUIRED']`` at run time and writes
that value to every existing ``AllianceAuthApplication`` row. Replaying
this migration on a freshly-cloned dev DB with a different operator's
``local.py`` produces a different post-migration state — that's
intentional. For brownfield deploys with live OAuth clients of unknown
PKCE support, the run-time-read is the only way to preserve behaviour
across the upgrade.

Robustness:
- ``OAUTH2_PROVIDER`` may be entirely unset on minimal installs;
  use ``getattr(settings, 'OAUTH2_PROVIDER', {}) or {}``.
- The ``PKCE_REQUIRED`` value may already be a callable in the
  operator's ``local.py``; calling it per-row would cascade
  operator-defined logic into the migration, and ``bool(callable)`` is
  silently ``True`` which would strict-flip every row. Detect this case
  and fall back to ``True`` (RFC 9700 secure-by-default), with a stderr
  warning so the operator sees it during ``manage.py migrate``.
"""

import sys

from django.conf import settings
from django.db import migrations, models


def _backfill_pkce_required(apps, schema_editor):
    """Backfill from the global setting at deploy time."""
    App = apps.get_model("allianceauth_oidc", "AllianceAuthApplication")
    provider = getattr(settings, "OAUTH2_PROVIDER", {}) or {}
    raw = provider.get("PKCE_REQUIRED", False)
    if callable(raw):
        sys.stderr.write(
            "WARNING: OAUTH2_PROVIDER['PKCE_REQUIRED'] is callable; "
            "backfilling pkce_required=True (RFC 9700 "
            "secure-by-default). Re-evaluate per-app via Django admin "
            "if your custom resolver disagrees.\n"
        )
        value = True
    else:
        value = bool(raw)
    App.objects.update(pkce_required=value)


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
        migrations.RunPython(
            _backfill_pkce_required,
            migrations.RunPython.noop,
            elidable=False,
        ),
    ]
