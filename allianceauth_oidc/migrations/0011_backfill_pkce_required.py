"""
Backfill ``pkce_required`` from the global setting at deploy time.

This migration is environment-dependent: the data step reads
``settings.OAUTH2_PROVIDER['PKCE_REQUIRED']`` at run time and writes
that value to every existing ``AllianceAuthApplication`` row. Replaying
this migration on a freshly-cloned dev DB with a different operator's
``local.py`` produces a different post-migration state — that's
intentional. For brownfield deploys with live OAuth clients of unknown
PKCE support, the run-time-read is the only way to preserve behaviour
across the upgrade.

Robustness:
- Greenfield (no rows) is a documented no-op — early return skips both
  the global-setting read and the warning so a fresh install does not
  emit operator noise.
- Only an explicit ``bool`` value (``True`` / ``False``) is honoured
  verbatim. Any other shape (callable, ``None``, missing key, ``str``,
  ``int``, …) is ambiguous and falls back to ``True`` (RFC 9700
  secure-by-default) with a ``RuntimeWarning`` so operators see the
  decision during ``manage.py migrate``. The strictness is intentional:
  ``bool("false") == True`` and similar coercions silently flip the
  meaning — refusing to coerce surfaces config drift instead of
  acting on it.
"""

import warnings

from django.conf import settings
from django.db import migrations


def _backfill_pkce_required(apps, schema_editor):
    """Backfill from the global setting at deploy time."""
    App = apps.get_model("allianceauth_oidc", "AllianceAuthApplication")
    # Greenfield: no rows to backfill. Skip the global-setting read so a
    # ``OAUTH2_PROVIDER`` with the new callable in place does not emit
    # an irrelevant RuntimeWarning during the very first ``migrate``.
    if not App.objects.exists():
        return
    provider = getattr(settings, "OAUTH2_PROVIDER", {}) or {}
    raw = provider.get("PKCE_REQUIRED")
    if isinstance(raw, bool):
        value = raw
    else:
        kind = type(raw).__name__
        warnings.warn(
            f"OAUTH2_PROVIDER['PKCE_REQUIRED'] is {kind} (expected "
            "bool); backfilling pkce_required=True (RFC 9700 "
            "secure-by-default). Re-evaluate per-app via Django admin "
            "if your resolver disagrees.",
            RuntimeWarning,
            stacklevel=2,
        )
        value = True
    App.objects.update(pkce_required=value)


class Migration(migrations.Migration):
    dependencies = [
        ("allianceauth_oidc", "0010_alliance_auth_application_pkce_required"),
    ]

    operations = [
        migrations.RunPython(
            _backfill_pkce_required,
            migrations.RunPython.noop,
            elidable=False,
        ),
    ]
