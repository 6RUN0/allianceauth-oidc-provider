"""
Add ``backchannel_logout_uri`` to ``AllianceAuthApplication``.

OIDC Back-Channel Logout 1.0 §2.4: RP endpoint receiving signed
``logout_token`` POSTs. Empty string keeps BCL disabled for the row,
so the field is non-null with a blank default — no data migration is
required for existing applications.
"""

from django.core.validators import URLValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "allianceauth_oidc",
            "0012_allianceauthapplication_access_token_format",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="allianceauthapplication",
            name="backchannel_logout_uri",
            field=models.URLField(
                blank=True,
                default="",
                help_text=(
                    "RP endpoint that accepts back-channel logout_token POSTs "
                    "(OIDC Back-Channel Logout 1.0). Leave blank to disable. "
                    "https:// required unless DEBUG is on; host must resolve "
                    "to a public IP."
                ),
                max_length=1024,
                validators=[URLValidator(schemes=["http", "https"])],
                verbose_name="Back-channel logout URI",
            ),
        ),
    ]
