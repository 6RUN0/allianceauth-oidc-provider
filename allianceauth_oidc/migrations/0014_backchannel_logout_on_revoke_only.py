"""
Add ``backchannel_logout_on_revoke_only`` to ``AllianceAuthApplication``.

Per-app opt-in narrowing the BCL fan-out to the explicit
``oidc_revoke_user_tokens`` command (reason=``user_revoked``). When
True, the four lifecycle reasons
(``user_deactivated`` / ``groups_changed`` / ``state_changed`` /
``user_deleted``) are silently skipped in
``logout.dispatch_backchannel_logout``. Default ``False`` so existing
v1 deployments keep their fan-out behaviour after this migration
runs.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "allianceauth_oidc",
            "0013_backchannel_logout_uri",
        ),
    ]

    operations = [
        migrations.AddField(
            model_name="allianceauthapplication",
            name="backchannel_logout_on_revoke_only",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "When checked, this RP receives a back-channel "
                    "logout_token ONLY when an operator runs "
                    "oidc_revoke_user_tokens. Lifecycle events "
                    "(deactivation, group/state changes, account "
                    "deletion) will NOT fan out to this RP. "
                    "Default is unchecked (all five triggers fire)."
                ),
                verbose_name=("Back-Channel Logout: explicit revoke only"),
            ),
        ),
    ]
