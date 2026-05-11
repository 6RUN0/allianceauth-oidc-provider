"""
Create ``BackChannelLogoutAttempt`` — the BCL dead-letter audit table.

One row per terminal ``oidc_logout_dispatched`` event. Records the
application FK, the user PK (plain int, not FK — the ``user_deleted``
trigger fires after the row is removed), the spec-defined ``jti``,
the success flag, the Celery attempt number, the stable reason
string, and a creation timestamp.

Two composite indexes support the two common admin scans:
``(application, -created_at)`` for per-RP timelines and
``(success, -created_at)`` for failure-only dashboards.

The default audit receiver records only failures; operators who want
full positive-path correlation can flip
``ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True``.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("allianceauth_oidc", "0014_backchannel_logout_on_revoke_only"),
    ]

    operations = [
        migrations.CreateModel(
            name="BackChannelLogoutAttempt",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "user_pk",
                    models.PositiveIntegerField(
                        blank=True,
                        db_index=True,
                        help_text=(
                            "Integer primary key of the user whose "
                            "session was being terminated. Not a "
                            "ForeignKey because the ``user_deleted`` "
                            "trigger fires after the row is removed."
                        ),
                        null=True,
                        verbose_name="User PK",
                    ),
                ),
                (
                    "jti",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        default="",
                        max_length=32,
                        verbose_name="JTI",
                    ),
                ),
                (
                    "success",
                    models.BooleanField(
                        db_index=True,
                        verbose_name="Success",
                    ),
                ),
                (
                    "attempt_count",
                    models.PositiveSmallIntegerField(
                        default=1,
                        help_text=(
                            "1-based attempt number from the Celery "
                            "task (1 = first try). Dispatcher-side "
                            "failures (broker_unavailable, "
                            "signing_kid_resolve_failed) record 0 "
                            "because no HTTP attempt was made."
                        ),
                        verbose_name="Attempt count",
                    ),
                ),
                (
                    "reason",
                    models.CharField(
                        blank=True,
                        db_index=True,
                        default="",
                        help_text=(
                            "Stable string identifying the dispatch "
                            "outcome: trigger reason "
                            "(user_revoked/...) on success, or "
                            "failure mode (redirect_blocked, "
                            "rp_client_error, retries_exhausted, "
                            "signing_kid_retired, broker_unavailable, "
                            "signing_kid_resolve_failed) on failure."
                        ),
                        max_length=64,
                        verbose_name="Reason",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        auto_now_add=True,
                        db_index=True,
                        verbose_name="Created at",
                    ),
                ),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="backchannel_logout_attempts",
                        to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                        verbose_name="Application",
                    ),
                ),
            ],
            options={
                "verbose_name": "Back-Channel Logout attempt",
                "verbose_name_plural": "Back-Channel Logout attempts",
                "ordering": ("-created_at",),
                "indexes": [
                    models.Index(
                        fields=["application", "-created_at"],
                        name="allianceaut_applica_7756e5_idx",
                    ),
                    models.Index(
                        fields=["success", "-created_at"],
                        name="allianceaut_success_2d01c4_idx",
                    ),
                ],
            },
        ),
    ]
