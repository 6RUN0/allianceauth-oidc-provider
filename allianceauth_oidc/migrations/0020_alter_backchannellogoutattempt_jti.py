"""
Widen ``BackChannelLogoutAttempt.jti`` from 32 to 255 chars.

The column was sized to exactly our own minted jti (``uuid4().hex``,
32 chars) with zero headroom. But the ``oidc_logout_dispatched``
signal contract accepts third-party senders, and a jti per RFC 7519
is an arbitrary string with no length bound — a canonical dashed UUID
is 36 chars, a SHA-256 hex digest is 64. Any such value overflowed the
column on MySQL/MariaDB (error 1406 "Data too long for column 'jti'")
while passing silently on sqlite, which ignores VARCHAR length.

255 matches DOT's string-column convention and covers every realistic
jti format. On MySQL/MariaDB this is a one-time table rebuild (utf8mb4
crosses the 1->2 byte VARCHAR length-prefix boundary at 64 chars), but
the audit table is small and off the hot path. As an ORM ``AlterField``
(not raw ``RunSQL``) it is outside the online-DDL RunSQL gate.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "allianceauth_oidc",
            "0019_issuedcodeaudit_application_client_id_snapshot_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="backchannellogoutattempt",
            name="jti",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                max_length=255,
                verbose_name="JTI",
            ),
        ),
    ]
