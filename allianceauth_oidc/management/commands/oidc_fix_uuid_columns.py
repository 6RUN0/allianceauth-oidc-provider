"""
``manage.py oidc_fix_uuid_columns`` — realign DOT's native-uuid columns.

Django 5.x sets ``has_native_uuid_field = True`` for MariaDB >= 10.7, so
every ``UUIDField`` is written in the canonical 36-character dashed form
and its expected column type becomes the native ``uuid`` instead of
``char(32)``. A deployment whose DOT UUID columns were created under an
older stack stay ``char(32)`` and then overflow with ``1406 Data too
long``. Two columns are affected: ``oauth2_provider_idtoken.jti``
(id_token issuance on ``/o/token/``) and
``oauth2_provider_refreshtoken.token_family`` (refresh-token rotation).

This command is the operator-runnable corrective: on MariaDB >= 10.7 it
converts each column to the native ``uuid`` type Django now expects,
preserving the column's nullability; everywhere else (sqlite,
PostgreSQL, MySQL, MariaDB < 10.7, or an already-converted column) it is
a no-op. See ``docs/MARIADB.md``.

It is deliberately a management command, not a migration: the tables
belong to ``django-oauth-toolkit`` (not this app, so no clean
``AlterField`` is possible), the corrective is backend-specific, and
only deployments upgraded across the MariaDB 10.7 boundary need it.
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connections, router
from django.utils.translation import gettext as _
from typing_extensions import override

from ._format import FORMAT_CHOICES, render_rows

logger = logging.getLogger(f"extensions.{__name__}")

_COLUMNS = ("table", "column", "current_type", "action", "detail")

# DOT ``UUIDField`` columns Django writes in the native 36-char form on
# MariaDB >= 10.7, each of which overflows a legacy ``char(32)`` column
# with error 1406. ``(model-getter name, field name)``. Nullability is
# read off the model field at runtime so the emitted ALTER preserves it
# (``jti`` is NOT NULL, ``token_family`` is nullable). Mirrors
# ``_NATIVE_UUID_TARGETS`` in ``allianceauth_oidc.checks`` (W006).
NATIVE_UUID_TARGETS: tuple[tuple[str, str], ...] = (
    ("get_id_token_model", "jti"),
    ("get_refresh_token_model", "token_family"),
)


class Command(BaseCommand):
    """Convert DOT's UUIDField columns to native uuid on MariaDB >= 10.7."""

    help = _(
        "Realign DOT's UUIDField columns (idtoken.jti, "
        "refreshtoken.token_family) with Django's native-uuid type on "
        "MariaDB >= 10.7 (fixes 1406 'Data too long')."
    )

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=_("Show the ALTERs that would run without executing them."),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    @staticmethod
    def _column_data_type(
        connection: Any, table: str, column: str
    ) -> str | None:
        """Return information_schema ``DATA_TYPE`` for the column, or None."""
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT DATA_TYPE FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s "
                "AND COLUMN_NAME = %s",
                [table, column],
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def _fix_one(
        self, getter_name: str, field_name: str, *, dry_run: bool
    ) -> dict[str, Any]:
        """Diagnose (and on a native backend, convert) a single column."""
        import oauth2_provider.models as dot_models

        model = getattr(dot_models, getter_name)()
        connection = connections[router.db_for_write(model) or "default"]
        table = model._meta.db_table
        field = model._meta.get_field(field_name)
        column = field.column

        # Only MariaDB >= 10.7 advertises a native uuid type, which is
        # what makes a legacy char(32) column overflow. Every other
        # backend already stores the 32-char hex form and is consistent.
        mysql_version = getattr(connection, "mysql_version", None)
        native_uuid_backend = (
            connection.vendor == "mysql"
            and getattr(connection, "mysql_is_mariadb", False)
            and mysql_version is not None
            and mysql_version >= (10, 7)
        )
        if not native_uuid_backend:
            return {
                "table": table,
                "column": column,
                "current_type": connection.vendor,
                "action": "skipped",
                "detail": "backend has no native UUID type "
                "(not MariaDB >= 10.7)",
            }

        current = self._column_data_type(connection, table, column)
        if current is None:
            raise CommandError(f"column {table}.{column} not found")
        if current.lower() == "uuid":
            return {
                "table": table,
                "column": column,
                "current_type": current,
                "action": "noop",
                "detail": "already native uuid",
            }

        # Preserve the field's nullability: jti is NOT NULL, token_family
        # is nullable. Reusing a hard-coded NOT NULL would reject existing
        # NULL token_family rows.
        null_sql = "NULL" if field.null else "NOT NULL"
        quote = connection.ops.quote_name
        # Identifiers come from model meta and are quoted via the
        # backend's own quoter; no user input reaches the statement.
        sql = (
            f"ALTER TABLE {quote(table)} "  # nosec B608
            f"MODIFY {quote(column)} UUID {null_sql}"
        )

        if dry_run:
            return {
                "table": table,
                "column": column,
                "current_type": current,
                "action": "would_alter",
                "detail": sql,
            }

        with connection.cursor() as cursor:
            cursor.execute(sql)

        logger.warning(
            "OIDC fix_uuid_columns: %s.%s converted %s -> uuid",
            table,
            column,
            current,
        )
        return {
            "table": table,
            "column": column,
            "current_type": current,
            "action": "altered",
            "detail": "converted to native uuid",
        }

    @override
    def handle(self, *args: Any, **options: Any) -> None:
        fmt = options["format"]
        dry_run = options["dry_run"]

        rows = [
            self._fix_one(getter_name, field_name, dry_run=dry_run)
            for getter_name, field_name in NATIVE_UUID_TARGETS
        ]
        self.stdout.write(render_rows(rows, columns=_COLUMNS, fmt=fmt))
