"""
``manage.py oidc_fix_idtoken_jti`` — realign DOT's idtoken jti column.

Django 5.x sets ``has_native_uuid_field = True`` for MariaDB >= 10.7, so
every ``UUIDField`` is written in the canonical 36-character dashed form
and its expected column type becomes the native ``uuid`` instead of
``char(32)``. A deployment whose ``oauth2_provider_idtoken.jti`` column
was created under an older stack stays ``char(32)`` and then overflows
on every id_token issuance (``/o/token/``) with
``1406 Data too long for column 'jti'``.

This command is the operator-runnable corrective: on MariaDB >= 10.7 it
converts the column to the native ``uuid`` type Django now expects;
everywhere else (sqlite, PostgreSQL, MySQL, MariaDB < 10.7, or an
already-converted column) it is a no-op. See ``docs/MARIADB.md``.

It is deliberately a management command, not a migration: the table
belongs to ``django-oauth-toolkit`` (not this app, so no clean
``AlterField`` is possible), the corrective is backend-specific, and
only deployments upgraded across the MariaDB 10.7 boundary need it.
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import connections, router
from django.utils.translation import gettext as _
from oauth2_provider.models import get_id_token_model
from typing_extensions import override

from ._format import FORMAT_CHOICES, render_rows

logger = logging.getLogger(f"extensions.{__name__}")

_COLUMNS = ("table", "column", "current_type", "action", "detail")


class Command(BaseCommand):
    """Convert DOT idtoken jti to native uuid on MariaDB >= 10.7."""

    help = _(
        "Realign DOT's idtoken jti column with Django's native-uuid "
        "type on MariaDB >= 10.7 (fixes 1406 on /o/token/)."
    )

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=_("Show the ALTER that would run without executing it."),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    def _emit(self, fmt: str, **row: Any) -> None:
        self.stdout.write(render_rows([row], columns=_COLUMNS, fmt=fmt))

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

    @override
    def handle(self, *args: Any, **options: Any) -> None:
        fmt = options["format"]
        dry_run = options["dry_run"]

        id_token_model = get_id_token_model()
        alias = router.db_for_write(id_token_model) or "default"
        connection = connections[alias]
        table = id_token_model._meta.db_table
        column = id_token_model._meta.get_field("jti").column

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
            self._emit(
                fmt,
                table=table,
                column=column,
                current_type=connection.vendor,
                action="skipped",
                detail="backend has no native UUID type (not MariaDB >= 10.7)",
            )
            return

        current = self._column_data_type(connection, table, column)
        if current is None:
            raise CommandError(f"column {table}.{column} not found")
        if current.lower() == "uuid":
            self._emit(
                fmt,
                table=table,
                column=column,
                current_type=current,
                action="noop",
                detail="already native uuid",
            )
            return

        quote = connection.ops.quote_name
        # Identifiers come from model meta and are quoted via the
        # backend's own quoter; no user input reaches the statement.
        sql = (
            f"ALTER TABLE {quote(table)} MODIFY {quote(column)} UUID NOT NULL"  # nosec B608
        )

        if dry_run:
            self._emit(
                fmt,
                table=table,
                column=column,
                current_type=current,
                action="would_alter",
                detail=sql,
            )
            return

        with connection.cursor() as cursor:
            cursor.execute(sql)

        logger.warning(
            "OIDC fix_idtoken_jti: %s.%s converted %s -> uuid",
            table,
            column,
            current,
        )
        self._emit(
            fmt,
            table=table,
            column=column,
            current_type=current,
            action="altered",
            detail="converted to native uuid",
        )
