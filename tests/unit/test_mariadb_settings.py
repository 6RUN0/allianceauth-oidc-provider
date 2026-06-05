"""
Unit tests for the opt-in MariaDB settings swap.

Pin the gate contract of ``apply_mariadb_database_if_enabled`` without a
container or a booted Django: with the gate off it must leave sqlite
untouched (and reject a non-sqlite inherited default), and with the gate
on it must build a ``mysql`` ``DATABASES['default']`` from the
``AA_OIDC_TEST_DB_*`` environment.

ORM-free unit tier: imports only the stdlib-only settings half of
``tests._mariadb_container`` (no ``testcontainers``), so the canary that
sweeps ``tests/unit/`` can import it everywhere.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from tests._mariadb_container import (
    apply_mariadb_database_if_enabled,
    mariadb_enabled,
)


def _sqlite_databases() -> dict:
    """Return a minimal sqlite ``DATABASES`` like AA's inherited default."""
    return {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    }


class ApplyMariadbDatabaseTests(unittest.TestCase):
    """Branch coverage for the gate's on / off / guard behaviour."""

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_gate_off_keeps_sqlite_and_returns_false(self) -> None:
        databases = _sqlite_databases()
        self.assertFalse(mariadb_enabled())
        self.assertFalse(apply_mariadb_database_if_enabled(databases))
        self.assertEqual(
            databases["default"]["ENGINE"], "django.db.backends.sqlite3"
        )

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_gate_off_rejects_non_sqlite_default(self) -> None:
        databases = {"default": {"ENGINE": "django.db.backends.postgresql"}}
        with self.assertRaises(RuntimeError):
            apply_mariadb_database_if_enabled(databases)

    @mock.patch.dict(
        os.environ,
        {
            "AA_OIDC_TEST_DB": "mariadb",
            "AA_OIDC_TEST_DB_HOST": "db.example",
            "AA_OIDC_TEST_DB_PORT": "3307",
            "AA_OIDC_TEST_DB_NAME": "oidc",
            "AA_OIDC_TEST_DB_USER": "root",
            "AA_OIDC_TEST_DB_PASSWORD": "secret",  # pragma: allowlist secret
        },
        clear=True,
    )
    def test_gate_on_builds_mysql_from_env(self) -> None:
        databases = _sqlite_databases()
        self.assertTrue(apply_mariadb_database_if_enabled(databases))
        default = databases["default"]
        self.assertEqual(default["ENGINE"], "django.db.backends.mysql")
        self.assertEqual(default["HOST"], "db.example")
        self.assertEqual(default["PORT"], "3307")
        self.assertEqual(default["USER"], "root")
        self.assertEqual(default["PASSWORD"], "secret")
        self.assertEqual(default["OPTIONS"]["charset"], "utf8mb4")
        self.assertEqual(default["TEST"]["COLLATION"], "utf8mb4_unicode_ci")

    @mock.patch.dict(
        os.environ,
        {"AA_OIDC_TEST_DB": "mariadb", "AA_OIDC_TEST_DB_HOST": "localhost"},
        clear=True,
    )
    def test_localhost_host_coerced_to_tcp_ip(self) -> None:
        # ``HOST="localhost"`` makes mysqlclient use a UNIX socket; the
        # container / service is TCP-only, so it must become 127.0.0.1.
        databases = _sqlite_databases()
        self.assertTrue(apply_mariadb_database_if_enabled(databases))
        self.assertEqual(databases["default"]["HOST"], "127.0.0.1")

    @mock.patch.dict(os.environ, {"AA_OIDC_TEST_DB": "mariadb"}, clear=True)
    def test_gate_on_falls_back_to_defaults(self) -> None:
        databases = _sqlite_databases()
        self.assertTrue(apply_mariadb_database_if_enabled(databases))
        default = databases["default"]
        self.assertEqual(default["ENGINE"], "django.db.backends.mysql")
        self.assertEqual(default["HOST"], "127.0.0.1")
        self.assertEqual(default["PORT"], "3306")
        self.assertEqual(default["USER"], "root")
