"""
Opt-in MariaDB backend for the test suite.

The default test database is sqlite-in-memory (inherited from Alliance
Auth's settings template). This module swaps in a real MariaDB when the
``AA_OIDC_TEST_DB`` gate is set, covering the MySQL-family code paths the
production deployments actually run on (utf8mb4 collation, ``mysql``
backend quoting, online-DDL behaviour).

Two cleanly separated halves so neither pulls a dependency the other
side lacks:

* **settings side** — :func:`apply_mariadb_database_if_enabled` reads the
  ``AA_OIDC_TEST_DB*`` environment and rewrites ``DATABASES`` in place.
  It imports nothing beyond the stdlib, so the off-lock test subprocess
  (which carries ``mysqlclient`` but not ``testcontainers``) can import
  it from ``tests.test_settingsAA4``.
* **session side** — :func:`mariadb_test_env` provisions the connection
  parameters for the ``tests_mariadb`` nox session. When they are already
  in the environment (a CI ``services:`` MariaDB or an operator-supplied
  server) it reuses them and starts nothing; otherwise it spins up a
  throwaway container via ``testcontainers`` (imported lazily, so a
  machine without it / without Docker can still import this module for
  the settings half).

Environment contract (all string-valued):

* ``AA_OIDC_TEST_DB`` — gate; ``"mariadb"`` enables the backend, unset /
  anything else leaves sqlite untouched.
* ``AA_OIDC_TEST_DB_HOST`` / ``_PORT`` / ``_NAME`` / ``_USER`` /
  ``_PASSWORD`` — connection parameters.
* ``AA_OIDC_TEST_DB_IMAGE`` — container image for the local path
  (default ``mariadb:11.4``).
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_GATE_ENV = "AA_OIDC_TEST_DB"
_ENABLED_VALUE = "mariadb"
_SQLITE_ENGINE = "django.db.backends.sqlite3"
_MYSQL_ENGINE = "django.db.backends.mysql"

_DEFAULT_IMAGE = "mariadb:11.4"
_DEFAULT_DBNAME = "oidc"
_DEFAULT_PASSWORD = "oidc"  # nosec B105  # pragma: allowlist secret
_CONTAINER_PORT = 3306

# Django test tag for cases that persist a JWT-format token into DOT's
# ``RefreshToken.token`` column. That column is ``CharField(255)`` with a
# ``unique_together(('token', 'revoked'))`` constraint, so a JWT refresh
# token (> 255 chars) overflows it on MySQL/MariaDB (error 1406) while
# sqlite — being typeless — accepts it. The ``tests_mariadb`` smoke runs
# ``--exclude-tag`` on this until the column is widened. Defined here (a
# Django-free module) so the nox session can import the literal without
# booting Django. TODO(allianceauth-oidc:refresh-token-jwt-mysql): widen
# ``oauth2_provider_refreshtoken.token`` to LONGTEXT and move uniqueness
# onto a fixed-length checksum, then drop this tag and the exclusion.
# See docs/MARIADB.md.
MYSQL_WIDE_REFRESH_TOKEN_TAG = "requires_wide_refresh_token"


def mariadb_enabled() -> bool:
    """Return ``True`` when the ``AA_OIDC_TEST_DB`` gate selects MariaDB."""
    return os.environ.get(_GATE_ENV, "").strip().lower() == _ENABLED_VALUE


def apply_mariadb_database_if_enabled(databases: dict) -> bool:
    """
    Rewrite ``databases['default']`` to MariaDB when the gate is on.

    Returns ``True`` when the swap is applied. When the gate is off it
    leaves ``databases`` untouched and asserts the inherited default is
    sqlite — a guard so a future Alliance Auth settings change that
    silently moved the default off sqlite is caught loudly here rather
    than tests unknowingly running on an unexpected backend.
    """
    if not mariadb_enabled():
        engine = databases.get("default", {}).get("ENGINE", "")
        if engine != _SQLITE_ENGINE:
            raise RuntimeError(
                "expected the inherited default database to be "
                f"{_SQLITE_ENGINE!r} when {_GATE_ENV} is unset, "
                f"got {engine!r}"
            )
        return False

    host = os.environ.get("AA_OIDC_TEST_DB_HOST", "127.0.0.1")
    # mysqlclient routes ``HOST="localhost"`` through a UNIX socket rather
    # than TCP; the container / CI service is only reachable over TCP (and
    # ``testcontainers`` reports its host as ``localhost``), so normalise
    # to the loopback IP to force a TCP connection.
    if host == "localhost":
        host = "127.0.0.1"

    databases["default"] = {
        "ENGINE": _MYSQL_ENGINE,
        "HOST": host,
        "PORT": os.environ.get("AA_OIDC_TEST_DB_PORT", str(_CONTAINER_PORT)),
        "NAME": os.environ.get("AA_OIDC_TEST_DB_NAME", _DEFAULT_DBNAME),
        "USER": os.environ.get("AA_OIDC_TEST_DB_USER", "root"),
        "PASSWORD": os.environ.get(
            "AA_OIDC_TEST_DB_PASSWORD", _DEFAULT_PASSWORD
        ),
        "OPTIONS": {"charset": "utf8mb4"},
        # Django's runner creates ``test_<NAME>`` for the run; pin the
        # charset / collation so the schema matches a production utf8mb4
        # deployment rather than the server's default.
        "TEST": {
            "CHARSET": "utf8mb4",
            "COLLATION": "utf8mb4_unicode_ci",
        },
    }
    return True


def _env_from_environment() -> dict[str, str]:
    """Forward an already-provisioned MariaDB connection as gate env."""
    keys = (
        "AA_OIDC_TEST_DB_HOST",
        "AA_OIDC_TEST_DB_PORT",
        "AA_OIDC_TEST_DB_NAME",
        "AA_OIDC_TEST_DB_USER",
        "AA_OIDC_TEST_DB_PASSWORD",
    )
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env[_GATE_ENV] = _ENABLED_VALUE
    return env


@contextmanager
def mariadb_test_env() -> Iterator[dict[str, str]]:
    """
    Yield ``AA_OIDC_TEST_DB_*`` env for the ``tests_mariadb`` subprocess.

    Reuses connection parameters already present in the environment (a CI
    ``services:`` MariaDB or an external server) and starts nothing;
    otherwise launches a disposable MariaDB via ``testcontainers`` and
    tears it down on exit. ``testcontainers`` is imported lazily so this
    module stays importable on the settings side without it.
    """
    if os.environ.get("AA_OIDC_TEST_DB_HOST"):
        yield _env_from_environment()
        return

    from testcontainers.mysql import MySqlContainer

    image = os.environ.get("AA_OIDC_TEST_DB_IMAGE", _DEFAULT_IMAGE)
    container = MySqlContainer(
        image=image,
        root_password=_DEFAULT_PASSWORD,
        dbname=_DEFAULT_DBNAME,
    )
    with container:
        yield {
            _GATE_ENV: _ENABLED_VALUE,
            "AA_OIDC_TEST_DB_HOST": container.get_container_host_ip(),
            "AA_OIDC_TEST_DB_PORT": str(
                container.get_exposed_port(_CONTAINER_PORT)
            ),
            "AA_OIDC_TEST_DB_NAME": _DEFAULT_DBNAME,
            # Connect as root: Django's runner needs CREATE DATABASE for
            # the ``test_<NAME>`` schema, which the container's regular
            # user is not granted.
            "AA_OIDC_TEST_DB_USER": "root",
            "AA_OIDC_TEST_DB_PASSWORD": _DEFAULT_PASSWORD,
        }
