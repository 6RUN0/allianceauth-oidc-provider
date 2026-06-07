# MariaDB / MySQL test backend

The suite defaults to sqlite-in-memory, but Alliance Auth deployments run
on MySQL/MariaDB. The `tests_mariadb` nox session runs the suite against a
real MariaDB so the MySQL-family code paths (utf8mb4 collation, the
`mysql` backend's quoting, length enforcement, online-DDL behaviour) are
exercised, not just the typeless sqlite ones.

## Running it

```sh
# Local: a throwaway MariaDB is started via testcontainers (needs Docker).
uv run nox -s "tests_mariadb(aa5)"      # locked-stack interpreter, AA 5.x
uv run nox -s "tests_mariadb(aa4)"      # AA 4.x cell

# Against an already-running server (CI service, or your own MariaDB):
AA_OIDC_TEST_DB=mariadb \
AA_OIDC_TEST_DB_HOST=127.0.0.1 AA_OIDC_TEST_DB_PORT=3306 \
AA_OIDC_TEST_DB_NAME=oidc AA_OIDC_TEST_DB_USER=root \
AA_OIDC_TEST_DB_PASSWORD=oidc \
uv run nox -s "tests_mariadb(aa5)"
```

The session skips cleanly when neither Docker nor `AA_OIDC_TEST_DB_HOST`
is available, so it never blocks a machine without a database.

## Environment contract

The settings swap lives in `tests/_mariadb_container.py`
(`apply_mariadb_database_if_enabled`, wired from `tests/test_settingsAA4`).
All values are strings:

| Variable | Meaning |
|----------|---------|
| `AA_OIDC_TEST_DB` | Gate. `mariadb` enables the backend; unset leaves sqlite. |
| `AA_OIDC_TEST_DB_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD` | Connection parameters. |
| `AA_OIDC_TEST_DB_IMAGE` | Container image for the local path (default `mariadb:11.4`). |

With the gate unset the swap is a no-op that asserts the inherited
default is still sqlite, so it can never silently change the backend.
`HOST=localhost` is normalised to `127.0.0.1` because `mysqlclient`
routes `localhost` through a UNIX socket rather than TCP.

`mysqlclient` (the DB driver) builds from sdist against the
libmariadb / libmysqlclient headers; CI installs
`default-libmysqlclient-dev` before `uv sync`.

## Known limitation: JWT refresh tokens on MySQL

The `tests_mariadb` smoke runs `--exclude-tag=requires_wide_refresh_token`
and the JWT cases that issue a JWT-format **refresh** token carry that
tag. The reason:

- `django-oauth-toolkit`'s `RefreshToken.token` is `CharField(max_length=255)`
  with a `unique_together(('token', 'revoked'))` constraint.
- A JWT refresh token exceeds 255 characters, so MySQL/MariaDB rejects the
  insert with error 1406 (`Data too long for column 'token'`). sqlite,
  being typeless, accepts it — which is why the suite passed on sqlite for
  so long. `AccessToken.token` is already `TextField` upstream and is
  unaffected.

This is a latent limitation for MySQL/MariaDB deployments that issue JWT
refresh tokens. Widening the column is not a one-line change: the
`unique_together` on `token` means a `TEXT`/`LONGTEXT` column cannot be
indexed without a prefix, and a prefix index cannot guarantee full-value
uniqueness. The proper fix moves the uniqueness guarantee onto a
fixed-length checksum column and widens `token` to `LONGTEXT`.

Tracked as `TODO(allianceauth-oidc:refresh-token-jwt-mysql)` in
`tests/_mariadb_container.py`. Until then the smoke excludes the tagged
cases; they still run on the sqlite suite.

## Operator note: native UUID columns on MariaDB >= 10.7

Django 5.x detects MariaDB's native `uuid` type (MariaDB >= 10.7) and
sets `has_native_uuid_field = True`. From then on every `UUIDField` is
written in the canonical 36-character dashed form (for example
`a4995e86-529d-402c-a247-fc329e47b293`), and its column type becomes the
native `uuid` instead of `char(32)`.

`django-oauth-toolkit`'s `oauth2_provider_idtoken.jti` is a `UUIDField`.
On a deployment whose schema was created under an older stack (MariaDB
< 10.7, or a Django/DOT version that rendered `UUIDField` as `char(32)`),
that column stays `char(32)`. After the database is later upgraded to
MariaDB >= 10.7, Django starts sending the 36-character value into the
32-character column and **every id_token issuance fails on `/o/token/`**
with:

```text
MySQLdb.DataError: (1406, "Data too long for column 'jti' at row 1")
```

This is a schema/backend mismatch, not an application or DOT-logic bug:
the column did not follow the backend across the MariaDB upgrade. A fresh
schema is immune, because the migration creates the column to match the
running backend (`uuid` on >= 10.7) — which is also why the
`tests_mariadb` smoke (default image `mariadb:11.4`) does not catch it.

Diagnose by confirming the backend feature flag in a Django shell:

```python
from django.db import connection
connection.mysql_version                   # (10, 7, ...) or higher
connection.features.has_native_uuid_field  # True
```

Fix (operator, one-off). DOT owns the table, so this app ships no
migration for it; the corrective is a management command instead:

```sh
# Preview the ALTER without touching the database.
python manage.py oidc_fix_idtoken_jti --dry-run

# Apply it. No-op on sqlite / PostgreSQL / MySQL / MariaDB < 10.7
# or an already-converted column, so it is safe to run unconditionally.
python manage.py oidc_fix_idtoken_jti
```

The command runs the equivalent of the SQL below, which you can also
apply by hand:

```sql
-- Align the column with the type Django now expects.
ALTER TABLE oauth2_provider_idtoken MODIFY jti UUID;
```

id_tokens are short-lived, so converting existing rows is low-risk; run
`DELETE FROM oauth2_provider_idtoken;` first if you prefer a clean cast
(clients simply re-authenticate). A lower-risk text shim is
`MODIFY jti VARCHAR(36)`, but Django's migration state still expects
`uuid`, so the native type is the cleaner alignment. The same mismatch
can hit any `UUIDField` column created before the MariaDB >= 10.7
upgrade.

The Django system check `allianceauth_oidc.W006` (database-tagged, so
it runs at `migrate` / `check --database`) flags this exact mismatch at
deploy time, pointing the operator at `oidc_fix_idtoken_jti`.
