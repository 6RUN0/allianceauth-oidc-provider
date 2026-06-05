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
