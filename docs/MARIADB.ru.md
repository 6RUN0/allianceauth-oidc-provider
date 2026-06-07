# Тестовый бэкенд MariaDB / MySQL

По умолчанию набор тестов гоняется на sqlite-in-memory, но боевые
развёртывания Alliance Auth работают на MySQL/MariaDB. Nox-сессия
`tests_mariadb` прогоняет тесты против реальной MariaDB, чтобы кодовые
пути семейства MySQL (коллация utf8mb4, кавычки бэкенда `mysql`,
контроль длины, поведение online-DDL) тоже проверялись, а не только
бестиповый sqlite.

## Как запустить

```sh
# Локально: одноразовая MariaDB поднимается через testcontainers (нужен Docker).
uv run nox -s "tests_mariadb(aa5)"      # интерпретатор из locked-стека, AA 5.x
uv run nox -s "tests_mariadb(aa4)"      # ячейка AA 4.x

# Против уже запущенного сервера (CI-сервис или ваша собственная MariaDB):
AA_OIDC_TEST_DB=mariadb \
AA_OIDC_TEST_DB_HOST=127.0.0.1 AA_OIDC_TEST_DB_PORT=3306 \
AA_OIDC_TEST_DB_NAME=oidc AA_OIDC_TEST_DB_USER=root \
AA_OIDC_TEST_DB_PASSWORD=oidc \
uv run nox -s "tests_mariadb(aa5)"
```

Сессия чисто пропускается, если нет ни Docker, ни
`AA_OIDC_TEST_DB_HOST`, поэтому она никогда не блокирует машину без БД.

## Контракт окружения

Подмена настроек живёт в `tests/_mariadb_container.py`
(`apply_mariadb_database_if_enabled`, подключается из
`tests/test_settingsAA4`). Все значения — строки:

| Переменная | Смысл |
|----------|---------|
| `AA_OIDC_TEST_DB` | Гейт. `mariadb` включает бэкенд; не задана — остаётся sqlite. |
| `AA_OIDC_TEST_DB_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD` | Параметры подключения. |
| `AA_OIDC_TEST_DB_IMAGE` | Образ контейнера для локального пути (по умолчанию `mariadb:11.4`). |

При незаданном гейте подмена — это no-op, который ассертит, что
унаследованный дефолт всё ещё sqlite, поэтому она не может молча
сменить бэкенд. `HOST=localhost` нормализуется в `127.0.0.1`, потому
что `mysqlclient` гоняет `localhost` через UNIX-сокет, а не TCP.

`mysqlclient` (драйвер БД) собирается из sdist против заголовков
libmariadb / libmysqlclient; CI ставит `default-libmysqlclient-dev`
перед `uv sync`.

## Известное ограничение: JWT refresh-токены на MySQL

Smoke-прогон `tests_mariadb` запускается с
`--exclude-tag=requires_wide_refresh_token`, и JWT-кейсы, выпускающие
**refresh**-токен в формате JWT, помечены этим тегом. Причина:

- `RefreshToken.token` из `django-oauth-toolkit` — это
  `CharField(max_length=255)` с ограничением
  `unique_together(('token', 'revoked'))`.
- JWT refresh-токен превышает 255 символов, поэтому MySQL/MariaDB
  отвергает вставку с ошибкой 1406 (`Data too long for column 'token'`).
  sqlite, будучи бестиповым, принимает её — именно поэтому набор так
  долго проходил на sqlite. `AccessToken.token` уже `TextField` в
  апстриме и не затронут.

Это латентное ограничение для развёртываний MySQL/MariaDB, выпускающих
JWT refresh-токены. Расширение колонки — не однострочная правка:
`unique_together` по `token` означает, что колонку `TEXT`/`LONGTEXT`
нельзя проиндексировать без префикса, а префиксный индекс не может
гарантировать уникальность по полному значению. Правильный фикс
переносит гарантию уникальности на колонку фиксированной длины с
контрольной суммой и расширяет `token` до `LONGTEXT`.

Отслеживается как `TODO(allianceauth-oidc:refresh-token-jwt-mysql)` в
`tests/_mariadb_container.py`. До тех пор smoke исключает помеченные
кейсы; они всё равно гоняются на sqlite-наборе.

## Заметка оператору: нативные UUID-колонки на MariaDB >= 10.7

Django 5.x определяет нативный тип `uuid` у MariaDB (MariaDB >= 10.7) и
выставляет `has_native_uuid_field = True`. С этого момента каждый
`UUIDField` пишется в каноничной 36-символьной форме с дефисами
(например, `a4995e86-529d-402c-a247-fc329e47b293`), и тип его колонки
становится нативным `uuid` вместо `char(32)`.

`oauth2_provider_idtoken.jti` из `django-oauth-toolkit` — это
`UUIDField`. На развёртывании, чья схема была создана под старым стеком
(MariaDB < 10.7 либо версия Django/DOT, рендерившая `UUIDField` как
`char(32)`), эта колонка остаётся `char(32)`. После того как базу позже
обновят до MariaDB >= 10.7, Django начинает слать 36-символьное
значение в 32-символьную колонку, и **каждая выдача id_token падает на
`/o/token/`** с:

```text
MySQLdb.DataError: (1406, "Data too long for column 'jti' at row 1")
```

Это рассогласование схемы и бэкенда, а не баг приложения или логики
DOT: колонка не последовала за бэкендом через апгрейд MariaDB. Свежая
схема к этому невосприимчива, потому что миграция создаёт колонку под
запущенный бэкенд (`uuid` на >= 10.7) — поэтому же smoke-прогон
`tests_mariadb` (образ по умолчанию `mariadb:11.4`) этого не ловит.

Диагностика — подтвердите feature-флаг бэкенда в Django shell:

```python
from django.db import connection
connection.mysql_version                   # (10, 7, ...) или выше
connection.features.has_native_uuid_field  # True
```

Фикс (оператор, разовый). Таблица принадлежит DOT, поэтому это
приложение не везёт под неё миграцию; корректив — management-команда:

```sh
# Показать ALTER, не трогая базу.
python manage.py oidc_fix_idtoken_jti --dry-run

# Применить. No-op на sqlite / PostgreSQL / MySQL / MariaDB < 10.7
# либо уже сконвертированной колонке — так что запускать можно безусловно.
python manage.py oidc_fix_idtoken_jti
```

Команда выполняет эквивалент SQL ниже, который можно применить и
вручную:

```sql
-- Привести колонку к типу, который Django теперь ожидает.
ALTER TABLE oauth2_provider_idtoken MODIFY jti UUID;
```

id_token'ы короткоживущие, так что конвертация существующих строк
малорискованна; если предпочитаете чистый каст, сначала выполните
`DELETE FROM oauth2_provider_idtoken;` (клиенты просто переаутентифи-
цируются). Менее рискованный текстовый шим — `MODIFY jti VARCHAR(36)`,
но миграционное состояние Django всё равно ожидает `uuid`, поэтому
нативный тип — более чистое выравнивание. То же рассогласование может
задеть любую колонку `UUIDField`, созданную до апгрейда на
MariaDB >= 10.7.

Системная проверка Django `allianceauth_oidc.W006` (помечена как
database, поэтому выполняется на `migrate` / `check --database`) ловит
ровно это рассогласование на этапе деплоя и указывает оператору на
`oidc_fix_idtoken_jti`.
