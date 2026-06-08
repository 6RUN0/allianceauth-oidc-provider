# История изменений

В этом файле — значимые правки в форке.

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версионирование —
[Semantic Versioning](https://semver.org/lang/ru/spec/v2.0.0.html). Пока проект в диапазоне 0.x.y,
минорные версии могут содержать ломающие изменения.

Журнал относится к форку
[6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider). История
апстрима
([Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider))
сохранена в `git log`; здесь — только то, что добавилось в форке.

## [Unreleased]

## [0.4.0] - 2026-06-08

### Добавлено

- Защитная сетка для нативного `uuid` на MariaDB `>= 10.7` под колонку
  `jti` idtoken'а из DOT. Django 5.x считает MariaDB `>= 10.7`
  носителем нативного типа `uuid` и пишет значения `UUIDField` в
  36-символьной форме с дефисами; колонка `oauth2_provider_idtoken.jti`,
  оставшаяся в legacy-`char(32)` после апгрейда через границу 10.7,
  затем переполняется и валит каждую выдачу id_token на `/o/token/` с
  `1406 Data too long for column 'jti'`. Это закрывают две новые
  поверхности: системная проверка `allianceauth_oidc.W006` (помечена
  как database) ловит рассогласование на `manage.py check --database` /
  `migrate`, а команда `manage.py oidc_fix_idtoken_jti` конвертирует
  колонку к нативному типу `uuid` (no-op на всех остальных бэкендах /
  уже сконвертированной колонке; понимает `--dry-run` / `--format`).
  Таблица принадлежит DOT, поэтому корректив поставляется командой, а не
  миграцией. Руководство оператора:
  [docs/MARIADB.md](docs/MARIADB.ru.md).

### Исправлено

- Страница подтверждения RP-initiated logout снова рендерится. Override
  `logout_confirm.html` лежал в `templates/allianceauth_oidc/`, но
  `RPInitiatedLogoutView` из DOT грузит
  `oauth2_provider/logout_confirm.html`, поэтому override никогда не
  рендерился и страница откатывалась к нестилизованному дефолту DOT.
  Шаблон перенесён в `templates/oauth2_provider/`, чтобы перекрывать
  копию DOT, и теперь наследует `allianceauth/base-bs5.html` — страница
  logout'а совпадает с оболочкой Alliance Auth. Заодно шаблоны
  `authorize.html` / `denied.html` переведены на классы Bootstrap 5.
  Новый `tests/test_templates_render.py` прогоняет каждый шаблон через
  его view, страхуя от молчаливой поломки override'ов.
- `BackChannelLogoutAttempt.jti` расширен с `char(32)` до `varchar(255)`
  (миграция `0020`). Колонка была размечена ровно под наш собственный
  jti (`uuid4().hex`, 32 символа), но сигнал `oidc_logout_dispatched`
  принимает сторонних отправителей, а jti по RFC 7519 — произвольная
  строка (каноничный UUID с дефисами — 36 символов, hex-дайджест
  SHA-256 — 64). Любое более длинное значение переполняло audit-колонку
  на MySQL/MariaDB с ошибкой 1406, молча проходя на sqlite. 255
  соответствует строковой колоночной конвенции DOT и покрывает все
  реалистичные форматы jti.
- Issuer в таблице эндпоинтов README исправлен с `https://your.host/o/`
  на `https://your.host/o` (без хвостового слэша). Без `OIDC_ISS_ENDPOINT`
  DOT выводит issuer, отрезая `/.well-known/openid-configuration` от
  discovery-URL, поэтому слэш префикса монтирования уходит вместе с
  суффиксом, и каноничный `iss` остаётся без хвостового слэша. RP сверяют
  `iss` с полем `issuer` из discovery байт-в-байт, так что слэш имел
  значение. Новые регрессионные тесты в `tests/test_discovery.py` это
  фиксируют: у discovery `issuer` нет хвостового слэша, `iss` в id_token
  равен `issuer` из discovery, а выведенный из запроса issuer (без
  `OIDC_ISS_ENDPOINT`) резолвится в префикс монтирования без его слэша.

### Инструментарий

- `Makefile` теперь генерируется из таблицы `TARGETS` в
  `_nox/makefile.py`, а не редактируется руками. Новые nox-сессии
  `makefile` / `makefile_check` пересобирают его и проверяют на дрейф;
  гейт `makefile_check` подключён в `preflight`, pre-commit и CI и
  следит, что закоммиченный файл совпадает с рендером, у каждой
  nox-сессии есть `make`-таргет, и ни один таргет не ссылается на
  исчезнувшую сессию.
- Новые nox-сессия `tests_mariadb` и CI-задача прогоняют набор против
  реальной MariaDB (локально через testcontainers, в CI — через
  service-контейнер), чтобы покрывались кодовые пути семейства MySQL, а
  не только бестиповый sqlite. Чисто пропускается, когда недоступны ни
  Docker, ни база. Руководство: [docs/MARIADB.md](docs/MARIADB.ru.md).
- Новые pre-commit-гейты: `pygrep-hooks` (отклоняет опечатки в
  Mock-методах, `logger.warn`, `eval()`, U+FFFD и сплошной
  `type: ignore`), `name-tests-test` и `djlint` (lint/format
  Django-шаблонов).
- Новый nox/CI-гейт `migrations_concurrency_check` сканирует миграции с
  сырым `RunSQL` на блокирующий (non-online) DDL для MySQL/MariaDB.
- Новый nox/CI-гейт `messages_check` проверяет целостность каталогов
  `.po` / `.pot` / `.mo`, не требуя полноты переводов.
- Кросс-версионный прогон AA 5.x (`tests_matrix`) теперь строит свой
  argv через чистый, покрытый юнит-тестами помощник в `_nox/matrix.py`.

## [0.3.2] - 2026-06-05

С `0.3.1` нет изменений wire-протокола и поведения в рантайме; при
обновлении действий со стороны оператора не требуется. Единственная
правка кода — фикс совместимости с `django-oauth-toolkit` 3.3 (только
состояние модели, без миграции схемы).

### Исправлено

- Совместимость с `django-oauth-toolkit` 3.3. DOT 3.3 переработал
  `help_text` унаследованного поля `client_secret` на абстрактном
  `AbstractApplication`; поскольку это поле материализовано в миграцию
  `0001` приложения, `makemigrations --check` начинал ругаться под DOT
  3.3 (ловится тестом `test_makemigrations_check_dry_run_clean` на
  off-lock матрице AA4). Теперь `AllianceAuthApplication` переобъявляет
  `client_secret` с атрибутами, повторяющими замороженное состояние
  `0001`, пиннингуя модель так, что `makemigrations --check` остаётся
  чистым на всём поддерживаемом диапазоне (`>=3.2,<4`). Изменение только
  в метаданных — без миграции схемы и без эффекта на базу.

### Документация

- Закрыты 14 расхождений README и кода, найденных в ревью двумя
  критиками. Операторам не хватало всего слоя Prometheus, двух из пяти
  audit-сигналов и dead-letter-таблицы — всё это уже поставлялось, но не
  было задокументировано. Теперь описаны: extra `[metrics]` и девять
  метрик `aa_oidc_*` (со ссылкой на `docs/METRICS{,.ru}.md`), окно
  ротации `OIDC_RSA_PRIVATE_KEYS_INACTIVE`, все пять audit-сигналов с
  именами получателей по умолчанию (было три) и dead-letter-таблица
  `BackChannelLogoutAttempt`. Три настройки BCL / приватной сети
  перенесены в основную таблицу настроек, `/o/authorized_tokens/`
  добавлен в таблицу эндпоинтов, а `README.ru.md` приведён к паритету
  (`logo_url`, `backchannel_logout_uri`,
  `backchannel_logout_on_revoke_only`).

### Инструментарий

- CI: задача `pip-audit` теперь выполняет `actions/checkout` перед
  локальным composite-шагом `./.github/actions/setup`. Ссылки на
  локальные action'ы разрешаются по файлам, уже выложенным на runner, —
  без checkout'а runner не находил `action.yml` и задача падала.
- Dev: подключён MCP-сервер code-intelligence `codegraph` через
  `.mcp.json` (его каталог индекса `.codegraph/` добавлен в gitignore) и
  задокументирован рабочий процесс MCP `codegraph` / `agentmemory` в
  `CLAUDE.md`.

## [0.3.0] - 2026-05-21 [YANKED]

Тэгнут, но не опубликован на PyPI. Release-pipeline race'нулся с
`main.yml` на первом запуске после добавления cross-workflow CI
gate (коммит `663c22f`). Git-тэг `v0.3.0` остался на репозитории
и не может быть удалён (защита тэгов), но артефакт на PyPI не
загружен.

Ставьте `0.3.1` — она содержит идентичный функциональный payload,
перетэгнутый после фикса gate'а (коммит `6407535`,
`ci(release): bounded polling instead of single-shot CI gate`).

## [0.3.1] - 2026-05-21

> ⚠️ **Изменение поведения, видимое оператору**: OIDC RP-Initiated
> Logout теперь включён по умолчанию.
> `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` принимает
> значение `True` через AppConfig; маршрут `/o/logout/` и поле
> `end_session_endpoint` в discovery становятся активны без явного
> opt-in. Чтобы вернуть прежнее (upstream DOT) поведение, задайте
> ключу `False` в настройках — `setdefault` сохраняет любое явное
> значение. См. новый warning `manage.py check`
> `allianceauth_oidc.W003`, если вы выключаете RP-init logout при
> наличии зарегистрированных back-channel logout RP.

### Безопасность

- Усиление защиты от SSRF в BCL. Три независимых гейта защищают
  исходящий `requests.post` worker'а от TOCTOU при DNS rebinding и
  bypass'ов на небезопасные адреса:
  (1) admin-form валидатор в `clean()`,
  (2) новый `pre_save` сигнал, закрывающий обход через
  `Application.objects.create(...)` / fixtures / data-миграции,
  которые пропускают `full_clean()`,
  (3) новый helper `_request_time_ssrf_gate_passes`, который
  переразрешает host прямо перед `requests.post` и fail-close'ит на
  транзиентных ошибках резолвера (audit
  `reason="dns_resolve_failed"` / `"unsafe_target_ip"`).
  Общий предикат `_is_unsafe_address` теперь распаковывает
  IPv4-in-IPv6 (`::ffff:...`) и 6to4 (`2002:...`) до проверок и
  добавляет `is_unspecified` к набору отказа — закрыты обходы
  `0.0.0.0`, `::` и 6to4-обёрнутые приватные IPv4, которые
  пропускала исходная цепочка из пяти предикатов.

- BCL fan-out пропускает деактивированные приложения.
  `Application.active=False` задокументирован как kill-switch для
  скомпрометированных/выведенных из эксплуатации клиентов; раньше
  фильтрация шла по токенам, но не по Application, и
  деактивированный RP продолжал получать подписанные `logout_token`
  POST'ы (с `sub`/`iss`/`aud`/`jti`) на каждое lifecycle-событие.
  `logout.apps_with_active_tokens` теперь добавляет `active=True`,
  и `dispatch_backchannel_logout` short-circuit'ит через
  `application.is_usable(None)` рядом с существующим blank-URI
  гейтом.

- В `auth_provider._enforce_policy` добавлена пропущенная ветка
  `case _: assert_never(decision)` в match'е по `AccessDecision`.
  Без неё четвёртый вариант union'а в будущем привёл бы к падению
  функции в конец без `return`, возврату `None`, который oauthlib
  трактует как falsy в callsite'ах `validate_code` /
  `validate_refresh_token` — c исходящим `invalid_grant` вместо
  громкого `TypeError` от `assert_never`. Симметрично существующему
  паттерну в `views_authorize.AuthAuthorizationView.dispatch`.

### Добавлено

- OIDC Back-Channel Logout 1.0 (sub-only v1). Установите
  `backchannel_logout_uri` у application, чтобы зарегистрировать RP
  для fan-out; пять trigger-сайтов (revoke-команда, `User.is_active`
  flip, изменение groups/state, удаление аккаунта) эмитят
  `oidc_logout_required`, и Celery-task POST-ит подписанный
  `logout_token` каждому зарегистрированному RP. SSRF-защита:
  allow-list для scheme, проверка host-DNS через per-call
  `concurrent.futures.ThreadPoolExecutor` (3 s wall-clock, защищает
  от no-op-ловушки `setdefaulttimeout`), отказ для
  private/loopback/link-local/multicast/reserved/unspecified IP с
  распаковкой IPv4-в-IPv6 и 6to4 и dev escape hatch
  `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE`. Дисциплина
  исходящих HTTP: `allow_redirects=False`, тело не читается,
  ограниченный `timeout=(5, 10)`. Retry — байт-в-байт (worker
  пересобирает JWT против закреплённых `(jti, iat, signing_kid)`).
  Discovery эмитит `backchannel_logout_supported: true`;
  `backchannel_logout_session_supported` намеренно отсутствует
  (sub-only v1). Per-app флаг
  `AllianceAuthApplication.backchannel_logout_on_revoke_only`
  ограничивает RP получением logout-токенов только при явном вызове
  `oidc_revoke_user_tokens`. Руководство оператора:
  [docs/BACK_CHANNEL_LOGOUT.ru.md](docs/BACK_CHANNEL_LOGOUT.ru.md).

- JWT access-токены (RFC 9068). Включается двумя ключами в
  `OAUTH2_PROVIDER`: `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT =
  "jwt"` И `ACCESS_TOKEN_GENERATOR =
  "allianceauth_oidc.tokens.dispatching_access_token_generator"`. Per-app
  override через `AllianceAuthApplication.access_token_format`
  (`"opaque"` / `"jwt"` / пусто). Default остаётся `"opaque"` —
  обновление никого не ломает. Токены по-прежнему stateful: JWT
  хранится в `oauth2_provider_accesstoken.token`, поэтому introspect,
  revoke и audit-сигнал `oidc_token_issued` продолжают работать; в
  body audit-сигнала добавилось поле `format`. Identity-claim'ы идут
  через канонический хук DOT `get_oidc_claims`, AT и id_token дают
  идентичный набор claim'ов для одного и того же набора scope. Новая
  настраиваемая защита от перерастания токена
  `ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` (по умолчанию `4096`) пишет
  `WARNING` при превышении, не меняя выпуск. Discovery-документ
  публикует `access_token_signing_alg_values_supported: ["RS256"]`.
  Руководство оператора:
  [docs/JWT_ACCESS_TOKENS.ru.md](docs/JWT_ACCESS_TOKENS.ru.md) —
  включение, RP cookbook (oauth2-proxy / mod_auth_openidc / WikiJS),
  ротация ключей, data minimization, откат.

- OIDC RP-Initiated Logout 1.0 (`/o/logout/`) включён по умолчанию
  через AppConfig-хук `AllianceAuthOIDC.ready`. Discovery публикует
  `end_session_endpoint`; маршрут — `RPInitiatedLogoutView` из
  `oauth2_provider`, поведение гейтится DOT внутри. Оператор
  сохраняет полный контроль через
  `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` —
  `setdefault` уважает любое явное значение (в том числе `False` для
  opt-out).

- Одиннадцать новых Django system check на `manage.py check` —
  шесть errors, пять warnings, все в пространстве
  `allianceauth_oidc.*`:
  - `E001` (Error) — `backchannel_logout_uri` зарегистрирован без
    `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` (у Celery-worker'а нет
    HTTP-запроса, чтобы вывести `iss`).
  - `E002` (Error) — `OAUTH2_PROVIDER_APPLICATION_MODEL` не
    указывает на `AllianceAuthApplication`. Stock-модель DOT
    обходит трёхуровневый policy enforcement.
  - `E003` (Error) — `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`
    не указывает на `AllianceAuthOAuth2Validator`. Stock-валидатор
    DOT пропускает слои 2 и 3 policy-гейта.
  - `E004` (Error) — `OAUTH2_PROVIDER['SCOPES']` не содержит
    scope `openid`. Дефолтный `{"read": ..., "write": ...}` от
    DOT молча отключает выпуск id_token.
  - `E005` (Error) — `OAUTH2_PROVIDER['PKCE_REQUIRED']` не
    является (или не оборачивает)
    `allianceauth_oidc.pkce.per_app_pkce_required`. Без адаптера
    per-app override молча no-op'ит, оставляя публичных клиентов
    уязвимыми к перехвату authorization code по RFC 9700.
  - `E006` (Error) — опасная тройная комбинация имеет реальную
    жертву: `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` И
    `DEBUG=False` И как минимум один зарегистрированный
    `backchannel_logout_uri`. Подавляется явным opt-in
    `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True`.
  - `W001` (Warning) — `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True`
    при `DEBUG=False`. Masked-fragment logging — инструмент для
    разработки; в продакшене утекают узнаваемые фрагменты
    токенов и секретов в хранилище логов.
  - `W002` (Warning) — JWT-режим включён наполовину: default
    формат `jwt` без dispatching `ACCESS_TOKEN_GENERATOR`, или
    генератор подключён без выставленного `jwt` дефолта. Обе
    половинки должны быть выставлены, чтобы JWT стал глобальным
    дефолтом.
  - `W003` (Warning) — `OIDC_RP_INITIATED_LOGOUT_ENABLED=False`
    при наличии приложений с `backchannel_logout_uri`. Single-
    Logout chain рвётся на первом hop'е, потому что RP-init logout
    endpoint — точка входа, которая триггерит BCL fan-out.
  - `W004` (Warning) — активное приложение хранит
    `backchannel_logout_uri` со схемой `http://` при `DEBUG=False`.
    Legacy-строки, сохранённые под `DEBUG=True`, переживают
    переключение; worker перепроверяет DNS, но не схему.
  - `W005` (Warning) —
    `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` при
    `DEBUG=False` без зарегистрированного
    `backchannel_logout_uri` (иначе срабатывает `E006`). SSRF-гейт
    на BCL-целях отключён.

- Сигнал аудита `oidc_token_introspected` для RFC 7662 introspect
  endpoint. Срабатывает на каждый вызов `/o/introspect/` с
  TypedDict-телом `OIDCIntrospectionAuditBody`
  (`introspector`, `token_sha256`, `active`, `client_id`).
  SIEM/audit-форвардеры подключают свой receiver — receiver по
  умолчанию логирует на INFO с redact'ом секретов.

- Сигнал аудита `oidc_code_reuse_detected` + модель
  `IssuedCodeAudit`, реализующая reuse-detection из RFC 6749 §10.5.
  DOT 3.2 удаляет `Grant` row при первом обмене; новая боковая
  таблица сохраняет связь code-hash → токены за пределами времени
  жизни `Grant`, поэтому reuse триггерит ревокацию связанных access
  и refresh токенов, а не только `invalid_grant`. Хранится как
  `sha256(code)`; raw code никогда не персистится.

- `manage.py oidc_show_effective_policy` — операторская инспекция
  per-app whitelist'а state/group'ов в том виде, в котором он
  оценивается против пользователя, с учётом глобального гейта.
  Полезно, когда пользователь сообщает о неожиданном
  `invalid_grant`, и нужно узнать, какой layer отказал.

- `manage.py oidc_revoke_user_tokens --reason TEXT` —
  опциональная произвольная audit-строка, попадающая в body
  ревокации `oidc_token_issued` и в trigger BCL fan-out.

- `manage.py oidc_jwks_rotate` — операторская команда для ротации
  ключа подписи JWKS. Генерирует свежий RSA-ключ, выводит из
  активного оборота текущий ключ (строки, закреплённые за старым
  `signing_kid`, продолжают давать байт-в-байт идентичные ретраи
  до своего истечения), обновляет JWKS endpoint. Принимает
  `--dry-run` для предпросмотра без персиста.

- Admin: bulk-action "Send test back-channel logout" в changelist'е
  `AllianceAuthApplication`. Эмитит `oidc_logout_required` с
  `reason="admin_test"` на no-op пользователя — прогоняет полный
  путь dispatcher → Celery → RP HTTP для операторской валидации без
  влияния на реальные сессии.

- Защита от clickjacking на `/o/authorize/`. Ответ теперь несёт
  `X-Frame-Options: DENY` плюс
  `Content-Security-Policy: frame-ancestors 'none'`, чтобы блокировать
  атаку из RFC 9700 §2.5: злоумышленник iframe'ит authorize-страницу
  для перехвата ввода пользователя. DOT не выставляет эти заголовки
  по умолчанию.

- Prometheus-счётчик `aa_oidc_policy_rejections_total`, размеченный
  по `stage` (`authorize` / `validate_silent_auth` /
  `validate_code` / `validate_refresh` / `validate_bearer` /
  `save_bearer`) и `reason` (`global` / `app` / `app_unusable`
  / `no_client` / `unknown`). Перекрывает все три layer'а policy
  enforcement, поэтому одним счётчиком dashboard отвечает на вопрос
  "какой гейт срабатывает чаще всего и на каком stage".

- Prometheus-счётчик `aa_oidc_code_reuse_audit_misses_total`,
  размеченный по `client_id`. `_handle_potential_code_reuse`
  инкрементируется при попадании на reuse-путь для кода без
  совпадающей строки в `IssuedCodeAudit`. После атомарной обёртки
  `save_bearer_token` + audit insert race-окно закрыто, поэтому
  счётчик теперь срабатывает исключительно на never-issued коды
  (fuzzers / replay'ы с чужого provider'а). Операторы коррелируют
  с сигналом `oidc_code_reuse_detected` — две метрики должны быть
  непересекающимися.

- Prometheus-счётчик `aa_oidc_audit_receiver_failures_total`,
  размеченный по `signal` и `receiver_dispatch_uid`.
  Инкрементируется на каждый receiver, который выбросил исключение
  во время `send_robust`-диспатча любого audit-сигнала
  (`oidc_token_issued`, `oidc_code_reuse_detected`,
  `oidc_token_introspected`, `oidc_logout_dispatched`). Ненулевая
  частота означает, что audit-пайплайн молча роняет события для
  хотя бы одного downstream-потребителя.

- Discovery (`/o/.well-known/openid-configuration/`) публикует
  девять дополнительных полей из OIDC Discovery 1.0 §3 / RFC 8414
  §2: `response_types_supported` сужен до `["code"]` (раньше шёл
  полный implicit/hybrid-набор DOT); `response_modes_supported`,
  `code_challenge_methods_supported` (S256), `acr_values_supported`
  (`["0"]` по RFC 6711), `prompt_values_supported`,
  `claims_parameter_supported` (True), `request_parameter_supported`
  / `request_uri_parameter_supported` (оба False — JAR/PAR не
  реализованы), `op_policy_uri` / `op_tos_uri` (задаются
  оператором через `ALLIANCEAUTH_OIDC_POLICY_URI` /
  `ALLIANCEAUTH_OIDC_TOS_URI`).

### Изменено

- В `tests/test_migrations.py` константа `MIGRATION_TARGET` обновлена
  до `"0015_backchannellogoutattempt"` — иначе post-migrate
  `objects.create(...)` через live-модель промахивается мимо схемы с
  каждым полем, добавленным в этом цикле (`pkce_required`,
  `access_token_format`, `backchannel_logout_uri`,
  `backchannel_logout_on_revoke_only`, `BackChannelLogoutAttempt`).
  PKCE-проверки продолжают покрывать data-шаг `0011`, потому что
  цепочка идёт вперёд.

## [0.2.0b2] - 2026-05-09

### Исправлено

- `manage.py oidc_audit_tokens --help` (и три соседние команды —
  `oidc_create_app`, `oidc_revoke_user_tokens`, `oidc_rotate_secret`)
  падали с `TypeError: expected string or bytes-like object, got
  '__proxy__'` на Python 3.12+. `HelpFormatter._fill_text` в новом
  argparse прогоняет описание парсера и `help` аргументов прямо через
  `re.sub`, а тот отказывается приводить к строке прокси-объект из
  `gettext_lazy`, который команды использовали. Все четыре команды
  переведены на не-ленивый `gettext`: management-команды живут в
  short-lived процессе, активный язык фиксируется на старте, и lazy
  не давала никакого выигрыша. Заодно убраны
  `# type: ignore[assignment]` поверх `BaseCommand.help: str` —
  без lazy они стали ложью.

### Документация

- В README — и в примере `OAUTH2_PROVIDER`, и в таблице ключей —
  рекомендованное значение `ACCESS_TOKEN_EXPIRE_SECONDS` поднято с
  `60` до `3600`. Прежнее `60` приехало из тестового сеттинга
  `tests/test_settingsAA4.py`, где маленький TTL нужен для того,
  чтобы expiry-сценарии прогонялись без `sleep`-ов. В качестве
  стартового значения для production оно не годилось: RP на
  `passport-openidconnect` (Wiki.js, Outline и подобные) отвергают
  токены со сроком жизни меньше минуты сразу, а более терпимые
  клиенты при чуть выросшей сетевой задержке просто не успевают
  сделать второй запрос на `/userinfo` до истечения TTL. `3600`
  совпадает со значением по умолчанию Auth0 / Keycloak / Google.
- Расширен раздел про интеграцию с WikiJS: полный набор URL
  (authorization / token / userinfo / issuer / logout), явно
  предупреждение, что тоггл `Skip User Profile` должен быть
  выключен — иначе WikiJS читает данные профиля только из
  `id_token` и падает с *«Missing or invalid email address from
  profile»*, поскольку провайдер строго следует OIDC Core 1.0 §5.4
  (claim'ы из scope `email` / `profile` отдаются только через
  `/userinfo`, в `id_token` их нет). Описан выбор стратегии
  аутентификации в WikiJS (Generic OpenID Connect / OAuth 2.0
  против Generic OAuth 2.0) с компромиссом для каждой.

### Изменено

- Стеки AA-версий объявлены как PEP 735 dependency groups (`aa4`,
  `aa5`) в `pyproject.toml` вместо хардкода внутри тела сессии
  `tests_aa4`. Сессия ставит зависимости через
  `uv pip install -e . --group aa4`, и uv пересекает контракт пакета
  `allianceauth>=4,<6` с сужением группы (`<5`). Снаружи ничего не
  меняется — матрица гоняет те же комбинации. `uv tree --group aaN`
  теперь перечисляет каждый поддерживаемый стек из `pyproject.toml`
  напрямую.

## [0.2.0b1] - 2026-05-08

Минорный бамп (0.1 → 0.2) фиксирует расширение контракта зависимостей:
это первый релиз с официальной поддержкой Alliance Auth 5.x. Операторам,
обновляющимся с `0.1.x`, перед деплоем стоит прочитать раздел
**Совместимость** ниже.

### Добавлено

- Официальная поддержка Alliance Auth 5.x (Django 5.2). Dev-окружение
  фиксируется на стеке AA 5.0.1 + Django 5.2.x как primary; обратная
  совместимость с AA 4.x остаётся под CI через новую off-lock сессию
  `tests_aa4` (запускается на Python 3.10 / 3.11 / 3.12; Python 3.13
  исключён, потому что AA 4.13.x декларирует `requires-python <3.13`).
  Контракт пакета расширен до `allianceauth>=4,<6`; версионных shim'ов
  внутри пакета нет.
- Classifier `Framework :: Django :: 5.2` на PyPI рядом с прежним
  `Framework :: Django :: 4.2`.

### Изменено

- `tests/test_settingsAA4.py` переопределяет `STORAGES["staticfiles"]`
  обратно на простой `StaticFilesStorage`. В AA 5.x по умолчанию идёт
  `ManifestStaticFilesStorage`, который отказывается отдавать
  не-хешированные пути из шаблонов без манифеста `staticfiles.json`,
  собираемого `collectstatic`. Под AA 4.x / Django 4.2 override
  ничего не меняет (поведение прежнее), под AA 5.x / Django 5.2
  разблокирует прогон сюиты.

### Совместимость

- Действующие развёртывания на AA 4.x продолжают работать без
  изменений — миграции и правок в settings не требуется.
- Операторам, планирующим переход AA 4.x → 5.x, следует ориентироваться
  на upgrade-guide самого Alliance Auth; в этом провайдере нет
  AA-версионно-специфичных ручек, которые надо переключать.

## [0.1.0b6] - 2026-05-08

### Добавлено

- В `/userinfo` и `id_token` теперь рядом с `email` отдаётся claim
  `email_verified` (OIDC Core 1.0 §5.1). Значение отражает состояние
  email-подтверждения в Alliance Auth по четырёх-уровневому дереву
  решений: `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` (force-override
  оператора) → проверка плейсхолдеров (soft-зависимость на
  `aa_skip_email`) → настройка AA `REGISTRATION_VERIFY_EMAIL` →
  выдача. `email` и `email_verified` отдаются связанной парой —
  один без другого не появится никогда.
- Если клиент указывает `acr_values`, в id_token отдаётся claim
  `acr=0` (OIDC Core 1.0 §3.1.2.6). Уровни Authentication Context
  Class Reference провайдер не реализует, поэтому RFC 6711
  «no specific level» — честный ответ вместо тихого отбрасывания
  claim'а.
- Новая тройственная настройка `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`:
  `True` — всегда отдавать `email_verified=true` (например, доверие
  приходит извне AA: пользователи импортированы из IdP, который сам
  верифицирует адреса); `False` — всегда `false`; `None` / не задано
  (по умолчанию) — auto-режим через дерево решений выше.
- В OIDC Discovery (`/o/.well-known/openid-configuration`) теперь
  объявлены `grant_types_supported` и `claim_types_supported` (OIDC
  Discovery 1.0 §3). Закрывает warning
  `EnsureServerConfigurationSupportsRefreshToken`, который OpenID
  Conformance Suite поднимал на плане `oidcc-refresh-token`.
- Soft-зависимость на сопутствующий плагин `aa-skip-email`:
  синтетические плейсхолдер-адреса, проставленные им, помечаются
  `email_verified=false` независимо от глобальной настройки — такие
  адреса появляются именно потому, что пользователь пропустил
  верификацию.

### Изменено

- В id_token больше не уезжают scope-привязанные claims (`email`,
  `name`, `picture`, `groups`, `locale`, `eve_*`) по умолчанию (OIDC
  Core 1.0 §5.4). DOT зеркалит id_token и `/userinfo` через один
  scope-filtered dict — это приводило к утечке таких claims в
  id_token при `scope=email`. Теперь они остаются в `/userinfo`,
  если клиент явно не запросил их через OIDC-параметр `claims` —
  override `get_id_token_dictionary` фильтрует словарь по whitelist
  reserved-claims (`sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`,
  `nonce`, `acr`, `amr`, `azp`, `at_hash`, `c_hash`, `jti`) плюс
  явно запрошенные клиентом id_token claims. Закрывает проверку
  `EnsureIdTokenDoesNotContainEmailForScopeEmail` плана
  `oidcc-scope-email` conformance suite.

### Инструментарий

- В conformance-harness'е per-module poll timeout поднят с 180s до
  360s. Эмпирически четыре browser-driven модуля
  (`oidcc-max-age-10000`, `oidcc-ui-locales`, `oidcc-claims-locales`,
  `oidcc-scope-email`) перешли из TIMEOUT в стабильный PASSED, при
  этом модули, которые реально зависают, всё ещё всплывают как
  TIMEOUT в пределах шести минут.
- `tests/conformance/diagnostic_export/` добавлен в `.gitignore`:
  per-plan HTML-архивы отчётов, которые скачиваются через
  `GET /api/plan/exporthtml/{id}` — эфемерные артефакты,
  регенерируются с любого прогона.

### Тесты

- `signals.py` достиг 100% покрытия по строкам и веткам. Три unit-теста
  теперь покрывают ранее недостижимый оборонительный блок
  `except (AttributeError, TypeError, ValueError, KeyError)` в
  `audit_oidc_token_issued`: путь swallow-`AttributeError`, ветка
  `body=None` (happy-path), и негативный кейс — посторонние
  исключения (`RuntimeError`) должны пробрасываться наружу,
  предохраняя от случайного расширения except'а до `Exception:`.

## [0.1.0b5] - 2026-05-08

### Добавлено

- Per-app override PKCE через новое поле
  `AllianceAuthApplication.pkce_required`. Новые приложения по умолчанию
  получают `True` (RFC 9700, secure-by-default); существующие строки
  заполняются миграцией значением прежней глобальной настройки —
  поведение в момент апгрейда сохраняется. Неизвестный `client_id`
  сваливается в `True` с записью `WARNING` в лог (fail-safe в строгий
  режим). Конфигурируется через Django admin (колонка changelist,
  чекбокс на форме редактирования, list filter).

### Изменено

- `OAUTH2_PROVIDER['PKCE_REQUIRED']` теперь указывает на callable
  (`per_app_pkce_required`), который живёт в лёгком модуле
  `allianceauth_oidc.pkce`. Adapter делает ORM-резолв через
  `.only("pkce_required")` и делегирует решение в
  `AccessPolicy.requires_pkce(app)` (`security.py`); сам policy-метод
  стал чистой логикой (без ORM, тестируется через `AppLike` Protocol
  DI seam). Неизвестный `client_id` пишется в лог `WARNING` (через
  `%a` — защита от log injection) и сваливается в `True`.
- Schema/data-миграция per-app PKCE разделена: `0010` добавляет
  колонку (schema-only, реверсивна), `0011` делает
  environment-зависимый backfill отдельным файлом. Свежие установки
  (без существующих строк) data-шаг пропускают целиком.
- Backfill теперь принимает только явный `bool` буквально; любая
  другая форма (callable, `None`, отсутствующий ключ, `str`, `int`)
  считается неоднозначной и сваливается в `pkce_required=True`
  (RFC 9700), поднимая `RuntimeWarning` вместо прежней записи в
  stderr.
- `AccessDecision` теперь tagged discriminated union
  (`AllowedDecision | GlobalDeny | AppDeny`) вместо одного
  `NamedTuple` с тремя nullable-полями. Инвариант
  «`deny_reason=APP` ⇒ `app is non-None`» теперь живёт в типе;
  `AuthAuthorizationView.dispatch` использует `match` плюс
  `typing_extensions.assert_never` для исчерпываемости — это
  заменило прежний `assert decision.app is not None`-через-комментарий.
- `AccessPolicy.pkce_required(app)` переименован в
  `AccessPolicy.requires_pkce(app)`, чтобы метод не коллидировал
  с атрибутом `AppLike.pkce_required`, который он читает.
  Переименование внутреннее; продакшн-вызовы идут через
  `OAUTH2_PROVIDER['PKCE_REQUIRED'] = per_app_pkce_required` и не
  затронуты.

> ⚠️ **Изменение конфигурации**: семантика `OAUTH2_PROVIDER['PKCE_REQUIRED']`
> изменилась с boolean на callable. Старые конфиги с `True`/`False`
> продолжают работать, но больше не соответствуют рекомендации в README.
> Перенесите конфиг на импорт `per_app_pkce_required` из
> `allianceauth_oidc.pkce` и присвойте ссылку на функцию — это даст
> per-app override. Если миграция запущена на живом долгоживущем
> процессе — вызовите `oauth2_settings.reload()`, чтобы DOT перечитал
> кэшированный дескриптор; свежие процессы подхватят изменение
> автоматически.
>
> ⚠️ **Порядок обновления**: запускайте `manage.py migrate` **до** замены
> `OAUTH2_PROVIDER['PKCE_REQUIRED']` с прежнего boolean на callable
> `per_app_pkce_required`. Data-шаг миграции читает прежнюю глобальную
> настройку в run-time; обратный порядок приводит к тому, что всем
> существующим приложениям принудительно проставится
> `pkce_required=True` (fail-safe по RFC 9700). Полный рецепт апгрейда —
> в разделе README «Обновление с предыдущей версии».

### Сборка

- Build-backend переехал с `flit_core` на `uv_build`. `version` и
  `description` теперь статические `[project]`-поля в
  `pyproject.toml` (single source of truth); runtime `__version__`
  резолвится через
  `importlib.metadata.version("allianceauth-oidc-provider-eveo7")`
  с фолбэком `0.0.0+local` для editable / source-checkout. Содержимое
  wheel идентично прежней сборке (тот же `allianceauth_oidc/*` плюс
  каталоги локализации, без test-артефактов).

### Инструментарий

- Внутренняя типизация ужесточена. Новые Protocol'ы `TokenLike` /
  `OAuthRequestLike` в `security.py` и локальный `ClaimsUser`
  в `auth_provider.py` заменили прежние параметры типа `object`
  у `TokenAudit`, `audit_oidc_token_issued`, `ClaimsBuilder`,
  `app_log`, `build_oidc_debug_meta`. Опечатки в именах атрибутов
  у этих хелперов теперь ловятся статически.
- mypy ramp в strict: подключён плагин `mypy_django_plugin.main`
  (django-stubs уже был в dev-группе, но не активирован), плюс
  `check_untyped_defs`, `warn_unused_ignores`, `warn_no_return`,
  `warn_unreachable`, `strict_equality`, `extra_checks` и error-коды
  `redundant-expr` / `possibly-undefined` / `truthy-bool` /
  `unused-awaitable` / `explicit-override`. На последний код
  понадобилось добавить `@override` декораторы десяти Django
  command / AppConfig override-методам (через `typing_extensions`,
  чтобы держать floor 3.10).
- ruff `select` расширен с 11 групп до 28: добавлены `DJ`, `LOG`, `G`,
  `RET`, `DTZ`, `ISC`, `BLE`, `PTH`, `TC`, `TID`, `A`, `FURB`,
  `TRY`, `PERF`, `SLF`, `ICN`, `PGH`, `ARG`, плюс четыре pylint-
  группы `PLE`, `PLW`, `PLC`, `PLR`. Карвоуты на framework-границах
  (signal-handler'ы, dispatch view, override-методы oauthlib
  валидатора, Django-миграции) держат шум локализованным.
- Новые pre-commit хуки: `vulture` (детект мёртвого кода,
  `min_confidence=80` плюс `ignore_names` под Django-контракты),
  `xenon` (циклматическая сложность с порогами `D/B/A`) и
  `uv lock --check` (drift lock-файла при изменениях
  `pyproject.toml` / `uv.lock`).
- `[tool.coverage]` сведён в `pyproject.toml`; легаси `.coveragerc`
  удалён. Включён `branch = true` плюс `exclude_also`-паттерны
  под `if TYPE_CHECKING:`, `assert_never(...)`, тела Protocol-
  методов (`...`), `def __repr__`, `raise AssertionError`. Общее
  покрытие 96% → 97% на неизменном test-наборе (за счёт честного
  исключения недостижимых веток).
- `[tool.ruff.lint.per-file-ignores]` приведён в порядок: убраны
  избыточные дубли (`tests/test_settingsAA4.py` теперь декларирует
  только file-specific `N999`), удалён stale-ignore `D107` из
  миграций, коды отсортированы по алфавиту внутри каждого списка,
  добавлен docblock про accumulate-not-override-семантику ruff.

## [0.1.0b4] - 2026-05-06

### Изменено

- Диаграмма policy-flow в README теперь — pre-rendered D2 SVG,
  а не Mermaid-блок. `readme-renderer` на PyPI не понимает
  Mermaid-расширения, поэтому страница v0.1.0b3 показывала
  диаграмму как сырой Mermaid-код. Новая схема: source остаётся
  diagram-as-code (`assets/diagrams/policy-flow.d2`), рядом
  лежит pre-rendered output (`policy-flow.svg`), README ссылается
  через raw GitHub URL на default-branch репо. Картинка
  рендерится одинаково на GitHub, на PyPI и в любом другом
  Markdown-viewer'е.

### Инструментарий

- Новая `nox`-сессия `diagrams` и `make`-шим `make diagrams`
  рендерят `assets/diagrams/*.d2` в SVG через бинарь `d2`.
  Та же opt-in схема graceful-skip с предупреждением, что и у
  `markdown_lint` и `actions_lint` — контрибьютору без
  установленного `d2` сессия пройдёт зелёной с подсказкой по
  установке (Gentoo overlay / d2lang.com).

## [0.1.0b3] - 2026-05-06

Теги `v0.1.0b1` и `v0.1.0b2` зафиксированы в git, но до PyPI не
доехали:

- `v0.1.0b1` — встроенная twine-предпроверка внутри
  `pypa/gh-action-pypi-publish@v1.9.0` отвергает
  `Metadata-Version: 2.4`, который выдаёт современный flit-core
  (PEP 685, 2024).
- `v0.1.0b2` — тот же сломанный twine запускается ещё раз во
  *время* `twine upload`, так что отключение предпроверки через
  `verify-metadata: false` оказалось недостаточным.

`v0.1.0b3` переключает publisher на `uv publish`, который
понимает `Metadata-Version: 2.4` нативно и поддерживает PyPI
Trusted Publishing автоматически. Это фактически первая
публикация форка на PyPI. Прежние теги остаются в истории git как
метки неудачных попыток. Полный разбор причин — в коммитах
`fix(ci):`.

Этот релиз также переводит три action'а на Node 24
(`actions/checkout` v4 → v6, `actions/upload-artifact` v4 → v7,
`astral-sh/setup-uv` v5 → v8) — снимает deprecation-warning
GitHub Actions про Node 20, — и применяет находки zizmor по
безопасности (`persist-credentials: false` на всех checkout-шагах,
`enable-cache: false` на всех setup-uv — последнее закрывает
cache-poisoning vector между release-прогонами).

### Добавлено

- Русский перевод (`locale/ru/LC_MESSAGES/django.po`) — шаблоны согласия и выхода, verbose-имена и
  help_text моделей, имя AppConfig, help-строки сервисных команд. Скомпилированный `.mo` едет
  прямо в wheel — оператору не нужно отдельно прогонять `compilemessages`.
- HTTP-уровень интеграционных тестов (`tests/test_integration_mock_rp.py`) на базе
  `LiveServerTestCase`, реальных `requests` и `jwcrypto`. Ловят то, что Django test client
  маскирует: ошибки в абсолютных URL, Bearer-заголовках, cookie. Уже нашли реальный баг —
  `dateformat.format(user.last_login, "U")` падает, когда `last_login is None`. В обычных тестах
  это скрыто: `force_login` сам выставляет `last_login` через сигнал `user_logged_in`.
- Обвязка OIDC Conformance Suite в `tests/conformance/`: docker-compose-стек (mongo + suite nginx +
  suite server + контейнер с провайдером), REST-драйвер `run_plan.py`, идемпотентный `seed.py`,
  минимальный `Dockerfile.provider` поверх `tests.test_settingsAA4`. Сквозной pipeline уже
  обнаруживает реальные проблемы соответствия спецификации; результаты первого прогона выписаны
  прямо в conformance-README, чтобы триажить было с чего.
- Операторские CLI-команды: `oidc_create_app`, `oidc_rotate_secret`, `oidc_revoke_user_tokens`,
  `oidc_audit_tokens`. У всех есть `--format=table|json|csv`; деструктивные понимают `--dry-run`.
- EVE-специфичные claim'ы (`eve_character_id`, `eve_corporation_*`, `eve_alliance_*`) рядом со
  стандартным OIDC-набором. Префикс настраивается через `ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX`,
  привязка к scope — отдельной настройкой.
- Mermaid-диаграммы: трёхслойная политика доступа в основном README и сетевая топология
  conformance-стека в conformance-README.

### Инструментарий

- Новые `nox`-сессии: `integration` (mock-RP, `--parallel=1`), `conformance` (docker-compose +
  `run_plan.py`), `makemessages` / `compilemessages` (i18n), `makemigrations` (Django-миграции
  под тестовыми settings), `markdown_lint` (rumdl + lychee + vale; каждый инструмент опционален —
  отсутствует в `PATH` ⇒ просто пропускается с предупреждением). Под все новые сессии есть
  обёртки в Makefile.
- `.rumdl.toml` поднимает `MD013` (line length) до 120 колонок и исключает code-блоки и таблицы:
  переносить там нечего, перенос только ломает copy-paste.
- В `.gitignore` точечное исключение для `allianceauth_oidc/locale/**/*.mo` и
  `locale/django.pot` — глобальные `*.mo` / `*.pot` остаются на месте, чтобы посторонние
  бинарники в репо не попадали.
- Type-check игноры обновлены под bump `django-stubs` — оттуда выпилили
  `LogEntry.objects.log_action` (deprecated в Django 5.1). Runtime-вызов на Django 4.2 ещё
  работает, поэтому добавлены прицельные `# type: ignore`.

### Сборка

- `uv.lock` обновлён через `uv sync --all-groups --upgrade`. Появились три новых транзитивных
  пакета (`ijson`, `jsonseq`, `python-discovery`), удалений нет.
- Расширили поддерживаемые версии Python до `>=3.10,<3.14` (вслед за allianceauth). В CI-матрице
  теперь четыре версии: 3.10 / 3.11 / 3.12 / 3.13.

### CI / проект

- GitHub Actions переписаны под современный uv-pipeline: отдельные джобы `test`, `lint`,
  `typecheck`, `package`, `concurrency` по ref'у, обновлённые actions. Авто-workflow публикации на
  PyPI пока не возвращали — публикация форка остаётся ручной (`uv build && twine upload dist/*`),
  см. ниже про новое имя дистрибутива.
- URL'ы в `pyproject.toml` указывают на
  [6RUN0 форк](https://github.com/6RUN0/allianceauth-oidc-provider); ссылка на оригинал
  [Solar-Helix](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
  сохранена в поле `urls.Upstream`.
- В README.md появилась шапка форка, инструкция установки из PyPI под именем форка (см. ниже) и
  русский сосед — [README.ru.md](README.ru.md).
- Форк публикуется на PyPI под отдельным именем — `allianceauth-oidc-provider-eveo7`. Естественное
  имя `allianceauth-oidc-provider` занято апстримным релизом, поэтому в `pyproject.toml`
  переименовано поле `[project] name` — это «развязывает» PyPI-имя и оставляет неизменным
  import-path (`allianceauth_oidc`). Настройки и импорты совместимы drop-in. Заливка пока ручная
  (`uv build && twine upload dist/*`); авто-workflow GitHub Actions для релиза не часть этого
  изменения.
- В `pyproject.toml` добавлен `maintainers` форка (Boris Talovikov, `boris.t.66@gmail.com`); поле
  `authors` с упоминанием автора апстрима сохранено — оригинальный автор остаётся виден в
  PyPI-метаданных.

## История апстрима

Что было до точки расхождения форка — смотрите `git log` и страницу релизов оригинала.

[Unreleased]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b2...v0.3.1
[0.3.0]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b2...v0.3.0
[0.2.0b2]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b1...v0.2.0b2
[0.2.0b1]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b6...v0.2.0b1
[0.1.0b6]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b5...v0.1.0b6
[0.1.0b5]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b4...v0.1.0b5
[0.1.0b4]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b3...v0.1.0b4
[0.1.0b3]: https://github.com/6RUN0/allianceauth-oidc-provider/releases/tag/v0.1.0b3
