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

### Добавлено

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
  [docs/JWT_ACCESS_TOKENS.md](docs/JWT_ACCESS_TOKENS.md) — включение,
  RP cookbook (oauth2-proxy / mod_auth_openidc / WikiJS), ротация
  ключей, data minimization, откат.

### Изменено

- В `tests/test_migrations.py` константа `MIGRATION_TARGET` обновлена
  до `"0012_allianceauthapplication_access_token_format"` — иначе
  post-migrate `objects.create(...)` через live-модель промахивается
  мимо схемы. PKCE-проверки продолжают покрывать data-шаг `0011`,
  потому что он по-прежнему запускается как часть цепочки до `0012`.

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
