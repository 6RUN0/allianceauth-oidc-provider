# allianceauth_oidc

> Это форк
> [Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider).
> Живёт в
> [6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) и
> добавляет: HTTP-уровень интеграционных тестов, обвязку OIDC Conformance Suite, сервисные
> CLI-команды, EVE-специфичные claim'ы в id_token и userinfo, локализацию (en / ru / uk) и
> английский [README.md](README.md).

Тонкая прослойка над
[`django-oauth-toolkit`](https://django-oauth-toolkit.readthedocs.io/), которая превращает
[Alliance Auth](https://gitlab.com/allianceauth/allianceauth) в OpenID Connect / OAuth2-провайдер.
Сама по протоколу ничего не делает: всё что касается OAuth / OIDC лежит на DOT, а здесь — только
доменная access-политика, маппинг claim'ов, безопасное логирование и кастомная модель
`Application`.

- [Обзор](#обзор)
- [Требования](#требования)
- [Установка](#установка)
- [Обновление с предыдущей версии](#обновление-с-предыдущей-версии)
- [Конфигурация](#конфигурация)
- [Справочник](#справочник)
- [Эксплуатация](#эксплуатация)
- [Интеграции с RP](#интеграции-с-rp)
- [Разработка](#разработка)

## Обзор

DOT занимается протокольной работой OAuth / OIDC; это приложение добавляет Alliance-Auth-специфичный
access control, маппинг claim'ов, безопасное логирование и кастомную модель `Application` с
whitelist'ом `state` / `group`.

Каждый обмен `authorization_code` проходит через три независимые проверки. Любое упрощение —
дыра в безопасности; именно поэтому в регрессии есть тесты под каждый слой по отдельности.

![Трёхслойная проверка политики: dispatch затем validate_code затем save_bearer_token](https://raw.githubusercontent.com/6RUN0/allianceauth-oidc-provider/current/assets/diagrams/policy-flow.svg)

Source диаграммы — `assets/diagrams/policy-flow.d2`; перерисовать через `make diagrams` после правок.

## Требования

| Компонент             | Поддерживаемые версии                              |
|-----------------------|----------------------------------------------------|
| Python                | 3.10, 3.11, 3.12, 3.13                             |
| Alliance Auth         | 4.x и 5.x                                          |
| Django                | 4.2 (с AA 4.x) или 5.2 (с AA 5.x)                  |
| `django-oauth-toolkit`| `>=3.2,<4`                                         |

CI прогоняет стек AA 5.x на каждой поддерживаемой версии Python и
backward-совместимость с AA 4.x на Python 3.10–3.12 (AA 4.13.x объявляет
`requires-python <3.13`, поэтому Python 3.13 в AA 4.x-измерении не идёт).
Оба стека используют один и тот же код — версионных shim'ов в пакете нет.

## Установка

Плагин встаёт в стандартное дерево проекта Alliance Auth. AA-helper при `auth-helper init`
делает примерно такой layout (`myauth` — имя проекта, которое вы выбрали; подставьте своё
везде ниже):

```text
myauth/
├── manage.py
└── myauth/
    ├── settings/
    │   ├── base.py        # AA-шный, не трогаем
    │   └── local.py       # ВАШИ настройки — все правки этого гайда сюда
    ├── urls.py            # ВАШИ urlpatterns
    └── ...
```

Если у вас другой layout — важны не сами имена файлов, а в каком файле лежит `INSTALLED_APPS`
(settings) и в каком `urlpatterns` (URL conf). Все правки ниже идут в эти два файла.

1. Поставьте форк из PyPI. Форк опубликован под именем
   `allianceauth-oidc-provider-eveo7`, чтобы не конфликтовать с
   апстримным `allianceauth-oidc-provider`; import-path
   (`allianceauth_oidc`) остался прежним, так что настройки и импорты
   совместимы drop-in:

   ```sh
   pip install allianceauth-oidc-provider-eveo7
   ```

   **Не ставьте** одновременно `allianceauth-oidc-provider` и
   `allianceauth-oidc-provider-eveo7` в одно окружение — оба
   распаковываются в директорию `allianceauth_oidc/`, pip откажет на
   втором установке с file-conflict'ом. Удалите апстримный пакет, если
   он установлен.

   Если хочется отслеживать `current` напрямую — установка из git
   тоже работает:

   ```sh
   pip install "git+https://github.com/6RUN0/allianceauth-oidc-provider.git@current"
   ```

2. **В `myauth/settings/local.py`** добавьте к `INSTALLED_APPS`:

   ```python
   INSTALLED_APPS += [
       "allianceauth_oidc",
       "oauth2_provider",
   ]
   ```

3. **В тот же `myauth/settings/local.py`** допишите конфигурацию DOT + валидатора политики.
   Весь блок обёрнут в guard `if "allianceauth_oidc" in INSTALLED_APPS …` — чтобы файл
   оставался валидным, если плагин когда-нибудь снимут. Каждый ключ объяснён ниже в разделе
   [Конфигурация → Ключи OAUTH2_PROVIDER](#ключи-oauth2_provider); сниппет можно вставлять
   как есть и подкручивать по месту:

   ```python
   from pathlib import Path

   # Per-app PKCE-резолвер. DOT не импортирует это значение по
   # dotted-path строке — присваивайте сам callable. Импорт идёт из
   # лёгкого модуля, безопасного на этапе загрузки settings (до
   # ``apps.populate()``).
   from allianceauth_oidc.pkce import per_app_pkce_required

   if (
       "allianceauth_oidc" in INSTALLED_APPS
       and "oauth2_provider" in INSTALLED_APPS
   ):
       OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"
       OAUTH2_PROVIDER = {
           "OIDC_ENABLED": True,
           "OIDC_RSA_PRIVATE_KEY": Path("/path/to/key").read_text(),
           "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
           "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
           "SCOPES": {
               "openid": "User Profile",
               "email": "Registered email",
               "profile": "Main Character affiliation and Auth groups",
           },
           "PKCE_REQUIRED": per_app_pkce_required,
           "ROTATE_REFRESH_TOKEN": True,
           "REFRESH_TOKEN_REUSE_PROTECTION": True,
           "ACCESS_TOKEN_EXPIRE_SECONDS": 3600,
           "REFRESH_TOKEN_EXPIRE_SECONDS": 24 * 60 * 60,
       }
   ```

4. **В `myauth/urls.py`** подключите URL-конф под `/o/`:

   ```python
   from .settings.local import INSTALLED_APPS

   if "allianceauth_oidc" in INSTALLED_APPS and "oauth2_provider" in INSTALLED_APPS:
       urlpatterns.append(
           path(
               "o/",
               include("allianceauth_oidc.urls", namespace="oauth2_provider"),
           )
       )
   ```

5. Из корня проекта (`myauth/`) — миграции и перезапуск Auth:

   ```sh
   python manage.py migrate
   supervisorctl restart myauth:    # или ваш аналог супервайзера
   ```

> [!NOTE]
> Если у вас кастомный шаблон логина (`authentication/templates/public/login.html`),
> следите, чтобы SSO-ссылка URL-кодировала параметр `next`. Без этого query-параметры
> обрезаются после редиректа — и OAuth-flow ломается на потерянном `client_id`:
>
> ```html
> <a href="{% url 'auth_sso_login' %}{% if request.GET.next %}?next={{ request.GET.next | urlencode }}{% endif %}"></a>
> ```

## Обновление с предыдущей версии

Свежие установки идут по [инструкции «Установка»](#установка) — оговорки про порядок шагов
ниже к ним не относятся. Этот раздел — для операторов с живыми OAuth-приложениями, которые
переезжают на новую версию.

### RP-Initiated Logout по умолчанию on (0.3.1)

`OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` теперь по умолчанию `True` через
AppConfig — маршрут `/o/logout/` и поле `end_session_endpoint` в
`.well-known/openid-configuration` становятся живыми без явного opt-in оператора. Upstream
DOT по умолчанию `False`; override применяется через `setdefault`, поэтому явный `False` в
ваших настройках сохраняется.

Если деплой опирается на прежнее поведение (`/o/logout/` отдаёт 404, `end_session_endpoint`
отсутствует в discovery), пропишите ключ явно:

```python
OAUTH2_PROVIDER["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = False
```

Отключение RP-init logout при наличии приложений с `backchannel_logout_uri` ломает
Single-Logout chain на первом hop'е — `manage.py check` тогда выдаёт
`allianceauth_oidc.W003`, делая конфигурационную проблему видимой. Текст warning'а — в
[System checks](#system-checks-managepy-check).

### Поле per-app PKCE (`pkce_required`)

`OAUTH2_PROVIDER['PKCE_REQUIRED']` сменил тип с boolean на callable; новая data-миграция
заполняет `AllianceAuthApplication.pkce_required` значением прежней глобальной настройки.

**Выполняйте шаги строго в этом порядке:**

1. `pip install -U allianceauth-oidc-provider-eveo7` — `local.py` пока не трогаем.
2. `python manage.py migrate` — **оставьте `OAUTH2_PROVIDER['PKCE_REQUIRED']` в прежнем
   boolean** на момент запуска миграции. Data-шаг читает глобальную настройку в run-time и
   проставляет это значение всем существующим приложениям, поведение в боевом режиме не
   меняется.
3. Правка `myauth/settings/local.py`: замените boolean-значение `PKCE_REQUIRED` на callable
   из [шага 3 установки](#установка). Дальше — per-app через Django admin.
4. Перезапуск Auth (`supervisorctl restart myauth:` или ваш супервайзер).
5. *По желанию:* живой долгоживущий процесс, у которого уже закэширован старый
   `OAUTH2_PROVIDER`, можно подтянуть без полного рестарта вызовом `oauth2_settings.reload()`.

Если шаги 2 и 3 выполнены в обратном порядке — т.е. на момент `migrate` уже стоит callable —
data-шаг видит non-boolean значение, переключается в RFC 9700 secure-by-default режим и
принудительно ставит `pkce_required=True` всем существующим приложениям. Откат —
поправить нужные приложения в Django admin вручную. Соответствующий `RuntimeWarning` описан
в разделе [Эксплуатация → Per-app PKCE](#per-app-pkce).

## Конфигурация

В предыдущем разделе уже есть готовый сниппет. Этот раздел — попунктная справка для тонкой
настройки. Две поверхности:

- словарь DOT `OAUTH2_PROVIDER` — без него протокол не заработает;
- наши опциональные Django-настройки `ALLIANCEAUTH_OIDC_*` — логирование / форма claim'ов /
  шаблон URL аватарки. У всех есть разумные значения по умолчанию.

И то и другое идёт в `myauth/settings/local.py` рядом с install-сниппетом.

### Ключи OAUTH2_PROVIDER

| Настройка | Рекомендуемое значение | Зачем |
|---|---|---|
| `OAUTH2_PROVIDER_APPLICATION_MODEL` | `"allianceauth_oidc.AllianceAuthApplication"` | **Обязательно.** Без этого state / group access-политика молча обходится. Ставится как top-level Django-настройка, не внутри `OAUTH2_PROVIDER`. |
| `OIDC_ENABLED` | `True` | **Обязательно.** Включает OIDC-слой DOT (discovery, JWKS, подписание id_token). |
| `OIDC_RSA_PRIVATE_KEY` | `Path("/path/to/key").read_text()` | **Обязательно.** RSA-ключ, которым DOT подписывает id_token. Генерация — в [документации DOT](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key). |
| `OIDC_RSA_PRIVATE_KEYS_INACTIVE` | `[]` (или список PEM'ов выводимых из ротации ключей) | Опциональный. PEM'ы ранее активных signing-ключей, всё ещё публикуемых в JWKS — нужно, чтобы уже выпущенные токены проходили валидацию в окно ротации. Используется в workflow `manage.py oidc_jwks_rotate`: командой сгенерировать свежий ключ, дописать старый PEM сюда, перевести `OIDC_RSA_PRIVATE_KEY` на новый, удалить запись из этого списка после `ACCESS_TOKEN_EXPIRE_SECONDS + clockTolerance`. |
| `OAUTH2_VALIDATOR_CLASS` | `"allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"` | **Обязательно.** Реализует трёхслойную политику и AA-специфичные claim'ы. |
| `APPLICATION_ADMIN_CLASS` | `"allianceauth_oidc.admin.ApplicationAdmin"` | **Обязательно.** AA-aware админка для нашей модели `Application`. |
| `SCOPES` | `{"openid": "...", "email": "...", "profile": "..."}` | **Обязательно.** Какие scope-ы показывать на consent-экране. Строки — это user-facing метки. |
| `PKCE_REQUIRED` | `per_app_pkce_required` (callable, импорт из `allianceauth_oidc.pkce`) | Per-app override, читается из `AllianceAuthApplication.pkce_required`. Новые приложения получают `True` (RFC 9700); существующие — то значение, что было в глобальной настройке на момент миграции. Неизвестный `client_id` сваливается в `True` и пишется в лог как `WARNING`. Конфигурируется через Django admin. **Внимание: значение должно быть ссылкой на функцию, а не dotted-path строкой — DOT не импортирует это значение автоматически.** |
| `ACCESS_TOKEN_GENERATOR` | `"allianceauth_oidc.tokens.dispatching_access_token_generator"` | **Требуется только при включении JWT-режима** (RFC 9068). Здесь dotted-path строка работает: `ACCESS_TOKEN_GENERATOR` входит в `IMPORT_STRINGS` DOT, и DOT резолвит путь на старте. В отличие от `PKCE_REQUIRED` (нужна именно ссылка на функцию). См. [JWT-токены доступа](#jwt-токены-доступа-rfc-9068). |
| `ROTATE_REFRESH_TOKEN` | `True` | Рекомендуется. На каждом использовании выпускает свежий refresh-токен; старый аннулируется. |
| `REFRESH_TOKEN_REUSE_PROTECTION` | `True` | Рекомендуется. Защита от replay'я по RFC 6819 §5.2.2.3 — refresh-токен, предъявленный дважды, отзывает всё семейство токенов. |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | `3600` | Компромисс: чем короче срок жизни access-токена, тем чаще RP вынуждены ходить за refresh — быстрее реакция на отзыв, но больше запросов к token endpoint; чем длиннее — тем медленнее распространяется отзыв, зато трафик легче. **Не берите за основу тестовое `60`** — это значение из `tests/test_settingsAA4.py`, нужно лишь для того, чтобы expiry-сценарии в тестах гонялись без `sleep`-ов. В реальном логине RP токен должен прожить как минимум один запрос на `/userinfo` плюс запас на `clockTolerance` клиента (~5 секунд); `passport-openidconnect` (Wiki.js, Outline и им подобные) отвергает токены со сроком жизни меньше минуты сразу же. `3600` (1 час) — то же значение по умолчанию, что в Auth0 / Keycloak / Google. |
| `REFRESH_TOKEN_EXPIRE_SECONDS` | `24*60*60` | На вкус деплоя — какая толерантность к риску. |
| `OIDC_ISS_ENDPOINT` | unset | **Обязателен, если хотя бы у одного приложения задан `backchannel_logout_uri`.** Абсолютный URL issuer'а (например, `"https://auth.example.org/o"`). Celery worker, который POST'ит `logout_token`'ы, не имеет HTTP request context, поэтому не может вывести `iss` в runtime — `oidc_issuer(None)` падает на эту настройку. Если back-channel logout сконфигурирован, а настройка не задана, system check (`allianceauth_oidc.E001`) падает на `manage.py check`; CI ломается громко, а не первый end-user logout. См. [OIDC Back-Channel Logout 1.0](docs/BACK_CHANNEL_LOGOUT.ru.md). |
| `OIDC_RP_INITIATED_LOGOUT_ENABLED` | `True` (по умолчанию on) | OIDC RP-Initiated Logout 1.0 — `/o/logout/` + `end_session_endpoint` в discovery. Upstream DOT по умолчанию `False`; AppConfig `_apply_default_oauth2_provider_settings` переключает в `True`, только когда ключ отсутствует, поэтому явный `False` opt-out сохраняется. Пара к `OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT` (DOT default `True`) — DOT рендерит `oauth2_provider/logout_confirm.html` на logout-запросах; наше приложение поставляет свой AA-themed override под `allianceauth_oidc/templates/allianceauth_oidc/logout_confirm.html` (Django резолвит его по template precedence). Установите prompt-настройку в `False`, чтобы пропустить confirm-шаг для headless flow'ов. |

### Свои настройки (ALLIANCEAUTH_OIDC_*)

| Настройка | По умолчанию | Что делает |
|---|---|---|
| `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS` | `False` | Заменяет `<redacted>` на маскированные фрагменты (`he…il`) в debug-логах. Включайте только если хранение логов нормально ограничено по доступу. |
| `ALLIANCEAUTH_OIDC_LOG_MASK_HEAD` | `2` | Сколько символов показывать в начале маскированного значения. |
| `ALLIANCEAUTH_OIDC_LOG_MASK_TAIL` | `2` | Сколько в конце. |
| `ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX` | `"eve_"` | Префикс EVE-специфичных claim'ов. Пустая строка — без префикса (повышает риск коллизий имён); любой другой префикс разделяет namespace'ы между провайдерами. |
| `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE` | `"profile"` | OIDC-scope, который гейтит EVE-claim'ы. **Привязка class-level** — после смены настройки нужен перезапуск Auth. |
| `ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE` | `"https://images.evetech.net/characters/{character_id}/portrait?size={size}"` | Шаблон URL для claim'а `picture`. Обязательны плейсхолдеры `{character_id}` и `{size}`; битый шаблон просто пропускает claim с warning'ом. |
| `ALLIANCEAUTH_OIDC_PORTRAIT_SIZE` | `128` | Какой размер запрашивать у image-сервера. EVE поддерживает 32 / 64 / 128 / 256 / 512 / 1024. |
| `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` | `None` | Тройственный force-override для claim'а `email_verified`. `True` — всегда отдавать `true` (например, доверие приходит извне AA: пользователи импортированы из IdP, который сам верифицирует адреса). `False` — всегда `false`. `None` (по умолчанию) — auto-режим: синтетические плейсхолдер-адреса от опционального плагина `aa-skip-email` → `false`; иначе зеркалит настройку AA `REGISTRATION_VERIFY_EMAIL`. |
| `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT` | `"opaque"` | Wire-формат, в котором выпускаются access-токены, когда у приложения поле `access_token_format` пустое. Установите `"jwt"`, чтобы включить RFC 9068 глобально; per-app `access_token_format` приоритетнее. Помимо этой настройки оператор должен прописать `ACCESS_TOKEN_GENERATOR` (см. выше) — иначе JWT-режим не активируется и стартовый лог пишет `WARNING` о неполной конфигурации. См. [JWT-токены доступа](#jwt-токены-доступа-rfc-9068). |
| `ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` | `4096` | Мягкий size-guard на длину выпущенных JWT-токенов. Генератор пишет `logger.warning`, если токен превысил порог (типичная причина — фикстура с пользователем в сотнях групп). Токен **не** мутируется и не отвергается — оператор сам решает, обрезать ли claim'ы, поднимать ли лимит `Authorization`-заголовка в апстримном прокси (Apache `LimitRequestFieldSize`, nginx `large_client_header_buffers`, HAProxy `tune.bufsize`) или сократить group-churn. Действует только в JWT-режиме. |
| `ALLIANCEAUTH_OIDC_POLICY_URI` | unset | OIDC Discovery 1.0 §3 `op_policy_uri`. Абсолютный URL privacy policy Authorization Server'а; светится в `.well-known/openid-configuration`, когда задан. Несколько compliance-фреймворков (GDPR Art. 13, NIS2) требуют от RP линковать на AS-side privacy policy — публикация URL здесь позволяет RP-login-страницам auto-линковать без per-RP статической конфигурации. Пропустите ключ (или установите пустую строку), чтобы не публиковать его в discovery. |
| `ALLIANCEAUTH_OIDC_TOS_URI` | unset | OIDC Discovery 1.0 §3 `op_tos_uri`. Абсолютный URL terms-of-service-страницы Authorization Server'а; светится в `.well-known/openid-configuration`, когда задан. Независим от `ALLIANCEAUTH_OIDC_POLICY_URI` — публикуйте один или оба. Пропустите ключ (или установите пустую строку), чтобы не публиковать его в discovery. |
| `ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS` | `False` | Сохранять ли успешные попытки back-channel-logout в `BackChannelLogoutAttempt` помимо неуспешных. По умолчанию таблица — строго dead-letter (только провалы); переключите в `True`, если SIEM нужны proof-of-delivery строки. Провалы записываются всегда. |
| `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE` | `False` | Обходит DNS-гейт private / loopback / link-local / multicast / CGNAT (и admin-save, и dispatch-time re-check) на `backchannel_logout_uri`. Нужно для dev / staging против RP в `192.168.x.x`, `10.x.x.x`, k8s overlay и т.п. При `DEBUG=False` поднимает `W005`; при `DEBUG=True` молчит. См. [Локальное тестирование на приватной сети](#локальное-тестирование-на-приватной-сети). |
| `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION` | `False` | Production-only явное подтверждение, что комбинация `DEBUG=False` + `_LOGOUT_URI_ALLOW_PRIVATE=True` — это сознательный выбор. Без этого opt-in та же комбинация триггерит `E006` и `manage.py check` падает — защитная сетка, чтобы dev-настройки SSRF-bypass не утекли в прод по недосмотру. |

### Периодическая чистка истёкших токенов (Celery Beat)

Задача `clear_expired_tokens` в комплекте идёт, но **не** ставится на расписание автоматически —
это уже на операторе:

```python
from celery.schedules import crontab

CELERYBEAT_SCHEDULE["allianceauth_oidc_clear_expired_tokens"] = {
    "task": "allianceauth_oidc.clear_expired_tokens",
    "schedule": crontab(minute=0, hour="*/2"),  # каждые 2 часа
}
```

Задача идемпотентна (удаляет только уже истёкшие строки); защита от лишних запусков — это
аутентификация Celery-брокера.

### Наблюдаемость — Prometheus-метрики

Провайдер поставляет **опциональную** Prometheus-инструментацию, которая кооперирует с
[`django-prometheus`](https://github.com/korfuri/django-prometheus). Оператор активирует её
установкой extra:

```sh
pip install allianceauth-oidc-provider-eveo7[metrics]
```

Без extra-зависимости receiver-цепочка всё равно подключается (каждый сигнал попадает в no-op
заглушку), так что install/test пути байт-идентичны независимо от того, активны метрики или
нет. Провайдер **никогда** не монтирует свой `/metrics` и не добавляет middleware — exposing
общего `prometheus_client.REGISTRY` — это работа `django-prometheus`'а; оператор сам решает,
где `/metrics` становится доступен.

Все имена метрик идут под префиксом `aa_oidc_*` — Grafana-дашборд, построенный вокруг этой
конвенции, чисто комбинируется с соседними AA-модулями. Опубликованные метрики:

| Метрика | Тип | Что считает |
|---|---|---|
| `aa_oidc_tokens_issued_total` | Counter | Успешные выпуски access/refresh/id-токенов (с labels `grant_type`, `format`) |
| `aa_oidc_authorize_denied_total` | Counter | Отказы на authorize-endpoint (label `reason`) |
| `aa_oidc_bcl_delivery_seconds` | Histogram | End-to-end latency одной BCL `logout_token`-доставки |
| `aa_oidc_bcl_dispatches_total` | Counter | Терминальные состояния BCL (success / retry-exhausted / dead-letter) |
| `aa_oidc_policy_rejections_total` | Counter | Отказы трёхслойной политики (label call-site: code / refresh / bearer / save) |
| `aa_oidc_code_reuse_audit_misses_total` | Counter | Вставки audit-row, проигравшие unique-index race |
| `aa_oidc_code_audit_skipped_total` | Counter | Code-flow exchange, прошедшие без audit-row (skip-путь) |
| `aa_oidc_tokens_cleaned_total` | Counter | Строки, удалённые `clear_expired_tokens` (DOT-токены + audit GC) |
| `aa_oidc_audit_receiver_failures_total` | Counter | Исключения в audit-receiver'ах, проглоченные до того, как они сломали бы signal chain |

Полный контракт — cardinality лейблов, layout buckets гистограмм, API no-op-заглушки и правила
cross-module namespacing `aa_<module>_*` — лежит в [docs/METRICS.ru.md](docs/METRICS.ru.md).

## Справочник

### Endpoint'ы

| Endpoint | Path | Замечания |
|---|---|---|
| Authorization | `/o/authorize/` | Policy-aware (трёхслойный gate). Перекрыт у нас. |
| Token | `/o/token/` | Audit-сигнал + безопасное debug-логирование. Перекрыт у нас. |
| UserInfo | `/o/userinfo/` | OIDC Core §5.3. Перекрыт у нас — добавляет `Cache-Control: no-store` и `Pragma: no-cache` по §5.3.2. |
| Discovery | `/o/.well-known/openid-configuration/` | OIDC Discovery 1.0 §3 / RFC 8414. Перекрыт у нас — отдаёт §3 RECOMMENDED-поля, которые DOT пропускает, плюс флаг `backchannel_logout_supported`. |
| JWKS | `/o/.well-known/jwks.json` | RFC 7517. Перекрыт у нас — добавляет `Access-Control-Allow-Origin: *`, чтобы браузерные RP могли получать JWKS cross-origin. |
| Token revocation | `/o/revoke_token/` | RFC 7009. Из DOT как есть. |
| Token introspection | `/o/introspect/` | RFC 7662. Перекрыт у нас — добавляет per-app gating и audit-сигнал `oidc_token_introspected`. |
| Token management UI | `/o/authorized_tokens/` (+ `/o/authorized_tokens/<pk>/delete/`) | Из DOT как есть. Позволяет залогиненному пользователю посмотреть свои активные токены и отозвать их. Без кастомизации. |
| RP-initiated logout | `/o/logout/` | DOT view; по умолчанию on через AppConfig (`OIDC_RP_INITIATED_LOGOUT_ENABLED=True` ставится, если ключ отсутствует). |
| Issuer (claim `iss`) | `https://your.host/o/` | Что отдаёт ваш discovery URL. |

### Claim'ы

Стандартные OIDC-claim'ы отдаются под привычными им scope'ами; AA-специфичные `groups` и
`eve_*` ездят на scope `profile` по умолчанию — RP'ы, которые и так запрашивают `openid profile`,
получают их без дополнительных настроек.

| Claim | Источник | Scope |
|---|---|---|
| `sub` | `User.pk` (DOT default) | `openid` |
| `email` | `user.email` | `email` |
| `email_verified` | Auto: `false` для синтетических плейсхолдеров (если установлен `aa-skip-email`); иначе зеркалит AA `REGISTRATION_VERIFY_EMAIL`. Force-override через `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`. | `email` (отдаётся в паре с `email`) |
| `acr` | `"0"` (RFC 6711 «no specific level»), когда клиент прислал `acr_values`; иначе отсутствует. | только id_token |
| `name` | `user.profile.main_character.character_name` | `profile` |
| `picture` | URL аватарки главного персонажа (см. `ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE`) | `profile` |
| `groups` | `user.groups[*].name`, плюс в конец дописывается `user.profile.state.name` | `profile` |
| `locale` | `user.profile.language` | `profile` |
| `eve_character_id` | `main_character.character_id` | `profile` (управляется через `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE`) |
| `eve_corporation_id` / `_name` / `_ticker` | `main_character.corporation_*` | то же |
| `eve_alliance_id` / `_name` / `_ticker` | `main_character.alliance_*` (не отдаётся для NPC-корпорации без альянса) | то же |
| `eve_faction_id` / `_name` | `main_character.faction_*` (не отдаётся, если у персонажа нет фракции) | то же |
| `eve_main_character_id` | алиас `eve_character_id` — нужен RP, которые также тянут claim'ы аутентифицированного персонажа | то же |
| `eve_affiliation` | составной `"<corp_ticker>[ / <alliance_ticker>]"` — для человекочитаемых логов | то же |

Префикс `eve_` настраивается. Пустые поля **не отдаются вовсе**, не как `null` — RP'ы, которые
проверяют `claim in payload`, ведут себя предсказуемо.

Claim `groups` ограничен **256 элементами** — это чтобы id_token влезал в типичный лимит 8 КБ
для заголовков и cookie. Имя state дописывается **после** обрезки, так что потребители, которые
рассчитывают на наличие state, не теряют его молча. Если 256 мало — наследуйтесь от
`AllianceAuthOAuth2Validator` и переопределите атрибут класса `MAX_GROUPS_IN_CLAIM`.

#### id_token vs /userinfo

По OIDC Core 1.0 §5.4 scope-привязанные claim'ы (всё из таблицы выше, кроме `sub`, `iss`, `aud`,
стандартных JWT-таймстампов, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`, `c_hash`,
`jti`) живут в `/userinfo` по умолчанию — внутри id_token они **не** едут. RP, которому они
нужны именно в id_token, должен явно запросить их через OIDC-параметр `claims`, например:
`claims={"id_token": {"email": null, "groups": null}}`. Так id_token остаётся компактным, и не
проявляется анти-паттерн «каждый claim везде», который ломает бюджеты заголовков и cookie.

### Audit-сигналы

`allianceauth_oidc.signals` публикует **пять** Django-сигналов (все с `use_caching=True`).
Дефолтные receiver'ы подключаются в `AppConfig.ready()` под стабильными `dispatch_uid`'ами —
тестовые наборы и операторы могут чисто `disconnect()`'ить их:

| Сигнал | Когда срабатывает | Дефолтный receiver |
|---|---|---|
| `oidc_token_issued` | Любой успешный выпуск access/refresh/id-токена | `audit_oidc_token_issued` |
| `oidc_code_reuse_detected` | Повторное предъявление уже обмененного authorization-code | `audit_oidc_code_reuse_detected` |
| `oidc_token_introspected` | Каждый запрос на RFC 7662 introspection | `audit_oidc_token_introspected` |
| `oidc_logout_required` | Lifecycle-событие, требующее BCL-fan-out (revoke / деактивация / смена группы или state / удаление аккаунта) | (audit-receiver'а нет — потребляется dispatch-task'ом) |
| `oidc_logout_dispatched` | Терминальное состояние BCL `logout_token` POST (success, retry-exhausted, dead-letter) | `record_backchannel_logout_attempt` |

Подключите свои receiver'ы, чтобы пушить это в SIEM, отдельную audit-таблицу или alerting:

```python
from django.dispatch import receiver
from allianceauth_oidc.signals import oidc_token_issued

@receiver(oidc_token_issued)
def forward_to_siem(sender, *, app, user, request, body, **kwargs):
    # body уже отредактирован (build_oidc_debug_meta); сырых секретов
    # сюда возвращать не надо.
    ...
```

Не наследуйтесь от `TokenView` ради этого — сигнал и есть документированная точка интеграции,
он переживает bump'ы DOT, которые меняют внутренности view'хи.

#### Семплирование высокочастотных audit-сигналов

`oidc_token_introspected` кидается на **каждый** запрос RFC 7662 introspection. Resource server'ы,
которые introspect'ят на каждый API-вызов, бьют по нему с request-rate — пробрасывать сырые
события в SIEM, который тарифицируется по объёму, очень дорого. Дефолтный receiver пишет одну
строку `INFO` на событие; SIEM-forwarder'ы должны семплировать или агрегировать, не пробрасывать
пассом:

```python
import secrets
from django.dispatch import receiver
from allianceauth_oidc.signals import oidc_token_introspected

# 1% reservoir-семплер; подберите под бюджет SIEM.
_SAMPLE_RATE = 0.01

@receiver(oidc_token_introspected, dispatch_uid="siem.introspect")
def forward_introspect_sampled(sender, *, request, introspector, body, **kwargs):
    if secrets.SystemRandom().random() > _SAMPLE_RATE:
        return
    # Пробрасываем `body` (отредактированный, без секретов — см.
    # OIDCIntrospectionAuditBody) + identity introspector'а. Сырые
    # значения токенов НИКОГДА не пробрасывайте.
    ...
```

`oidc_token_issued` и `oidc_code_reuse_detected` — низкочастотные (выпуск токена и факт
реального replay соответственно), для них pass-through нормален.

### Audit-таблицы

#### Audit-таблица повторного использования кодов

RFC 6749 §10.5 SHOULD-clause defence-in-depth: каждый успешный обмен authorization-code пишет
строку в `IssuedCodeAudit` (`code_hash`, `application`, `application_client_id_snapshot`,
`access_token_pk`, `refresh_token_pk`, `reuse_count`, `last_reuse_at`, `created_at`). При
повторной попытке предъявить тот же код `validate_code` отзывает связанные токены и кидает
`oidc_code_reuse_detected` для корреляции в SIEM. Колонка `application_client_id_snapshot`
заполняется при вставке строки и переживает админ-удаление RP (FK `application` —
`SET_NULL`), так что per-RP forensic-запросы по историческим строкам продолжают работать.

**Retention**:

- Строки с `reuse_count = 0` автоматически удаляются `clear_expired_tokens` после того, как
  они проживут дольше `OAUTH2_PROVIDER['REFRESH_TOKEN_EXPIRE_SECONDS']` — после этого код
  всё равно нельзя обменять ни на один токен, который AS согласится выпустить, так что
  audit-строка больше не несёт никакой ценности.
- Строки с `reuse_count >= 1` **сохраняются навсегда** — это форензическая улика попытки
  replay-атаки. Операторы чистят их вручную (admin → «Issued code audits») после закрытия
  incident-review окна.

Сигнал `oidc_code_reuse_detected` кидается на каждый replay, так что real-time корреляция в
SIEM работает без polling'а таблицы. Подключите свой receiver под уникальным `dispatch_uid`,
чтобы маршрутизировать reuse-события через alerting pipeline.

#### Audit-таблица back-channel logout

`BackChannelLogoutAttempt` — dead-letter / proof-of-delivery хранилище BCL-диспатчера.
Колонки: `application` (FK, `SET_NULL`), `application_client_id_snapshot`,
`application_name_snapshot`, `user_pk`, `jti`, `success`, `attempt_count`, `reason`,
`created_at`. Snapshot-колонки переживают admin-удаление RP — per-RP forensic-запросы по
историческим строкам продолжают работать. Видно в `/admin/` под «Back channel logout attempts».

По умолчанию сюда попадают только **проваленные** попытки — таблица строго dead-letter.
Установите `ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True`, чтобы сохранять и успешные доставки
(proof-of-fan-out для SIEM). Сигнал `oidc_logout_dispatched` кидается на каждое терминальное
состояние независимо, поэтому real-time SIEM-корреляция работает без polling'а.

Контракт retry / dead-letter — в [docs/BACK_CHANNEL_LOGOUT.ru.md](docs/BACK_CHANNEL_LOGOUT.ru.md).

### Поля приложения

Помимо схемы DOT'овского `AbstractApplication`, `AllianceAuthApplication` добавляет:

- `states` (M2M) и `groups` (M2M) — whitelist доступа; пусто = открыто для всех.
- `active` — `is_usable()` возвращает это значение; деактивированное приложение не выдаёт коды.
- `debug_mode` — per-app флаг повышенного уровня логов (см. *Debug-логи*).
- `pkce_required` — per-app форсирование PKCE; читается через
  `pkce.per_app_pkce_required` (делегирует в `AccessPolicy.requires_pkce`).
- `access_token_format` — per-app override wire-формата access-токена
  (`"opaque"` / `"jwt"` / пусто). Пустое значение наследует deployment-wide
  `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT` (по умолчанию `"opaque"`).
  См. [JWT-токены доступа](#jwt-токены-доступа-rfc-9068).
- `backchannel_logout_uri` — RP-endpoint, принимающий подписанные `logout_token` POST'ы
  (OIDC BCL 1.0). Валидируется SSRF-гейтом в `_validate_backchannel_logout_uri` на каждом save.
- `backchannel_logout_on_revoke_only` — если включено, lifecycle-триггеры (деактивация, смена
  групп/state, удаление аккаунта) пропускают этот RP; fan-out делает только
  `oidc_revoke_user_tokens`.
- `logo_url`, `allowed_origins` — operator-facing-дополнения, поставляемые миграциями
  0004/0007.

## Эксплуатация

### Сервисные команды

Шесть `manage.py`-команд закрывают повседневные задачи обслуживания — без необходимости
лезть в admin-UI. Все, у которых вывод структурирован, понимают `--format=table|json|csv`;
у деструктивных есть `--dry-run`.

| Команда | Зачем | Деструктивная? | Ключевые флаги |
|---|---|---|---|
| `oidc_create_app` | Завести новое OIDC-приложение неинтерактивно (CI / Ansible). Печатает «сырой» `client_secret` один раз. | да | `--name`, `--user-id`, `--redirect-uri`, `--state`, `--group`, `--client-type`, `--grant-type`, `--debug-mode` |
| `oidc_rotate_secret` | Перегенерировать `client_secret`. Уже выпущенные токены живут до своего истечения. | да | `--client-id`, `--dry-run` |
| `oidc_revoke_user_tokens` | Отозвать все access + refresh у пользователя (offboarding, реакция на компрометацию). Идемпотентно. | да | `--username`, `--reason`, `--dry-run` |
| `oidc_audit_tokens` | Read-only список активных токенов. | нет | `--username`, `--client-id`, `--include-expired` |
| `oidc_jwks_rotate` | Сгенерировать свежий RSA-ключ для ротации JWKS; печатает PEM + RFC 7638 thumbprint (`kid`) + четырёхшаговый recipe ротации. **Read-only** — не трогает ни settings, ни БД; оператор сам прописывает новый PEM в `OIDC_RSA_PRIVATE_KEY` и переносит предыдущий в `OIDC_RSA_PRIVATE_KEYS_INACTIVE`. | нет | `--out`, `--key-size` |
| `oidc_show_effective_policy` | Посмотреть per-app state/group whitelist в том виде, в котором он применяется к конкретному пользователю, включая глобальный gate. Полезно при триаже неожиданного `invalid_grant`. | нет | `--username`, `--client-id` |

```sh
python manage.py oidc_create_app \
    --name="Grafana" --user-id=1 \
    --redirect-uri="https://grafana.example/login/generic_oauth" \
    --state=Member --group=Operators --format=json

python manage.py oidc_rotate_secret --client-id=abc123 --dry-run
python manage.py oidc_revoke_user_tokens --username=alice
python manage.py oidc_audit_tokens --client-id=abc123 --format=csv
```

`oidc_create_app` ещё пишет запись в Django admin `LogEntry` — действие сразу видно в истории
`/admin/` без правок в коде. Деструктивные команды логируются на `INFO` / `WARNING`.

### Per-app PKCE

`AllianceAuthApplication.pkce_required` — per-app boolean, переключается через Django admin
(колонка в changelist'е, чекбокс на форме редактирования, list filter). DOT читает значение на
каждом authorize-запросе через callable `per_app_pkce_required`, прописанный в
`OAUTH2_PROVIDER`.

- **Новые приложения** по умолчанию `True` (RFC 9700, secure-by-default).
- **Существующие приложения после апгрейда** заполняются миграцией значением прошлой глобальной
  настройки `OAUTH2_PROVIDER['PKCE_REQUIRED']`. Если был глобальный `False` — все строки получат
  `False`; если `True` — все строки получат `True`. Дальше включайте/отключайте per-app через
  admin.
- **Неизвестный `client_id`** (нет совпадения среди зарегистрированных приложений) даёт `True` с
  записью `WARNING` в лог — аномальный трафик сразу заметен в audit'е.
- **Кэш не используется** — каждый authorize-запрос делает один SELECT, ограниченный одним
  столбцом `pkce_required`.

> **Переключение `pkce_required` не влияет на уже выпущенные authorization-коды.** Код несёт
> PKCE-контракт момента выпуска; обмен на токен проверяет тот же контракт. Если оператор переключает
> флаг во время идущего flow — это не делает уже выпущенный код задним числом ни безопаснее, ни
> уязвимее.
>
> **Предупреждение миграции про non-boolean global.** Если `manage.py migrate` поднимает
> Python `RuntimeWarning` с текстом вида
> `OAUTH2_PROVIDER['PKCE_REQUIRED'] is <type> (expected bool); backfilling pkce_required=True`,
> значит в `local.py` уже был задан кастомный resolver, **либо** вы заменили `PKCE_REQUIRED` на
> callable `per_app_pkce_required` до запуска migrate (правильный порядок —
> в разделе [Обновление с предыдущей версии](#обновление-с-предыдущей-версии)), **либо** ключ
> отсутствует / равен `None`. Любое non-boolean значение неоднозначно, поэтому миграция падает
> в RFC 9700 secure-by-default — всем существующим приложениям проставляется `True`, а
> глобальная настройка остаётся нетронутой. После миграции пройдитесь по приложениям через
> admin и поправьте per-app значения. Свежие установки (без существующих строк) предупреждение
> пропускают.

**Массовые операции.** Одиночные переключения удобно делать через admin; на >5 приложений
быстрее через ORM:

```python
# manage.py shell
from allianceauth_oidc.models import AllianceAuthApplication

# Отключить PKCE для всех приложений с префиксом в имени:
AllianceAuthApplication.objects.filter(
    name__startswith="Legacy-"
).update(pkce_required=False)

# Или по списку client_id:
AllianceAuthApplication.objects.filter(
    client_id__in=["abc", "def"]
).update(pkce_required=False)
```

`QuerySet.update()` не вызывает `Model.save()` — то есть проходит мимо `pre_save` / `post_save`
сигналов и не пишет запись в Django admin `LogEntry` на каждую затронутую строку. Это
осознанный компромисс: bulk-обновление атомарно и быстро. Если нужен audit trail —
пройдитесь по `.all()` и вызовите `instance.save(update_fields=["pkce_required"])` для
каждой записи, либо оставьте однострочную пометку в вашем operations log с указанием фильтра
и времени.

Обратное направление идентично (`pkce_required=True`). Для *новых* приложений, создаваемых
через CLI вместо admin, `oidc_create_app --no-pkce-required` сразу выставляет нужное значение
без последующего визита в admin; default — `True`.

### JWT-токены доступа (RFC 9068)

Access-токены по умолчанию — непрозрачные случайные строки. Оператор может
включить токены формата [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)
глобально или для отдельных приложений, когда нижестоящие RP (oauth2-proxy,
mod_auth_openidc, WikiJS, кастомные сервисы) предпочитают валидировать токен
локально без round-trip'a в /o/introspect/. JWT-режим **opt-in** и
**stateful**: JWT хранится в `oauth2_provider_accesstoken.token`, поэтому
revoke / introspect / audit продолжают работать.

Активируйте, прописав две настройки в `OAUTH2_PROVIDER`:

```python
OAUTH2_PROVIDER = {
    # ... ваши обычные настройки ...
    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
    "ACCESS_TOKEN_GENERATOR": (
        "allianceauth_oidc.tokens.dispatching_access_token_generator"
    ),
    # Рекомендация при активации JWT-режима: уменьшить срок жизни
    # access-токена, чтобы ограничить окно PII-at-rest в таблице
    # AccessToken. См. секцию "Data minimization" в
    # docs/JWT_ACCESS_TOKENS.ru.md.
    "ACCESS_TOKEN_EXPIRE_SECONDS": 300,  # 5 минут; раньше было 3600
}
```

> [!IMPORTANT]
> Нужны обе настройки. `ACCESS_TOKEN_GENERATOR` принимает dotted-path строку,
> потому что эта настройка входит в `IMPORT_STRINGS` DOT — DOT резолвит путь
> на старте. `PKCE_REQUIRED` НЕ входит в `IMPORT_STRINGS` и поэтому требует
> ссылку на функцию. Если выставлен только
> `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt"` без
> `ACCESS_TOKEN_GENERATOR`, JWT-режим не включится, а
> `AllianceAuthOIDC.ready()` напишет в лог `WARNING` о
> неполной конфигурации. Проверка только логирует — старт никогда не падает
> из-за битого dotted-path.

**Per-app override.** У каждого `AllianceAuthApplication` есть необязательное
поле `access_token_format` (`"opaque"` / `"jwt"` / пусто). Пустое значение
наследует глобальный default. Это позволяет сначала переключить один
некритичный RP, проверить и только потом править глобал. Поле редактируется
через Django admin.

**Маппинг claim'ов.** Identity-claim'ы (`email`, `name`, `groups`, `eve_*`,
…) проходят через ту же scope-gating-машинерию, что и id_token — через
канонический хук DOT `get_oidc_claims`. AT и id_token дают идентичный набор
claim'ов для одного и того же набора scope. Поверх добавляются framing-claim'ы
RFC 9068 (`typ="at+jwt"`, `aud=client_id`, `client_id`, `exp`, `iat`, `jti`,
`scope`). Подпись — `RS256` ключом `OIDC_RSA_PRIVATE_KEY`, публикуемый
`kid` — это RFC 7638 thumbprint ключа.

**Сценарий миграции per-app → глобал, RP cookbook, дисциплина ротации ключей,
data-minimization, troubleshooting** — см.
[docs/JWT_ACCESS_TOKENS.ru.md](docs/JWT_ACCESS_TOKENS.ru.md). Рецепт в §7
проводит по рекомендованной последовательности (сначала per-app, потом
глобал) и указывает на `manage.py oidc_audit_tokens --include-expired`,
где колонка `format` позволяет проверить wire-формат каждого токена со
стороны оператора.

### Back-channel logout (OIDC BCL 1.0)

Sub-only [back-channel logout](docs/BACK_CHANNEL_LOGOUT.ru.md)
встроен. Задайте `backchannel_logout_uri` у приложения, чтобы
включить per-RP fan-out; AS POST'ит подписанный `logout_token`
каждый раз, когда сессия завершается (revoke / деактивация /
смена группы или state / удаление аккаунта). Пять триггерных
точек покрывают реальные операторские workflow'ы. SSRF-защиты
(host DNS check с 3-секундным wall-clock'ом, scheme allow-list,
`allow_redirects=False`), spec-compliant `events` URI и
secret-pin регрессия на каждой log-строке держат dispatch-путь
безопасным. Session-scoped logout (`sid`) намеренно отложен до
следующей feature-итерации.

`OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` обязателен, как только
хотя бы у одного RP появляется `backchannel_logout_uri` — у
Celery worker'а нет HTTP request context. Django system check
(`allianceauth_oidc.E001`, severity `Error`) проваливает
`manage.py check` на деплое, если настройка отсутствует.

### System checks (`manage.py check`)

Провайдер регистрирует шесть ошибок и пять предупреждений во
фреймворке системных проверок Django. CI должен падать на ошибках и
обращать внимание на предупреждения как на configuration smells.

| ID | Severity | Триггер | Действие оператора |
|---|---|---|---|
| `allianceauth_oidc.E001` | Error | У приложения задан `backchannel_logout_uri`, но `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` не выставлен. | Задайте `OIDC_ISS_ENDPOINT` абсолютный URL issuer'а. Celery worker, который POST'ит `logout_token`'ы, не имеет HTTP request context, поэтому не может вывести `iss` в runtime — без этой настройки первый же logout-диспатч упадёт. |
| `allianceauth_oidc.E002` | Error | `OAUTH2_PROVIDER_APPLICATION_MODEL` не разрешается в `AllianceAuthApplication` (или подкласс). | Установите `OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"`. Stock DOT-модель обходит трёхслойную policy-enforcement — любой залогиненный пользователь сможет аутентифицироваться против любого зарегистрированного приложения. |
| `allianceauth_oidc.E003` | Error | `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']` не разрешается в `AllianceAuthOAuth2Validator` (или подкласс). | Установите `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] = "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"`. Stock DOT-валидатор пропускает слои 2 и 3 policy-gate'а (`validate_code` / `validate_refresh_token` / `save_bearer_token`) — code-flow обмены и refresh-grant перестают перепроверять state/group membership. |
| `allianceauth_oidc.E004` | Error | `OAUTH2_PROVIDER['SCOPES']` не содержит scope `openid`. | Добавьте `"openid"` в словарь `SCOPES`. Дефолтная DOT-карта `{"read": ..., "write": ...}` молча выключает выдачу id_token — discovery всё ещё резолвится и access-токены всё ещё минтятся, но OIDC RP'и падают на token endpoint'е с `invalid_scope` или получают token response без `id_token`. |
| `allianceauth_oidc.E005` | Error | `OAUTH2_PROVIDER['PKCE_REQUIRED']` не является (и не оборачивает) `allianceauth_oidc.pkce.per_app_pkce_required`. Без адаптера DOT использует собственный резолвер, и per-app override `pkce_required=False` молча no-op'ит. Public-клиенты, выпущенные через этот разрыв, уязвимы к перехвату auth-code (RFC 9700 PKCE BCP). | Поставьте `OAUTH2_PROVIDER['PKCE_REQUIRED'] = per_app_pkce_required` (именно **объект функции**, не dotted-путь — DOT не импортирует эту настройку). |
| `allianceauth_oidc.E006` | Error | Опасная комбинация со конкретной жертвой: `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` И `DEBUG=False` И хотя бы у одного `AllianceAuthApplication` непустой `backchannel_logout_uri`. Подписанные `logout_token` JWT уходили бы на private-IP-таргеты в production-shaped окружении. | Установите `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=False` в проде. Чтобы явно принять trade-off на изолированном лабе / air-gapped staging'е, дополнительно установите `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True` — оба переключателя должны быть выставлены, чтобы опасный путь работал без ошибки. |
| `allianceauth_oidc.W001` | Warning | `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True` при `DEBUG=False`. Логирование маскированных фрагментов (`he…il`) — development aid; в production-shaped окружении это утекает в log-stream идентифицируемые префиксы/суффиксы access/refresh-токенов и клиентских secret'ов. | Установите флаг `False` (или удалите) в проде. Оставляйте `True` только на изолированных staging-хостах, где trade-off осознанный. |
| `allianceauth_oidc.W002` | Warning | `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT='jwt'`, но `ACCESS_TOKEN_GENERATOR` указывает не на наш dispatching generator (JWT-режим молча неактивен), ЛИБО dispatcher подключён, но default format не выставлен в `'jwt'` (per-app override работает, но глобальный default — нет). | Включите `OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] = "allianceauth_oidc.tokens.dispatching_access_token_generator"`. Обе половины должны быть согласованы, чтобы JWT был глобальным дефолтом. |
| `allianceauth_oidc.W003` | Warning | `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` явно `False`, при том что у одного или нескольких приложений выставлен `backchannel_logout_uri`. Single-Logout chain рвётся на первом hop'е, потому что RP-initiated logout — точка входа, которая триггерит back-channel fan-out. | Либо снимите `backchannel_logout_uri` с затронутых приложений (перечислены в тексте warning'а), либо включите RP-initiated logout обратно (по умолчанию он on — задайте `True` или уберите явный `False`). |
| `allianceauth_oidc.W004` | Warning | У одного или нескольких **активных** приложений `backchannel_logout_uri` использует `http://` при `DEBUG=False`. Admin-форма блокирует новые `http://` URI в проде, но legacy-строки, сохранённые при `DEBUG=True`, переживают переключение. Воркер re-checks DNS, но не схему — `logout_token` JWT (с `iss`/`aud`/`sub`/`jti`) продолжает уходить cleartext'ом. | Замените URI на `https://` либо деактивируйте строку, если RP уже выведен из эксплуатации. |
| `allianceauth_oidc.W005` | Warning | `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` при `DEBUG=False` (но без зарегистрированного `backchannel_logout_uri`, который триггерит E006). SSRF-гейт на back-channel logout target'ы отключён — если private-IP URI будет зарегистрирован позже, воркер POST'нет подписанные `logout_token`'ы на `127.0.0.1` / `169.254.169.254` / k8s overlay / CGNAT IP. | Поставьте флаг `False` (или удалите) в проде. Оставляйте `True` только на dev / staging хостах, которые осознанно указывают на private RP. |

ID проверок стабильны между релизами; mute через
`SILENCED_SYSTEM_CHECKS` поддерживается, но не рекомендуется — лучше
поправить конфигурацию, чтобы следующий оператор не наступил на тот
же drift.

### Локальное тестирование на приватной сети

Два переключателя позволяют прогнать полный BCL-flow против RP,
которые резолвятся в приватные адреса (типичные dev / staging на
`192.168.x.x`, `10.x.x.x`, k8s overlay, CGNAT `100.64.0.0/10`).

| Настройка | Эффект |
|---|---|
| `DEBUG = True` | Admin-форма принимает `http://` BCL URI. `W001`, `W004`, `W005` молчат. |
| `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True` | Оба DNS-гейта (admin save И воркер re-check при диспатче) сразу `return True`; private / loopback / link-local / multicast / reserved / CGNAT target'ы проходят. |

Типичные конфигурации:

```python
# Dev на localhost / LAN — тихо, BCL работает полностью
DEBUG = True
ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True
```

```python
# Staging на k8s overlay (10.244.x.x, 100.64.x.x) — работает, W005 виден
DEBUG = False
ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True
```

`W005` в staging-варианте — **информационный**, не блокирующий:
делает выбор «я осознанно принимаю SSRF-риск в этой среде» видимым
на каждом `manage.py check`. Та же позиция у `W001` (masked-secret
логи) и `W004` (`http://` BCL): предупреждения, а не ошибки.

### Debug-логи

Per-application `Debug Mode` (включается в админке) поднимает уровень token-flow логов с `DEBUG`
до `INFO`. «Сырые» значения токенов и секретов **никогда** не логируются; настройка
`_LOG_MASKED_SECRETS` (см. [Свои настройки](#свои-настройки-allianceauth_oidc_)) определяет, как
они выводятся: как `<redacted>` или как маскированные фрагменты.

При отладке приложения смотрите строки вроде:

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views_token:204] OIDC DEBUG token issued
app_id=1 client_id=abc123 user_id=42
meta={'grant_type': 'authorization_code', ..., 'access_token': '<redacted>', 'id_token': '<redacted>'}
```

Сам `id_token` (захваченный отдельно, не из лога) можно вставить на <https://jwt.io/>, чтобы
посмотреть claim'ы. Два неочевидных поля:

- `iss` — issuer; должен **точно** совпадать с тем, что прописано в настройках самого RP.
- `sub` — PK пользователя; помогает на триаже «откуда здесь именно этот юзер».

Если для проверки подписи на jwt.io нужен публичный ключ, а на диске только приватный:

```sh
ssh-keygen -y -e -m pem -f /path/to/key
```

### Усиление безопасности — на стороне деплоя

Провайдер реализует протокольную часть OAuth2 / OIDC; runtime-обвязка ниже намеренно
оставлена деплою — чтобы она органично легла на ваш edge / инфраструктуру.

- **Rate-limit на `/o/token/` и `/o/authorize/`.** Встроенного нет ни на одном из endpoint'ов.
  Защита от brute-force — это либо edge (nginx `limit_req`, Cloudflare, WAF), либо
  `django-ratelimit` в самом Auth. Без неё атакующий с сетевым доступом будет долбить
  `client_secret` / `code` / `refresh_token` на полной скорости канала.
- **Аутентификация Celery-брокера.** Задача `clear_expired_tokens` публикуется в Celery-брокер
  вашего AA. Если брокер доступен извне без аутентификации — недоверенный клиент может
  многократно дёргать чистку. Сама задача идемпотентна, ущерба нет, но защита здесь — broker
  auth + сетевые ACL.
- **Security-заголовки.** Приложение не выставляет CSP / HSTS / X-Frame-Options /
  X-Content-Type-Options. На это есть middleware-стек Alliance Auth и `SECURE_*`-настройки
  Django — выставляйте их глобально, не на уровне нашего модуля.

## Интеграции с RP

### Зарегистрировать приложение

В `/admin/allianceauth_oidc/` создайте `Alliance Auth application`:

| Поле | Значение | Замечания |
|---|---|---|
| `User` | любой (например `1`) | Владелец — пробрасывается в DOT, в нашей политике не используется. |
| `Client type` | `confidential` | Public-клиенты вне scope'а — рецепта для них мы не даём. |
| `Authorization grant type` | `Authorization code` | Единственный flow, под который заточена политика. |
| `Client secret` | сгенерируется | Сохраните **до** нажатия save (если включён `HASH_CLIENT_SECRET`, а это default). |
| `Algorithm` | `RSA with SHA-2 256` | Должно совпадать с `OIDC_RSA_PRIVATE_KEY`. |
| `States` / `Groups` | whitelist | Пустые — открыто всем; непустые — пользователю нужен или один из state, или одна из групп. |

Каждый, кто логинится в любое зарегистрированное приложение, ещё должен иметь глобальное право
`allianceauth_oidc.access_oidc`. Без него гейт первого слоя возвращает `PermissionDenied`
независимо от того, что в state / group whitelist'ах.

### Grafana

Проверено без маппинга групп (Group → Team — это уже Grafana Cloud / Enterprise, выходит за
рамки этого документа).

```ini
[server]
root_url = <URL вашего Grafana>

[auth.generic_oauth]
enabled = true
name = <имя auth>
allow_sign_up = true
client_id = <client_id>
client_secret = <нехешированный client_secret>
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://<your.auth.url>/o/authorize/
token_url = https://<your.auth.url>/o/token/
api_url = https://<your.auth.url>/o/userinfo/
```

### WikiJS

В WikiJS два совместимых способа подключения: **Generic OpenID Connect / OAuth 2.0** (строгий OIDC,
проверяет подпись `id_token` через JWKS) и **Generic OAuth 2.0** (без проверки `id_token`, всё
из `/userinfo`). Оба работают с этим провайдером; OIDC-режим предпочтительнее — берите его, если
у вас нет редких ситуаций вроде нестандартного `iss`, ротации JWKS или расхождения часов между
серверами.

В auth заранее заведите группы, в которые WikiJS будет распределять пользователей при логине
(например, `Administrators` — чтобы выдать кому-то полный доступ к админке wiki).

| Поле WikiJS | Значение |
|---|---|
| Authorization Endpoint URL | `https://auth.example.com/o/authorize/` |
| Token Endpoint URL | `https://auth.example.com/o/token/` |
| User Info Endpoint URL | `https://auth.example.com/o/userinfo/` |
| Issuer | то, что отдаёт поле `issuer` из `https://auth.example.com/o/.well-known/openid-configuration` — копируйте дословно, включая или исключая слэш в конце; строгие валидаторы рубят запрос на любом расхождении |
| Skip User Profile | **off** — см. предупреждение ниже |
| Logout URL *(опционально)* | `https://auth.example.com/o/logout/` |
| Client ID | `<client_id>` из админки `AllianceAuthApplication` |
| Client Secret | `<client_secret>` из админки `AllianceAuthApplication` |
| Scopes | `openid profile email` |
| User ID Claim | `sub` |
| Email claim | `email` |
| Display Name Claim | `name` |
| Avatar Claim | `picture` |
| Map Groups | on |
| Groups Claim | `groups` |
| Allow Self Registration | on |

> **Тоггл «Skip User Profile» оставляйте выключенным.** Если его включить, WikiJS читает данные
> профиля только из `id_token` и не ходит на `/userinfo`. Этот провайдер реализует OIDC Core
> 1.0 §5.4 буква в букву: `email`, `name`, `picture`, `groups`, `locale` отдаются **только**
> через `/userinfo` и никогда не попадают в `id_token`. С включённым «Skip User Profile» WikiJS
> упадёт на этапе создания пользователя с ошибкой *«Missing or invalid email address from
> profile»*.
>
> **Не задавайте `ACCESS_TOKEN_EXPIRE_SECONDS` слишком маленьким.** WikiJS после обмена кода
> на токен делает ещё один запрос — на `/userinfo`. С `clockTolerance` ~5 секунд и реальной
> сетевой задержкой токен короче ~30 секунд на практике уже не успевает дожить до второго
> запроса, и `/userinfo` отвечает 401. Держите рекомендованные `3600` (см. таблицу
> [ключей `OAUTH2_PROVIDER`](#ключи-oauth2_provider)).

## Разработка

### Сессии nox

| Сессия | Зачем | Гоняется по умолчанию (`nox`)? |
|---|---|---|
| `lint` | pre-commit (ruff, mypy, basedpyright, …) | да |
| `tests` | Django-тесты (параллельно) | да |
| `coverage` | тесты + term / HTML / XML coverage | нет |
| `typecheck` | mypy + basedpyright (подмножество `lint`, отдельно — для быстрой обратной связи) | нет |
| `audit` | pip-audit | нет |
| `markdown_lint` | rumdl + lychee + vale (каждый инструмент опционален) | нет |
| `makemessages` / `compilemessages` | i18n: обновление .po и компиляция в .mo | нет |
| `makemigrations` | генерация миграций Django под тестовыми settings | нет |
| `integration` | mock-RP по проводу через `LiveServerTestCase` | нет |
| `conformance` | OIDC Conformance Suite через docker-compose | нет |
| `preflight` | `lint` + `typecheck` + `tests` + `migrations_check` подряд (pre-PR-гейт) | нет |
| `tests_matrix` | прогон тестов по всем поддерживаемым Python (off-lock, uv venv) | нет |
| `tests_aa4` | прогон тестов на стеке Alliance Auth 4.x | нет |
| `tests_compat` | прогон тестов с произвольным пином `allianceauth` | нет |
| `migrations_check` | проверка, что миграции согласованы и не содержат опасных операций | нет |
| `actions_lint` | линт GitHub Actions workflows (`actionlint`) | нет |
| `diagrams` | рендер diagram-as-code из `assets/diagrams/` в SVG | нет |
| `verify_wheel` | сборка wheel во временный каталог и аудит содержимого | нет |
| `mutation` | мутационное тестирование production-модулей через cosmic-ray | нет |
| `mutation_parallel` | возобновление частичного прогона cosmic-ray в N воркеров | нет |
| `mutation_html` | рендер HTML-отчёта cosmic-ray из `mutation.sqlite` | нет |
| `mutation_check` | gate CI по доле выживших мутантов в `mutation.sqlite` | нет |

У сессий `mutation*` свой setup / resume / report-rendering recipe в
[docs/mutation-testing.md](docs/mutation-testing.md).

### Интеграционные тесты (`nox -s integration`)

`tests/test_integration_mock_rp.py` поднимает `LiveServerTestCase`, прогоняет OIDC code-flow
через `requests` + `jwcrypto` и проверяет подпись id_token по JWKS, полученным по сети. Так
ловятся регрессии, до которых стандартный `nox -s tests` не дотягивается: Django test client
пропускает WSGI-слой, и баги в абсолютных URL (`iss`, `jwks_uri`), Bearer-заголовках и cookie
всплывают только здесь.

Сессия форсит `--parallel=1`: `LiveServerTestCase` шарит DB-соединение с WSGI-потоком, а это не
переживает `fork()` test runner'а.

### Conformance Suite (`nox -s conformance`)

Гоняет [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite) против
нашего провайдера в docker-compose-стеке: MongoDB + Suite + контейнер с провайдером. План по
умолчанию заводится через REST-API Suite — это делает `tests/conformance/run_plan.py`.

Это уровень выше наших регрессионных тестов: ловит ровно те edge-cases спецификации, до которых
мы сами не додумаемся. Запускайте перед тегированием релиза. Детали — prerequisites, ручной /
итеративный сценарий, override'ы настроек и список уже найденных conformance-проблем для
триажа — лежат в [tests/conformance/README.md](tests/conformance/README.md).
