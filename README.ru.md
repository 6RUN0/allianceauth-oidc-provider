# allianceauth_oidc

> Это форк
> [Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider).
> Живёт в
> [6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) и
> добавляет: HTTP-уровень интеграционных тестов, обвязку OIDC Conformance Suite, операторские
> CLI-команды, EVE-специфичные claim'ы в id_token и userinfo, локализацию (en / ru / uk) и
> английский [README.md](README.md).

## Allianceauth OIDC Provider

## Что умеет

- OIDC / OAuth2
  - Доступные scope:
    - openid
    - email
    - profile — добавляет claim `groups`: все группы пользователя плюс его state списком строк
- Доступ к приложению — три независимых правила:
  - глобальное право `access_oidc`
  - whitelist по state
  - whitelist по группам

## Code flow и три слоя проверок

Каждый обмен `authorization_code` проходит три независимых ворот. Любые упростить — значит открыть
дыру; именно поэтому в регрессии есть тесты под каждый слой по отдельности.

```mermaid
sequenceDiagram
    participant RP as Relying Party
    participant Auth as /o/authorize/
    participant DOT as django-oauth-toolkit
    participant Token as /o/token/
    participant Validator as AllianceAuthOAuth2Validator

    RP->>Auth: GET / POST authorize (response_type=code)
    Note over Auth: Слой 1 — dispatch()<br/>глобальный access_oidc<br/>+ whitelist по state/группам
    Auth->>DOT: forward (если политика прошла)
    DOT-->>RP: 302 ?code=<code>
    RP->>Token: POST code + client_secret
    Token->>Validator: validate_code(code, request)
    Note over Validator: Слой 2 — повторная проверка<br/>state/групп при обмене
    Validator-->>Token: ok / invalid_grant
    Token->>Validator: save_bearer_token(...)
    Note over Validator: Слой 3 — последний guard;<br/>PermissionDenied → invalid_grant
    Validator-->>RP: 200 access_token + id_token
```

## Пример

![Imgur](https://i.imgur.com/gcrFcRL.png)

## Установка

1. Поставьте форк прямо из git. Имя пакета на PyPI занято апстримом, поэтому ставим по VCS-URL,
   а не `pip install allianceauth-oidc-provider`:

   ```sh
   pip install "git+https://github.com/6RUN0/allianceauth-oidc-provider.git@current"
   ```

1. Добавьте в `INSTALLED_APPS` в `local.py`

   ```python
   INSTALLED_APPS += [
       # другие ваши приложения #
       'allianceauth_oidc',
       'oauth2_provider',
       # другие ваши приложения #
   ]
   ```

1. Дополнительные настройки

   ```python

   # в начале файла
   from pathlib import Path

   # добавить ниже
   if 'allianceauth_oidc' in INSTALLED_APPS and 'oauth2_provider' in INSTALLED_APPS:
       OAUTH2_PROVIDER_APPLICATION_MODEL='allianceauth_oidc.AllianceAuthApplication'
       OAUTH2_PROVIDER = {
           # https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key
           "OIDC_ENABLED": True,
           # ваш приватный ключ
           "OIDC_RSA_PRIVATE_KEY": Path("/path/to/key/file").read_text(),
           "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
           "SCOPES": {
               "openid": "User Profile",
               "email": "Registered email",
               "profile": "Main Character affiliation and Auth groups"
           },
           # PKCE обязателен для public-клиентов по RFC 9700 (OAuth 2.0
           # Security BCP) и рекомендован для confidential. Отключайте
           # только если знаете, что все клиенты поддерживают PKCE.
           "PKCE_REQUIRED": True,
           "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
           'ACCESS_TOKEN_EXPIRE_SECONDS': 60,
           'REFRESH_TOKEN_EXPIRE_SECONDS': 24*60*60,
           # Ротировать refresh-токены при каждом использовании +
           # детектировать переиспользование — если refresh-токен
           # предъявлен дважды, DOT отзовёт всё семейство токенов
           # (RFC 6819 §5.2.2.3, защита от replay).
           'ROTATE_REFRESH_TOKEN': True,
           'REFRESH_TOKEN_REUSE_PROTECTION': True,
       }
   ```

   Подробнее о генерации и хранении приватного ключа —
   [в документации DOT](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key).
1. Подключите endpoints в `urls.py`

   ```python
   from .settings.local import INSTALLED_APPS

   # ...
   # ваши импорты и urlpatterns
   # ...

   if "allianceauth_oidc" in INSTALLED_APPS and "oauth2_provider" in INSTALLED_APPS:
       urlpatterns.append(
           path(
               "o/",
               include("allianceauth_oidc.urls", namespace="oauth2_provider"),
           )
       )
   ```

1. примените миграции
1. перезапустите auth

## Опциональные настройки (по необходимости)

### Маскирование секретов в debug-логах

«Сырые» токены и секреты в логи не попадают никогда. Если у приложения включён _Debug Mode_, в
логах появляются дополнительные debug-метаданные, но сами секреты по-прежнему скрыты — пока вы
явно не разрешите маскированный вывод.

Опционально в settings:

```python
# False (по умолчанию) — секреты в логах как "<redacted>".
# True — секреты как маскированные фрагменты (head…tail).
ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS = False

# Сколько символов показывать с каждой стороны при маскировке.
ALLIANCEAUTH_OIDC_LOG_MASK_HEAD = 2
ALLIANCEAUTH_OIDC_LOG_MASK_TAIL = 2
```

Маскированное логирование имеет смысл только тогда, когда у логов есть нормальное разграничение
доступа.

### EVE-специфичные claim'ы (`eve_*`)

Помимо стандартного OIDC-набора, провайдер кладёт в токен данные из доменной модели Alliance Auth:
персонажа / корпорацию / альянс — всё это берётся с main-character пользователя. Префикс по
умолчанию `eve_`, scope `profile` (то есть приходит «бесплатно» вместе с `openid profile`,
который RP'ы и так почти всегда запрашивают).

| Claim | Откуда берётся | Замечания |
|---|---|---|
| `eve_character_id` | `main_character.character_id` | EVE ID, целое число |
| `eve_corporation_id` / `_name` / `_ticker` | `main_character.corporation_*` | Денормализовано прямо на персонаже |
| `eve_alliance_id` / `_name` / `_ticker` | `main_character.alliance_*` | У NPC-корпорации без альянса claim просто не появится |

Если нужно переопределить префикс или scope:

```python
# По умолчанию `eve_`. Пустая строка уберёт префикс совсем
# (внимание — повышает риск коллизии имён); любой другой префикс
# можно использовать для разделения namespace'ов между несколькими
# провайдерами.
ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX = "eve_"

# По умолчанию `profile`. Поставьте, например, `eve` — и RP будет
# обязан явно запросить этот scope. Учтите: привязка к scope
# class-level, после смены настройки нужен перезапуск Auth.
ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE = "profile"
```

Пустые значения **не отдаются вовсе**, а не приходят как `null`. Так RP'ы, которые проверяют
`claim in payload`, ведут себя предсказуемо.

### URL аватарки (`picture` claim)

`picture` по умолчанию указывает на официальный EVE image-server. Если он спрятан за CDN или
нужен другой размер — переопределите настройки:

```python
# По умолчанию:
# "https://images.evetech.net/characters/{character_id}/portrait?size={size}"
ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE = "https://cdn.example/portraits/{character_id}-{size}.png"

# EVE image-server поддерживает 32/64/128/256/512/1024. По умолчанию 128.
ALLIANCEAUTH_OIDC_PORTRAIT_SIZE = 256
```

В шаблоне обязательны плейсхолдеры `{character_id}` и `{size}`. Если шаблон битый — provider
просто опускает claim `picture` с warning'ом в лог; token endpoint при этом продолжает работать.

### Периодическая чистка истёкших токенов (Celery Beat)

Чтобы таблица токенов не разрасталась бесконечно, повесьте задачу очистки на расписание:

```python
from celery.schedules import crontab

CELERYBEAT_SCHEDULE["allianceauth_oidc_clear_expired_tokens"] = {
    "task": "allianceauth_oidc.clear_expired_tokens",
    "schedule": crontab(minute=0, hour="*/2"),  # каждые 2 часа
    "apply_offset": True,
}
```

### Операторские команды

Четыре `manage.py`-команды закрывают рутинные операционные задачи и не требуют ходить в admin-UI.
Все поддерживают `--format=table|json|csv`, у деструктивных есть `--dry-run`.

```sh
# Создать OIDC-приложение неинтерактивно — пригодится для CI и Ansible.
python manage.py oidc_create_app \
    --name="Grafana" \
    --user-id=1 \
    --redirect-uri="https://grafana.example/login/generic_oauth" \
    --state=Member \
    --group=Operators \
    --format=json

# Перегенерировать client_secret. Уже выпущенные токены остаются
# валидными до своего истечения; чтобы отрубить «здесь и сейчас» —
# комбинируйте с oidc_revoke_user_tokens.
python manage.py oidc_rotate_secret --client-id=abc123 --format=json
python manage.py oidc_rotate_secret --client-id=abc123 --dry-run

# Отозвать все access + refresh токены пользователя (offboarding,
# реакция на компрометацию). Команда идемпотентна — повторный запуск
# на чистом пользователе ничего не сломает.
python manage.py oidc_revoke_user_tokens --username=alice
python manage.py oidc_revoke_user_tokens --username=alice --dry-run

# Read-only аудит: кто сейчас залогинен в каком приложении.
python manage.py oidc_audit_tokens
python manage.py oidc_audit_tokens --username=alice --include-expired
python manage.py oidc_audit_tokens --client-id=abc123 --format=csv
```

Деструктивные команды (`create_app`, `rotate_secret`, `revoke_user_tokens`) пишут в лог на уровне
INFO / WARNING. Кроме того, `create_app` создаёт запись в Django admin LogEntry — действие сразу
видно в истории `/admin/` без правок в коде.

### Operational hardening — это уже на вашей стороне

Приложение реализует протокольную часть OAuth2 / OIDC, а runtime-обвязка ниже намеренно оставлена
оператору — чтобы интеграция с вашим edge / инфраструктурой получилась нативной:

- **Rate limiting на `/o/token/` и `/o/authorize/`.** Встроенного нет ни на одном из endpoint'ов.
  Защита от brute-force — это либо edge (nginx `limit_req`, Cloudflare, WAF), либо
  `django-ratelimit` в самом Auth. Без неё атакующий с сетевым доступом будет долбить
  `client_secret` / `code` / `refresh_token` на полной скорости канала.
- **Аутентификация Celery-брокера.** Задача `clear_expired_tokens` публикуется в Celery-брокер
  вашего AA. Если брокер доступен извне без аутентификации — недоверенный клиент сможет
  многократно дёргать чистку. Сама задача идемпотентна (удаляет только уже истёкшие строки), так
  что ущерба нет, но защита здесь — broker auth + сетевые ACL.
- **Security-заголовки.** Приложение не выставляет CSP / HSTS / X-Frame-Options /
  X-Content-Type-Options. На это есть middleware Alliance Auth и Django'шные `SECURE_*`-настройки —
  выставляйте их глобально, не на уровне нашего модуля.

## Подключение приложений

### Четыре основных endpoint'а

- Authorization: `https://your.url/o/authorize/`
- Token: `https://your.url/o/token/`
- Profile: `https://your.url/o/userinfo/`
- Issuer: `https://your.url/o/`

### Claims

- `openid profile email`

### Соответствие claim'ов и полей

- `name` — имя главного EVE-персонажа (требует scope profile)
- `email` — email пользователя из auth (требует scope email)
- `groups` — все группы пользователя плюс его state (требует scope profile)
- `sub` — PK модели User
- `picture` — URL аватарки главного персонажа (требует scope profile)
- `locale` — выбранный пользователем язык (требует scope profile)

### Создать приложение

Зайдите в admin `/admin/allianceauth_oidc` и создайте alliance auth application:

- `User` можно поставить 1 — это параметр upstream-библиотеки, у нас он не используется
- `client type` — confidential
- `authorization grant type` — `Authorization code`
- `Client secret` нужно сохранить **до** нажатия save, если включён hashing — потом он
  показываться не будет
- `Algorithm` — `RSA with SHA-2 256`

После — выберите состояния и/или группы, которым разрешён доступ. \
_Кроме этого пользователю нужно глобальное право `allianceauth_oidc.access_oidc` — без него ни
одно приложение работать не будет._

### WikiJS

Создайте в auth те группы, которые хотите видеть в wiki, — сервис их подхватит при логине. Это
заметно сокращает «группо-спам». Чтобы выдать полный доступ к admin-разделу wiki — заведите в
auth группу `Administrators`.

#### Administration > Authentication > Generic OpenID Connect / OAuth2

- Skip User Profile `off`
- Email claim `email`
- Display Name Claim `name`
- Map Groups `on`
- Groups Claim `groups`
- Allow Self Registration `on`

### Grafana

Пока проверено только без маппинга групп.

Маппинг Group → Team — это уже Grafana Cloud / Enterprise, выходит за рамки этого документа.

#### /etc/grafana/grafana.ini

```ini
[server]
root_url = <URL вашего Grafana>

[auth.generic_oauth]
enabled = true
name = <имя auth>
allow_sign_up = true
client_id = <client id из приложения>
client_secret = <client secret из приложения (нехешированный)>
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://<your.auth.url>/o/authorize/
token_url = https://<your.auth.url>/o/token/
api_url = https://<your.auth.url>/o/userinfo/
```

### Отладка приложения

1. Включите _Debug Mode_ конкретного приложения в admin Auth.
1. После попытки логина смотрите в `gunicorn.log` строки вроде:

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views:78] OIDC DEBUG token issued app_id=1 client_id=abc123 user_id=42 meta={'grant_type': 'authorization_code', 'scope': 'openid email profile', 'client_id': 'abc123', 'redirect_uri': 'https://app.example/cb', 'code': '<redacted>', 'refresh_token_req': None, 'client_secret': None, 'assertion': None, 'token_type': 'Bearer', 'expires_in': 111, 'scope_resp': 'openid email profile', 'access_token': '<redacted>', 'refresh_token': '<redacted>', 'id_token': '<redacted>'}
```

1. Возьмите значение `id_token` и вставьте на <https://jwt.io/>, чтобы увидеть, что именно ушло
   в приложение. В целом всё прозрачно; внимание заслуживают два поля:

- `iss` — issuer; должен **точно** совпадать с тем, что прописано в настройках самого приложения.
- `sub` — id пользователя; пригодится, когда нужно понять, «какой именно юзер сюда пришёл».

Если хотите проверить подпись на jwt.io, а публичный ключ потерян:

```sh
ssh-keygen -y -e -m pem -f /path/to/key/file
```

Это выдаст публичный ключ в PEM, в таком виде jwt.io его и принимает.

> [!NOTE]
> Если у вас кастомная тема или переопределён public-шаблон логина — проверьте файл
> `authentication/templates/public/login.html`. SSO-ссылка должна URL-кодировать параметр
> `next`; без этого query-параметры обрезаются, и OAuth/OIDC flow ломается — например, после
> редиректа теряется `client_id`.
>
> ```html
> <a
>   href="{% url 'auth_sso_login' %}{% if request.GET.next %}?next={{ request.GET.next | urlencode }}{% endif %}"
> ></a>
> ```

## Разработка

### Интеграционные тесты (mock-RP поверх реального HTTP)

`nox -s integration` запускает HTTP-уровень тестов из `tests/test_integration_mock_rp.py`. Они
поднимают `LiveServerTestCase`, прогоняют OIDC code-flow через `requests` + `jwcrypto` и
проверяют подпись id_token по JWKS, полученным по сети. Так ловятся регрессии, до которых
стандартный `nox -s tests` не дотягивается: Django test client пропускает WSGI-слой, и баги в
абсолютных URL (`iss`, `jwks_uri`), в Bearer-заголовках или cookie всплывают только здесь.

```sh
uv run nox -s integration                   # весь mock-RP набор
uv run nox -s integration -- --keepdb       # пробросить аргументы в django test
```

В дефолтный `nox` сессия не входит: HTTP-тесты заметно медленнее test-client'а и требуют
`--parallel=1` (LiveServerTestCase несовместим с `fork()` test runner'а).

### Conformance Suite (`nox -s conformance`)

`nox -s conformance` гоняет [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite)
против нашего провайдера в docker-compose-стеке: MongoDB + Suite + контейнер с провайдером. План
по умолчанию заводится через REST-API Suite — это делает `tests/conformance/run_plan.py`.

Это уровень выше наших регрессионных тестов: он ловит ровно те edge-cases спецификации, до которых
мы сами не додумаемся. Запускайте перед тегированием релиза. Детали — prerequisites, ручной /
итеративный сценарий, override настроек и список уже найденных conformance-проблем для триажа —
лежат в [tests/conformance/README.md](tests/conformance/README.md).
