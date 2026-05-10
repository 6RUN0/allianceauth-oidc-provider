# JWT-токены доступа (RFC 9068)

## 1. Обзор

Модуль поддерживает два wire-формата access-токена:

- **Opaque** (по умолчанию) — случайные URL-safe строки. Валидация
  требует round-trip'a в `/o/introspect/` на каждом защищённом
  запросе. RP вроде `passport-openidconnect`, Wiki.js, Outline и
  подобных принимают такой формат без дополнительной настройки.
- **JWT (RFC 9068)** — JSON Web Token с `typ="at+jwt"`, подпись
  `RS256` тем же ключом `OIDC_RSA_PRIVATE_KEY`, что и id_token.
  Готовые reverse-proxy auth-инструменты (oauth2-proxy,
  mod_auth_openidc, HAProxy `oauth2-bouncer`, Envoy `oauth2_proxy`)
  валидируют токен локально по опубликованному JWKS — без round-trip'a
  на горячем пути.

JWT-режим **opt-in** (по умолчанию `"opaque"`) и **stateful**: каждый
выпущенный JWT хранится в `oauth2_provider_accesstoken.token` ровно
так же, как opaque-аналог, поэтому revoke / introspect / audit-сигнал
продолжают работать. Per-app override
(`AllianceAuthApplication.access_token_format`) позволяет переключить
сначала один некритичный RP, проверить, и только потом поднять
глобальный default.

## 2. Активация

Пропишите две настройки в `OAUTH2_PROVIDER`:

```python
OAUTH2_PROVIDER = {
    # ... ваши обычные настройки ...
    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
    "ACCESS_TOKEN_GENERATOR": (
        "allianceauth_oidc.tokens.dispatching_access_token_generator"
    ),
    "ACCESS_TOKEN_EXPIRE_SECONDS": 300,  # см. "Data minimization"
}
```

Нужны обе. `ACCESS_TOKEN_GENERATOR` входит в `IMPORT_STRINGS` DOT, и
DOT превращает dotted-path в callable на старте; `PKCE_REQUIRED` не
входит, поэтому PKCE-адаптер требует ссылку на функцию — см. таблицу
OAUTH2_PROVIDER в README.

Если выставлена только одна из двух, `AllianceAuthOIDC.ready()` пишет
стартовый `WARNING`, называя пропущенный ключ. Проверка только
логирует и обёрнута в `try/except`: опечатка в dotted-path никогда не
ломает старт Django — всплывает в логе.

После применения миграций и рестарта Auth каждый новый AT в этом
деплое становится JWT (с учётом per-app override'ов — см. §7).

## 3. Маппинг claim'ов

Провайдер переиспользует канонический `oidc_claim_scope` DOT для JWT.
Это значит, что наборы claim'ов AT и id_token побайтово совпадают для
одного и того же набора scope, за исключением framing-claim'ов RFC
9068 (id_token их не несёт). Расхождений по claim'ам поддерживать не
надо.

| Claim | Источник | Scope | Заметки |
|-------|----------|-------|---------|
| `sub` | `User.pk` (или `client_id` для client_credentials) | `openid` | Fallback по RFC 9068 §3, когда конечного пользователя нет |
| `email` | `user.email` | `email` | |
| `email_verified` | Auto / `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` | `email` | Та же логика, что и в id_token |
| `name` | `user.profile.main_character.character_name` | `profile` | |
| `picture` | URL EVE-портрета | `profile` | |
| `groups` | `user.groups[*].name + state.name` | `profile` | Cap 256 записей |
| `locale` | `user.profile.language` | `profile` | |
| `eve_*` | Данные персонажа / корпы / альянса EVE | `profile` (настраивается) | |

Framing-claim'ы RFC 9068 поверх:

| Claim | Значение |
|-------|----------|
| `typ` (header) | `"at+jwt"` |
| `alg` (header) | `"RS256"` |
| `kid` (header) | RFC 7638 thumbprint подписывающего ключа |
| `iss` | Через `oauth2_settings.oidc_issuer(request)` |
| `aud` | `client_id` (соглашение AA: идентифицирует приложение) |
| `client_id` | `client_id` (дублирует `aud` по RFC 9068 §3) |
| `exp` | `iat + ACCESS_TOKEN_EXPIRE_SECONDS` |
| `iat` | Время выпуска токена (Unix epoch, секунды) |
| `jti` | UUID4 hex |
| `scope` | Space-delimited список scope'ов запроса |
| `auth_time` | `user.last_login` (Unix epoch); опускается для client_credentials |

## 4. Data minimization

JWT-режим платит обе цены: stateful-хранилище И PII-на-проводе. Строка
в БД нужна для revoke, но JWT при этом несёт identity-claim'ы в
открытую (только base64url, подписано но не зашифровано).
Митигация — **дисциплина TTL токена**: короткое окно `exp`
ограничивает срок жизни любого утёкшего PII-payload'а.

Рекомендуется: `OAUTH2_PROVIDER["ACCESS_TOKEN_EXPIRE_SECONDS"] = 300`
(5 минут) как минимум. RP вынуждены чаще ходить за refresh, но окно
PII-at-rest сжимается пропорционально. Та же логика — в существующей
рекомендации `CLAUDE.md` для WikiJS; в JWT-режиме она становится
default'ом, а не частным случаем.

В деплоях, где JWT-режим затолкал бы PII в менее защищённые пайплайны
(аналитика, полные сетевые логи, холодные бэкапы), оставьте default
`"opaque"` и настройте RP на introspect.

## 5. Ротация ключей

Ключ подписи — `OIDC_RSA_PRIVATE_KEY`. Дисциплина ротации:

1. **Сгенерируйте новый ключ** offline. Поставляемая команда
   `manage.py oidc_jwks_rotate` создаёт свежий PKCS8 RSA-ключ,
   печатает его RFC 7638 thumbprint (тот самый `kid`, который
   попадёт в JWT-заголовок и JWKS) и заново выдаёт рецепт ниже
   для справки. `--out PATH` пишет чистый PEM в файл (mode `0600`),
   готовый для подстановки в `OAUTH2_PROVIDER`; `--key-size 3072`
   (или больше) покрывает compliance-режимы, требующие `>= 128`
   бит security strength. Для не-поставляемых путей см.
   [документацию DOT][dot-oidc].
2. **Настройте overlap**. DOT поддерживает
   `OIDC_RSA_PRIVATE_KEYS_INACTIVE` — список ключей, по которым
   валидация ещё доверяется, но новые токены ими не подписываются.
   Добавьте **старый** ключ в этот список, поставьте **новый** как
   `OIDC_RSA_PRIVATE_KEY`, перезапустите Auth. JWKS теперь публикует
   оба `kid`.
3. **Подождите дольшего из `ACCESS_TOKEN_EXPIRE_SECONDS` и самого
   длинного TTL кэша на стороне RP**. Существующие JWT, подписанные
   старым ключом, продолжают валидироваться по опубликованному JWKS
   в течение этого окна.
4. **Уберите старый ключ** из `OIDC_RSA_PRIVATE_KEYS_INACTIVE`. JWKS
   перестаёт его публиковать. Любой запоздавший JWT, подписанный
   старым ключом, падает — что и требовалось.

Если пропустить overlap (шаги 2-3), все in-flight JWT'ы мгновенно
становятся невалидными — и вы получаете outage пропорциональный
числу активных сессий.

Back-channel logout (sub-only, OIDC BCL 1.0) переиспользует ту же
цепочку `OIDC_RSA_PRIVATE_KEY` + `OIDC_RSA_PRIVATE_KEYS_INACTIVE`
для подписи `logout_token`. Celery dispatcher запоминает `kid`
активного ключа в момент постановки в очередь, а worker на retry
резолвит ключ из любого из двух store, поэтому ротация в полёте не
теряет in-progress логауты. См.
[docs/BACK_CHANNEL_LOGOUT.ru.md](BACK_CHANNEL_LOGOUT.ru.md).

[dot-oidc]: https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html

## 6. RP cookbook

### oauth2-proxy

```yaml
# oauth2-proxy.cfg
provider = "oidc"
oidc_issuer_url = "https://your-auth.example.com/o"
client_id = "your-client-id"
client_secret = "your-client-secret"
scope = "openid profile email"
# Audience по соглашению AA совпадает с client_id.
oidc_extra_audiences = ["your-client-id"]
# Локальная валидация JWT по опубликованному JWKS — без /introspect.
skip_jwt_bearer_tokens = true
extra_jwt_issuers = "https://your-auth.example.com/o=your-client-id"
```

### mod_auth_openidc (Apache)

```apache
OIDCProviderMetadataURL https://your-auth.example.com/o/.well-known/openid-configuration
OIDCClientID your-client-id
OIDCClientSecret your-client-secret
OIDCScope "openid profile email"
# Принимать JWT access-токены от нас, валидируя локально.
OIDCOAuthVerifyJwksUri https://your-auth.example.com/o/.well-known/jwks.json
OIDCOAuthRemoteUserClaim sub
```

### Discord SSO (кастомная интеграция)

Discord-боты не говорят OIDC напрямую; если у вас уже есть кастомный
мост, который резолвит `sub` из вашего AA-OIDC, JWT-режим этот мост
не меняет — `sub` остаётся идентификатором пользователя. Для
локальной валидации JWT мосту понадобится подключить `jose` /
`jwcrypto` и проверять подпись по опубликованному JWKS.

### WikiJS

OIDC-стратегия WikiJS использует `passport-openidconnect`, который
**не валидирует JWT access-токены локально** — он валидирует
`id_token` и хранит AT для последующих обращений к `/userinfo`.
Поэтому JWT-режим в WikiJS функционально не меняет ничего:

- Плюс: при включении JWT-режима в WikiJS не надо ничего менять.
- Минус: сама по себе WikiJS никаких преимуществ от JWT-режима не
  получает — выгода появляется, только если фронтэнд WikiJS прикрыт
  oauth2-proxy или подобным.

## 7. Миграция: opaque → JWT

Рекомендуется идти **сначала per-app, потом глобал**:

1. Примените миграцию 0012 (она добавляет поле `access_token_format`).
2. В Django admin выберите один некритичный RP. Поставьте ему
   `access_token_format = "jwt"`. Сохраните.
3. Пропишите `ACCESS_TOKEN_GENERATOR` в `local.py` (сам диспетчер без
   per-app override'а и глобального default'а ничего не меняет).
4. Перезапустите Auth. Выбранный RP теперь выпускает JWT, всё
   остальное — opaque.
5. Проверьте через `manage.py oidc_audit_tokens --include-expired
   --client-id=<выбранный RP>`. У вывода появится колонка `format`;
   убедитесь, что у выбранного RP — `jwt`, у остальных — `opaque`.
6. Через выдержку (24-72 часа) выставите
   `OAUTH2_PROVIDER["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"]
   = "jwt"` и перезапустите. Все остальные RP начнут выпускать JWT
   при следующем запросе токена.

## 8. Откат

Чтобы откатить глобал в opaque, переключите настройку:

```python
OAUTH2_PROVIDER["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "opaque"
```

In-flight JWT'ы остаются валидными до своего `exp`; публикуемый JWKS
по-прежнему отдаёт ключ подписи, поэтому RP, провалидировавший JWT
до отката, продолжает считать его действительным. Новые токены — снова
opaque. Никакой data-миграции не требуется.

Чтобы откатить отдельный RP, в admin'е верните его
`access_token_format` в пустое значение (или явно `"opaque"`, если
хотите зафиксировать).

`ACCESS_TOKEN_GENERATOR` можно оставить даже после отката — при
`"opaque"` диспетчер резолвит формат и делегирует встроенному
генератору oauthlib (тот же callable, что DOT использовал бы по
умолчанию).

## 9. Проверка токенов

### Со стороны оператора

```sh
# После выпуска свежего AT — декодирование без проверки подписи:
python -c '
import sys, json, base64
parts = sys.stdin.read().strip().split(".")
def decode(seg):
    pad = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + pad))
print("HEADER:", json.dumps(decode(parts[0]), indent=2))
print("PAYLOAD:", json.dumps(decode(parts[1]), indent=2))
'
```

Полная валидация (с подписью) — через `jwcrypto` (он уже транзитивная
зависимость DOT) по опубликованному JWKS.

### Audit-сигнал

Кастомные receiver'ы, подключенные к `oidc_token_issued`, видят поле
`format` в аргументе `body`:

```python
@receiver(oidc_token_issued)
def forward_to_siem(sender, *, body, token, **kwargs):
    fmt = body.get("format")  # "opaque" | "jwt" | None
    ...
```

## 10. Troubleshooting

**Симптом: я включил JWT-режим, но токены по-прежнему opaque.**

Скорее всего у вас выставлен только
`ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt"`, без
`ACCESS_TOKEN_GENERATOR`. Проверьте стартовый лог
`extensions.allianceauth_oidc.apps` — там будет `WARNING`.

**Симптом: апстримный прокси отвергает AT с "header too long".**

Токен превысил лимит `Authorization`-заголовка прокси. Посмотрите в
логе `extensions.allianceauth_oidc.tokens` warning о фактическом
размере и решите: поднять лимит прокси (Apache `LimitRequestFieldSize`,
nginx `large_client_header_buffers`, HAProxy `tune.bufsize`) или
обрезать членство в группах. Настройка
`ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` влияет только на порог
warning'а, выпуск токенов она не меняет — она информационная.

**Симптом: grant client_credentials валится на проверке `sub`.**

Провайдер корректно отдаёт `sub=client_id` для client_credentials (по
RFC 9068 §3). Некоторые RP валидируют `sub` против пользовательской
БД и отвергают всё, что не соответствует известному пользователю.
Это проблема настройки RP — настройте RP так, чтобы он принимал
`sub` формы `client_id` или пропускал валидацию `sub` для
machine-to-machine токенов.

**Симптом: я ротировал ключ и все активные сессии сломались.**

Пропустили шаг overlap (§5.2). Восстановите предыдущий ключ как
`OIDC_RSA_PRIVATE_KEY`, добавьте новый в
`OIDC_RSA_PRIVATE_KEYS_INACTIVE`, и проведите ротацию заново
правильно.
