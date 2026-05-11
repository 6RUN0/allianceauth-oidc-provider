# OIDC Back-Channel Logout 1.0

## 1. Обзор

Этот модуль реализует
[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
в режиме **sub-only**. Когда AS завершает сессию пользователя
(revoke, деактивация, изменение groups/state, удаление аккаунта), он
POST-ит подписанный `logout_token` каждому Relying Party, который
зарегистрировал `backchannel_logout_uri`. RP по spec §2.6 обязан
"завершить все сессии пользователя" для этого `sub`.

Что означает sub-only на практике:

- Payload `logout_token` содержит `sub` (primary key пользователя)
  но НИКОГДА `sid`. RP завершает все вкладки/устройства пользователя,
  а не только текущую сессию.
- Companion-флаг `backchannel_logout_session_supported` в discovery
  намеренно НЕ эмитится. Session-scoped logout отложен в **feature
  v2** (см. §8).

## 2. Установка оператором

Перед регистрацией RP должны быть две настройки + Celery worker.

1. **Зафиксируйте issuer.** Celery worker не имеет HTTP request
   context, поэтому AS не может вывести `iss` во время сборки
   logout-токена. Добавьте абсолютный issuer URL в
   `OAUTH2_PROVIDER`:

   ```python
   OAUTH2_PROVIDER = {
       # ...
       "OIDC_ISS_ENDPOINT": "https://auth.example.org/o",
   }
   ```

   Django system check (`allianceauth_oidc.E001`) срабатывает на
   `manage.py check`, если хотя бы у одного
   `AllianceAuthApplication` установлен `backchannel_logout_uri` И
   `OIDC_ISS_ENDPOINT` не задан. Severity — `Error`; `manage.py
   check` вернёт ненулевой код, поэтому CI-пайплайны падают громко,
   а не на первом логауте конечного пользователя.

2. **Запустите Celery worker.** Back-channel logout — это fan-out по
   дизайну; одно событие логаута порождает N исходящих POST к N RP.
   Worker использует тот же broker / result-backend, что и Alliance
   Auth. Запись в `CELERYBEAT_SCHEDULE` не нужна — задачи запускаются
   сигналами, eagerly.

3. **Зарегистрируйте RP.** Django admin → OIDC application →
   установите `backchannel_logout_uri` в endpoint RP. URL ОБЯЗАН
   быть `https://`, кроме случая `settings.DEBUG=True` (разработка);
   admin-форма отвергает `http://` в production. DNS-bound SSRF
   guard резолвит host URL с 3-секундным wall-clock дедлайном и
   отвергает private / loopback / link-local / multicast / reserved
   адреса (RFC 1918, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4,
   240.0.0.0/4). Используйте
   `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` только для
   dev/compose-окружений.

## 3. Triggers (T1)

Fan-out логаута запускается при срабатывании ЛЮБОГО из пяти
сайтов:

| Сайт | Reason string | Условие |
|---|---|---|
| `manage.py oidc_revoke_user_tokens` | `user_revoked` | Всегда, после revoke |
| `User.is_active` flip True → False | `user_deactivated` | Безусловно при наличии RT/AT |
| `m2m_changed` на `User.groups` (post_remove / post_clear) | `groups_changed` | Если `AccessPolicy.is_allowed` теперь отказывает |
| `allianceauth.authentication.signals.state_changed` | `state_changed` | Если `AccessPolicy.is_allowed` теперь отказывает |
| `pre_delete` + `post_delete` на `User` | `user_deleted` | Безусловно при наличии RT/AT |

Spec §2.6 явно разрешает AS эмитить несколько `logout_token` для
одной пары `(user, application)`, если два trigger-а сработали в одной
транзакции (например, revoke + cascade deactivate). RP ОБЯЗАН делать
dedup по `jti` (уникальный для каждого исходящего POST).

## 3.1 Фильтрация триггеров для RP

По умолчанию все пять trigger-сайтов выше шлют `logout_token` каждому
RP с непустым `backchannel_logout_uri`. Для некоторых типов relying
party — audit, analytics, long-term-access дашбордов — оператор
может хотеть сохранить непрерывность сессии при автоматических
lifecycle-событиях и завершать сессии ТОЛЬКО при explicit revoke.

Per-app BooleanField `backchannel_logout_on_revoke_only` сужает
fan-out:

| Значение флага | Что fires для этого RP |
|---|---|
| `False` (по умолчанию) | Все пять triggers fires (v1 behaviour) |
| `True` | ТОЛЬКО `oidc_revoke_user_tokens` (`reason="user_revoked"`); четыре lifecycle reasons (`user_deactivated`, `groups_changed`, `state_changed`, `user_deleted`) silently пропускаются |

### Когда включать

- Audit / analytics RPs, которые должны продолжать запись активности
  при кратковременном churn'е аккаунта (ротация групп, временный
  deactivate).
- RP, у которого собственный session lifecycle длиннее AS-side
  membership state, и оператор явно принимает риск «stale session»
  в обмен на continuity.

### Семантика "skipped"

Skipped-событие **silent** на audit-сигнале — никакого
`oidc_logout_dispatched` не эмитится. Это держит audit log чистым
для типичного default-`False` deployment'а. Когда оператор хочет
подтвердить, что gating действительно сработал (например,
troubleshooting «почему BCL не сработал на смене группы»), нужно
установить `debug_mode=True` на затронутом RP и повторить trigger;
dispatcher эмитит INFO-level log line с literal substring
`skipped by on_revoke_only flag` и исходным reason. При
`debug_mode=False` тот же вызов уходит в DEBUG и остаётся скрытым.

### Custom receivers

Операторы, подключающие собственные receivers к
`oidc_logout_required`, ОБЯЗАНЫ использовать
`reason="user_revoked"`, если хотят, чтобы dispatch обошёл флаг.
Неизвестные / custom reason-строки трактуются как non-revoke и
пропускаются при `backchannel_logout_on_revoke_only=True`.

## 4. Структура logout_token

Header:

```json
{ "typ": "logout+jwt", "alg": "RS256", "kid": "<RFC 7638 thumbprint>" }
```

Payload (закрытый набор — поля сверх этого НЕ эмитятся никогда):

```json
{
  "iss": "https://auth.example.org/o",
  "aud": "<client_id>",
  "iat": 1700000000,
  "jti": "<uuid4 hex>",
  "sub": "<user.pk>",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout": {}
  }
}
```

Spec-литералы, которые НЕЛЬЗЯ "исправлять":

- URI в `events` — `http://...`, не `https://...`. Spec §2.4.
- Claim `nonce` НИКОГДА не присутствует (spec MUST NOT).
- Claim `sid` НИКОГДА не присутствует в v1 — sub-only logout по §2.6.

Identity / PII-клеймы (`email`, `name`, `picture`, `groups`,
`locale`, `scope`, `client_secret`, character data) НИКОГДА не
эмитятся в logout_token. Regression-тест
(`TestBackChannelLogoutTokenBuilder.test_ac21_payload_never_contains_pii`)
фиксирует отсутствие.

## 5. Retry и идемпотентность

Celery task `allianceauth_oidc.send_logout_token` принимает скалярные
аргументы (`user_pk`, `application_pk`, `jti`, `signing_kid`, `iat`),
поэтому broker НИКОГДА не хранит JWT. На каждой попытке worker
пересобирает токен против зафиксированного `signing_kid` и
закрепленных `(jti, iat)`, поэтому retry — байт-в-байт идентичны.
Default расписание retry — exponential backoff (5s, 10s, 20s, 40s,
80s, capped at 125s) с `max_retries=3`; кумулятивный wall-clock ≤
155 s (≈ 2:35), внутри 3-минутного окна, рекомендованного spec для
свежести `iat` на RP-стороне.

Маршрутизация по статус-коду:

| Ответ RP | Действие |
|---|---|
| 2xx | Успех; audit signal `oidc_logout_dispatched(success=True)` |
| 3xx | Блокировка — `allow_redirects=False`; `reason="redirect_blocked"`; без retry |
| 4xx | `reason="rp_client_error"`; без retry |
| 5xx | Celery autoretry; финальный сбой → `reason="retries_exhausted"` |
| `SigningKeyRetiredError` | `reason="signing_kid_retired"`; без HTTP-вызова |

Дисциплина исходящих HTTP:

- `requests.post(allow_redirects=False, timeout=(5, 10))`.
- Тело ответа НИКОГДА не читается; только `status_code`.
- `User-Agent: allianceauth-oidc/<version>`.

## 6. Модель безопасности

- **SSRF-защита.** `Application.clean()` резолвит host через
  bounded `concurrent.futures.ThreadPoolExecutor` (3 s wall-clock),
  НЕ `socket.setdefaulttimeout` — последний является процесс-
  глобальным mutable и НЕ ограничивает `getaddrinfo` (вызов libc
  resolver). Private / loopback / link-local / multicast /
  reserved IP отвергаются, кроме случая dev-only escape hatch
  `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True`.

- **Политика DNS-сбоев — non-blocking.** Транзиентные сбои resolver
  (`gaierror`, `socket.timeout`, `OSError`,
  `concurrent.futures.TimeoutError`) логируют WARNING и позволяют
  admin-форме сохранить. Операторы решают, алёртить ли по частоте —
  graylog dashboard, log aggregator и т.п. — а вредоносный /
  дрейфующий RP URL всё равно обязан пройти SSRF-отказ на следующем
  save.

- **Никаких токенов в логах.** Все log-строки в `logout.py` и
  `tasks.send_logout_token` маршрутизируются через
  `build_logout_debug_meta`, у которого фиксированный allow-list
  полей (`application_pk`, `application_name`,
  `backchannel_logout_uri`, `jti`, `status_code`, `reason`).
  Тесты `TestBackChannelLogoutLogging.test_ac36_*` проверяют, что
  ни `logout_token`, ни `access_token`, `refresh_token`,
  `id_token`, `client_secret` не утекают в captured log output на
  ветках success / 3xx / 4xx / kid-retired.

- **Никакого PII в токенах.** См. §4 выше — закрытый набор payload.

## 7. Audit / observability

Эмитятся два Django-сигнала:

- `oidc_logout_required(sender, user, application, reason=None)` —
  поднимается каждым trigger-сайтом ПЕРЕД любым HTTP fan-out.
  Default-receiver (`logout.dispatch_backchannel_logout`) ставит
  Celery task в очередь; кастомные receivers могут подключаться
  под другим `dispatch_uid` для SIEM-forwarding.

- `oidc_logout_dispatched(sender, application, jti, success, attempt_count, user_pk=None, reason=None)`
  — эмитится `tasks.send_logout_token` на каждой попытке (success,
  3xx, 4xx, kid-retired, retries-exhausted), а также dispatcher-ом
  когда broker недоступен. Receivers могут форвардить
  `LogoutAuditBody` (curated audit payload) в log-aggregator без
  утечки секретов. `user_pk` — это целое число (не модель),
  поэтому flow `user_deleted` корректно отчитывается о
  пострадавшем пользователе даже после удаления его строки.

## 7.1 Журнал неудачных доставок (dead-letter)

`BackChannelLogoutAttempt` фиксирует каждое терминальное событие
`oidc_logout_dispatched` как одну неизменяемую audit-строку.
Просматривается из Django admin → **Alliance Auth OIDC →
Back-Channel Logout attempts**.

| Колонка         | Поле сигнала    | Заметки                                                  |
|-----------------|-----------------|----------------------------------------------------------|
| `application`   | `application`   | FK на `AllianceAuthApplication`. `CASCADE` при удалении. |
| `user_pk`       | `user_pk`       | Целое число; `NULL`, если строка пользователя уже удалена. |
| `jti`           | `jti`           | 32-байтовый hex из `uuid4().hex`. Пустой для отказов до выдачи токена. |
| `success`       | `success`       | `True` = HTTP 2xx; `False` = любой другой терминальный исход. |
| `attempt_count` | `attempt_count` | Номер попытки Celery (1-based). `0` для отказов на стороне dispatcher. |
| `reason`        | `reason`        | Trigger reason при успехе, failure mode при провале.     |
| `created_at`    | wall clock      | `auto_now_add`; индекс для сортировки `-created_at`.     |

**Что записывается.** По умолчанию — **только провалы**:
`success=False` со значениями `reason` из набора
`redirect_blocked`, `rp_client_error`, `retries_exhausted`,
`signing_kid_retired`, `signing_kid_resolve_failed`,
`broker_unavailable`. Успешные доставки молча отбрасываются —
чтобы таблица оставалась сфокусированной на том, что требует
внимания оператора.

Установите `ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True` в Django
settings, чтобы также записывать успехи (полная SIEM-корреляция,
compliance-аудит). Флаг влияет только на новые события —
исторические строки не бэкфилятся.

**Read-only by design.** Admin отключает add и change; audit-row
есть честная запись того, что произошло на проводе, и её НЕЛЬЗЯ
редактировать. Delete оставлен, чтобы суперюзеры могли вручную
почистить таблицу (или через периодический Celery task с
retention-политикой).

**Retention.** Автоматическая очистка не поставляется — таблица
растёт линейно вместе с числом провалов. Для среднестатистического
инстанса это «несколько строк в неделю». Если объём провалов
большой (или есть compliance-ограничение по сроку хранения),
заведите Celery beat-задачу с
`BackChannelLogoutAttempt.objects.filter(
created_at__lt=cutoff).delete()` — по аналогии с
`clear_expired_tokens` из §2.

**Forwarding в SIEM.** Подключите второй receiver к
`oidc_logout_dispatched` под другим `dispatch_uid` —
`record_backchannel_logout_attempt` не «съедает» сигнал.
Обычно SIEM-forwarder склеивает `application_id` + `user_pk` +
`reason` в структурированную лог-строку; curated `LogoutAuditBody`
TypedDict документирует безопасный для отправки набор полей.

## 8. Out of scope — feature v2 (session-scoped logout)

Sub-only logout завершает **все** сессии пользователя на RP. Feature
v2 в будущем может добавить session-scoped logout (`sid` claim в
`logout_token`) — см. plan v5 §12 для трёх описанных forward-paths.
v1-омиссия намеренная, не упущение; session-scoped flow требует
coupling с `RefreshToken.token_family` (DOT) либо отдельной моделью
`OIDCSession`, а spec явно разрешает AS отказаться от session-
scoping.

## 9. RP integration

Большинство off-the-shelf OIDC-библиотек поддерживают back-channel
logout из коробки:

- **oauth2-proxy** — установите redirect URI на AS и сконфигурируйте
  endpoint back-channel logout на RP.
- **mod_auth_openidc (Apache)** — `OIDCSessionType server-cache`
  плюс зарегистрированный logout endpoint по docs модуля.
- **Wiki.js / Outline / Grafana** — см. vendor docs про "OIDC
  back-channel logout"; флаг `backchannel_logout_supported: true` в
  discovery — feature-detection probe.

Для каждого RP:

1. Зарегистрируйте back-channel logout endpoint на стороне RP.
2. Установите `backchannel_logout_uri` в Django admin → OIDC
   application.
3. Запустите логаут (например, `manage.py oidc_revoke_user_tokens
   --username=test`).
4. Подтвердите по логам RP POST `logout_token` с `aud = <client_id>`
   и `sub`, соответствующим `user.pk` на AS.
