# Prometheus-метрики

Документ фиксирует соглашения, которым следует каждый AA-модуль
в этой экосистеме при добавлении Prometheus-инструментирования.
Это одновременно контракт для текущего модуля
(`allianceauth-oidc-provider`) и шаблон для соседних модулей —
единый набор имён, лейблов и bucket-разметки означает, что один
дашборд Grafana работает на всех сразу.

## Модель интеграции

Модули **кооперируются с** `django-prometheus`, а не **зависят
от** него. Конкретно:

* `django-prometheus` живёт в `[project.optional-dependencies]`
  под extras-ключом `metrics`. Оператор подключает его явно через
  `pip install <module>[metrics]` или получает транзитивно, если
  другой AA-модуль уже подтянул свой `metrics`-extras.
* `_metrics.py` модуля делает `try: import django_prometheus`
  один раз на импорте. При успехе реальные `Counter` /
  `Histogram` / `Gauge` из `prometheus_client` регистрируются в
  shared default-`REGISTRY`. При неудаче каждая метрика
  заменяется no-op-заглушкой, реализующей тот же интерфейс
  (см. [Контракт no-op-заглушки](#контракт-no-op-заглушки) ниже).
* Модуль никогда не монтирует свой `/metrics`-view и не
  добавляет middleware. Экспозиция registry — задача
  `django-prometheus`; оператор сам решает, когда и где
  `/metrics` становится доступен.

Receiver-цепочка подключается безусловно: no-op-receiver
вызывается на каждый сигнал, поэтому startup-путь идентичен с
включёнными и выключенными метриками. Это делает интеграцию
тестируемой без условных фикстур и устраняет дрейф конфигурации
"метрики включены в dev, но не в prod".

Поскольку каждый AA-модуль эмитит в один и тот же
`prometheus_client.REGISTRY` (default), модуль ОБЯЗАН владеть
уникальным namespace `aa_<module>_*` и НЕ должен определять
метрики с именами, конфликтующими с namespace другого модуля.
Два модуля, регистрирующие одинаковое имя, поднимут
`ValueError: Duplicated timeseries in CollectorRegistry` на
старте Django, ломая startup *всех* модулей — не только второго
зарегистрированного.

## Именование метрик

```
aa_<module>_<noun>[_unit][_total]
```

* `aa_` — фиксированный префикс. Панель Grafana с фильтром
  `{__name__=~"aa_.*"}` забирает метрики всех AA-модулей,
  принявших эту конвенцию. `django_*` зарезервирован за
  `django-prometheus`-собственными сериями; не пересекаться.
* `<module>` — короткое имя AA-модуля. Для текущего модуля —
  `oidc`. Один snake_case-идентификатор, совпадающий с коротким
  именем Python-пакета; одновременно — namespace-замок,
  предотвращающий cross-module collision выше.
* `<noun>` — то, что считается или измеряется. Multi-token
  snake_case допустим и часто необходим (`tokens_issued`,
  `bcl_delivery_seconds`, `authorize_denied`); глаголы и времена
  запрещены (`issuing_tokens`, `delivering_bcl_seconds` —
  неправильно).
* `<unit>` — обязателен для всего не-counter, измеряющего
  физическую величину: `seconds`, `bytes`. Counter'ы, считающие
  count (события, occurrences), не имеют unit-сегмента.
* `_total` — дописывается `prometheus_client` при эмиссии
  samples любого `Counter`. **В конструкторе**: передавайте имя
  без `_total` (например, `Counter("aa_oidc_tokens_issued", ...)`);
  библиотека добавит `_total` при выводе samples. **В тестах и
  Grafana-запросах**: читайте метрику как
  `aa_oidc_tokens_issued_total`. Передача имени, уже
  заканчивающегося на `_total`, сегодня молча разрешена, но
  deprecated, и в будущем релизе `prometheus_client` может
  бросать.

Примеры:

| Имя                               | Тип       | Почему такая форма              |
|-----------------------------------|-----------|---------------------------------|
| `aa_oidc_tokens_issued_total`     | Counter   | Кумулятивное целое, без единиц. |
| `aa_oidc_bcl_delivery_seconds`    | Histogram | Latency в секундах — единица обязательна. |
| `aa_oidc_bcl_dispatches_total`    | Counter   | Multi-token noun, без unit.     |

## Замкнутые value-sets

Каждый лейбл, чьё пространство значений конечно, ОБЯЗАН быть
объявлен как module-level `Final[frozenset[str]]` константа в
`constants.py`, и затем импортироваться везде, где это
пространство значений упоминается (emitter, receiver, тесты,
документация). Inline-строки, разбросанные по модулям,
запрещены: все случаи трёхместного дрейфа в истории этого модуля
начинались именно так.

Для `allianceauth_oidc` канонические наборы живут в
[`allianceauth_oidc/constants.py`](../allianceauth_oidc/constants.py):

* `BCL_HISTOGRAM_OUTCOMES` — outcomes per-attempt для
  `aa_oidc_bcl_delivery_seconds`.
* `BCL_DISPATCH_OUTCOMES` — терминальные outcomes для
  `aa_oidc_bcl_dispatches_total`.
* `BCL_DEAD_LETTER_OUTCOMES` — подмножество dispatch-набора,
  классифицированное как терминальная failure для alerting.
* `AUTHORIZE_DENY_REASONS` — значения для
  `aa_oidc_authorize_denied_total`.

При появлении нового failure mode добавьте его в канонический
набор *первым*, затем обновите emitters и тесты. Аннотация
`Final` плюс type checking ловит любой emitter, в котором
hardcoded string-литерал ушёл из набора.

## Словарь лейблов

Стабильные имена лейблов между модулями — берите из таблицы
прежде чем изобретать новое.

| Лейбл        | Значения                                                              | Заметки |
|--------------|-----------------------------------------------------------------------|---------|
| `client_id`  | OAuth `client_id` строкой                                             | На зарегистрированное приложение. Cardinality = `#apps × #values_of_other_labels`. Крупные альянсы держат 30-60 RP; считайте запас исходя из этого. Замкнутое множество (Application-админы, не end users). |
| `grant_type` | `authorization_code` / `refresh_token` / `client_credentials` / `password` (DOT-supported subset; RFC 6749 также определяет `implicit`, RFC 8628 добавляет `urn:ietf:params:oauth:grant-type:device_code`) | Имена RFC 6749 — буква в букву. |
| `outcome`    | Module-specific, из `Final[frozenset]` в `constants.py`               | Histograms используют per-attempt-словарь; терминальные counter'ы — расширенный набор. Никогда не выдумывайте значения inline. |
| `reason`     | Module-specific, из `Final[frozenset]` в `constants.py`               | Лейбл denial- / outcome-classification-counter'ов. Значения — из задокументированного замкнутого множества; никаких user-controlled строк. |
| `kid`        | JWK thumbprint                                                        | Идентификатор активного signing-ключа. Cardinality ограничен политикой ротации (обычно 1-3 активных). |

### Запрещённые лейблы

* **`user_id` / `user_pk` / `username` / `email` /
  `character_id` / `character_name` / `main_character_id` /
  `alt_character_id`** — cardinality неограничен на горизонте
  жизни AA-инстанса. Каждый новый пользователь, персонаж или alt
  раздувает series count и in-memory-хранение метрик. Используйте
  audit-логи для пер-identity-расследования, метрики —
  никогда.
* **`corporation_id` / `alliance_id` как per-user-прокси** —
  AA-инсталляции охватывают целые альянсы (десятки корп, сотни
  пользователей); эти лейблы нормальны *в агрегированном виде*
  (например, `aa_oidc_active_corps`) но смертельны как per-event
  прокси для "какой пользователь".
* **IP-адрес, session id, JWT `jti`** — то же. Полезны в audit,
  фатальны в метриках.
* **`url` / `path`** — когда значение request-derived, атакующий
  взрывает cardinality варьируя его. Если нужны метрики на
  endpoint — лейбл по имени view (замкнутое множество, которым
  владеет приложение), а не по URL.
* **AA `state` в free-form** — нормально, когда AA-инстанс
  использует default-замкнутый набор `Member`/`Blue`/`Guest`;
  как только оператор добавит custom state, источник станет
  admin-controlled но неограниченным. Документируйте явно,
  когда метрика безопасна для лейбла по `state`.

## Histogram buckets

Дефолт библиотеки `prometheus_client.Histogram.DEFAULT_BUCKETS`
(`(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0,
2.5, 5.0, 7.5, 10.0)`) подобран под in-process latency и
переусиливает sub-50ms-диапазон. Cross-network OIDC-операции
обычно медленнее; берите buckets под ожидаемый диапазон
операции.

* **Исходящий HTTP** (BCL-delivery, ESI-вызовы, RP-webhooks):
  `(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0)` — покрывает
  warm (50ms) до timeout-ceiling (15s) с разумной грануляцией на
  типовом RP-ответе (~250ms-1s).
* **Внутренние Django-request-paths**: оставьте на откуп
  middleware `django-prometheus` (у него собственные подобранные
  buckets — это не дефолты `prometheus_client`).
* **Долгие фоновые задачи** (token-cleanup, JWKS-ротация):
  `(1, 5, 15, 60, 300, 1800)` — в секундах, но ожидаются
  full-second / minute-scale значения.

`+Inf` дописывается автоматически; явно никогда не добавляйте.

## Правило большого пальца для cardinality

Метрика хранит in-memory одну запись на *уникальную комбинацию
лейблов*. Комбинации мультипликативны.

* **Counter'ы и Gauge'и**: `слотов = произведение cardinality
  каждого лейбла`. Пример: `client_id` (30 приложений) ×
  `outcome` (7 значений) = 210 слотов на метрику.
* **Histogram'ы**: каждая комбинация лейблов производит `N+3`
  Prometheus-серии — по одной на bucket плюс `_count`, `_sum` и
  `+Inf` bucket. Гистограмма с 9 BCL-buckets и 30 × 4
  label-комбо производит `30 × 4 × (9 + 3) = 1440` time-series,
  не 120. Histograms доминируют в cardinality-бюджетах.

Hard limits:

* Одна метрика выходящая за ~10 000 time-series — оператор
  получает warnings и медленные scrape'ы; рассмотрите drop
  лейбла.
* `client_id × user_id` — мгновенная cardinality bomb;
  запрещено таблицей выше.

Целевой потолок in-memory storage для всего модуля — ниже
10 000 уникальных series. Не жёсткий лимит, эвристика;
конкретные deployments с multiprocess-collector могут идти выше,
но оператор платит scrape-time и RAM.

## Multi-process под gunicorn

Реальные AA-деплои крутят несколько gunicorn-воркеров, каждый —
свой Python-процесс со своим `prometheus_client.REGISTRY`. Один
Prometheus-scrape попадает в случайный воркер и видит *только
метрики этого воркера*. Поведение по умолчанию — нестабильно:
counters прыгают вниз, когда scrape ротируется между воркерами.

Каноническое решение — родной multiprocess-collector-режим
`prometheus_client`; `django-prometheus` предоставляет
Django-view-адаптер, но не владеет multiprocess-механикой сам.
Operator-setup:

1. Установить env-переменную `prometheus_multiproc_dir`
   (`PROMETHEUS_MULTIPROC_DIR` тоже принимается; lower-case —
   канон) в writable-директорию, обычно `tmpfs`, чтобы файлы
   исчезли при перезагрузке хоста.
2. В gunicorn-конфиге подключить хук
   `child_exit(server, worker)`, вызывающий
   `prometheus_client.multiprocess.mark_process_dead(worker.pid)` —
   чтобы per-process-файлы зачищались при выходе воркера.
3. Смонтировать `django_prometheus.exports.ExportToDjangoView`
   (или любой custom view) с `CollectorRegistry`, построенным
   через `prometheus_client.multiprocess.MultiProcessCollector(registry)`.

Канонические ссылки:

* [Документация multiprocess `prometheus_client`](https://prometheus.github.io/client_python/multiprocess/) — авторитетная спека.
* [`django-commons/django-prometheus`](https://github.com/django-commons/django-prometheus) — поддерживаемый форк (старая ссылка `korfuri/django-prometheus` всё ещё резолвится, но проект переехал).

Модуль эмитит обычные метрики в default-registry;
multiprocess-обвязка — операторская забота, обрабатывается один
раз на AA-деплой, не на модуль.

### Caveat — `Gauge.set_function` и multiprocess

`Gauge.set_function(...)` **несовместим** с
multiprocess-collector: каждый воркер вычисляет своё значение, и
collector не может содержательно их агрегировать. Если нужен
семантика "текущий count", предпочтите одно из:

* **Lifecycle-counter'ы** — инкрементируйте на событии,
  создающем считаемую сущность, и инкрементируйте второй
  counter на событии, удаляющем её. Выводите разницу через
  PromQL (`sum(rate(issued[5m])) - sum(rate(cleaned[5m]))`).
  Работает в любом режиме; это то, что делает
  `aa_oidc_tokens_cleaned_total`.
* **Periodic-task gauge** — планируйте Celery-задачу, которая
  `set(...)` гейдж с явным `multiprocess_mode`
  `livesum`/`liveall`/`max`. Сложнее; оправдано только когда
  оператор обязан видеть точное мгновенное значение.

Конвенция `allianceauth_oidc`: "сначала lifecycle-counter'ы,
periodic-task-gauges только по требованию".

## Pattern инструментирования

Выбирайте call-site исходя из количества emitter'ов лежащего в
основе события:

* **Direct-инструментирование** — вызов
  `metric.labels(...).observe(...)` / `.inc()` прямо в
  code-path. Используйте, когда measurement intrinsic ровно
  *одному* источнику — например,
  `bcl_delivery_seconds.observe(...)` встроен в
  `tasks.send_logout_token` потому что `requests.post`
  round-trip имеет ровно один call-site.
* **Signal-driven** — подключите receiver на соответствующий
  `django.dispatch.Signal` в `connect_metrics_receivers()` и
  инкрементируйте внутри receiver. Используйте, когда у события
  есть, или может появиться, ≥2 emitter'ов — например,
  `bcl_dispatches_total` signal-driven, потому что и
  `tasks.send_logout_token`, и
  `logout.dispatch_backchannel_logout` эмитят
  `oidc_logout_dispatched`, и будущий custom dispatcher может
  эмитить тот же сигнал.

Правило: "по умолчанию инструментируйте signal-driven; переходите
на direct только если call-site доказуемо уникален". Receiver'ы
сигналов переживают свои оригинальные call-sites; direct-
инструментирование жёстко привязывает метрику к call-site,
который её написал.

## Контракт no-op-заглушки

Когда `django_prometheus` недоступен, `_metrics.py` подставляет
объекты `_NoOpMetric` вместо реальных метрик. Каждый AA-модуль,
следующий конвенции, ОБЯЗАН соблюдать этот контракт на своей
заглушке:

* `.labels(*args, **kwargs)` — возвращает `self`, чтобы
  chained-вызовы работали прозрачно.
* `.inc(amount: float = 1.0)` — возвращает `None`, без побочных
  эффектов.
* `.observe(amount: float)` — возвращает `None`, без побочных
  эффектов.
* `.set(value: float)` — возвращает `None`, без побочных
  эффектов.
* `.set_function(fn: Callable[[], float])` — возвращает `None`,
  без побочных эффектов. Функция никогда не вызывается.
* Других public-методов нет. Модули, желающие более богатой
  семантики (например, `inc_exemplar`), ОБЯЗАНЫ гейтить
  call-site через enabled-check, а не полагаться на заглушку.

Контракт enforced тестами — см.
[`tests/test_metrics.py`](../tests/test_metrics.py) для
delta-pattern-фикстур и плановый smoke-тест, patch'ащий
`sys.modules` для явного прохода через stub-путь.

## Чеклист добавления новой метрики

Прежде чем добавить `Counter` / `Histogram` / `Gauge`:

* [ ] Имя соответствует `aa_<module>_<noun>[_unit][_total]` с
      multi-token snake_case где нужно?
* [ ] Все лейблы — из словаря выше, либо, если новые, объявлены
      как `Final[frozenset]` в `constants.py`?
* [ ] Каждый лейбл — из ограниченного источника? (Без
      user-controlled строк без санитайзера; кросс-проверено
      против forbidden-labels-списка.)
* [ ] Если гистограмма: buckets обоснованы под ожидаемый
      диапазон операции, и bucket count отражён в
      cardinality-бюджете?
* [ ] Если gauge с `set_function`: задокументирован как
      multiprocess-incompatible, или заменён lifecycle-counter'ом?
* [ ] Выбор direct-vs-signal-инструментирования соответствует
      правилу выше?
* [ ] Метрика попала в inventory-таблицу с именем, типом,
      лейблами, файлом и источником?
* [ ] Тест ассертит *delta инкремента* вокруг действия под
      тестом (никогда не абсолютное значение)?

## Extraction-триггеры — когда рефакторить конвенцию

Текущий модуль — первый adopter. Конвенция плюс harness
`_metrics.py`-stub'а — это ~80 строк boilerplate на модуль. Это
приемлемо для двух adopter'ов и явный refactor-триггер на
третьем:

* **Модуль #2 принимает конвенцию** — копируем `_metrics.py`
  целиком. Добавляем в обе копии комментарий, ссылающийся на
  другую, чтобы drift был виден на PR-review.
* **Модуль #3 принимает конвенцию** — выносим `_NoOpMetric`,
  factories `_counter`/`_histogram` и try-import-гейт в пакет
  `aa-metrics-base`; каждый AA-модуль объявляет
  `aa-metrics-base` как non-optional dependency (он крошечный и
  pure-Python) и импортирует shared stub-harness. Первые два
  модуля мигрируют в рамках extraction-PR.
* **Helper `setup_multiprocess()`** — когда operator-side
  multiprocess-setup-recipe переживёт ≥2 деплоя без изменений,
  поднимаем шаги 1-3 выше в функцию, exported из
  `aa-metrics-base`. До этого держим recipe operator-side, чтобы
  не запекать форк setup-конвенций `django-prometheus`.

Триггеры намеренно консервативны: версионирование shared-пакетов
дороже 50 строк duplicated boilerplate, и форма абстракции
становится очевидной только после трёх реальных adopter'ов.

## Текущий inventory — `allianceauth_oidc`

| Метрика                                | Тип       | Лейблы                    | Файл                  | Источник                                |
|----------------------------------------|-----------|---------------------------|-----------------------|-----------------------------------------|
| `aa_oidc_tokens_issued_total`          | Counter   | `grant_type`, `client_id` | `_metrics.py`         | Receiver сигнала `oidc_token_issued`.   |
| `aa_oidc_tokens_cleaned_total`         | Counter   | (нет)                     | `tasks.py`            | Celery-задача `clear_expired_tokens` — инкрементируется по per-run cleanup-дельте. |
| `aa_oidc_authorize_denied_total`       | Counter   | `reason` (`global`/`app`) | `views.py`            | `AuthAuthorizationView.dispatch`.       |
| `aa_oidc_bcl_delivery_seconds`         | Histogram | `client_id`, `outcome`    | `tasks.py`            | `send_logout_token` — observed вокруг `requests.post`. |
| `aa_oidc_bcl_dispatches_total`         | Counter   | `client_id`, `outcome`    | `_metrics.py`         | Receiver сигнала `oidc_logout_dispatched` — фireет на каждом terminal-событии. |
| `aa_oidc_code_reuse_audit_misses_total`| Counter   | `client_id`               | `auth_provider.py`    | `_handle_potential_code_reuse` инкрементирует когда для предъявленного `code` нет строки в `IssuedCodeAudit`. После N-3 (atomic-wrap `save_bearer_token` + `_record_code_issuance`) race-window-источник закрыт; счётчик теперь срабатывает исключительно на never-issued кодах (fuzzers / replay на чужой провайдер). Коррелировать с сигналом `oidc_code_reuse_detected` — метрики должны быть непересекающимися. |
| `aa_oidc_audit_receiver_failures_total`| Counter   | `signal`, `receiver_dispatch_uid` | `_metrics.py`         | `signals.dispatch_audit_signal` инкрементирует на каждый receiver, упавший внутри `send_robust`. Один счётчик покрывает все 4 audit-сигнала (`oidc_token_issued`, `oidc_code_reuse_detected`, `oidc_token_introspected`, `oidc_logout_dispatched`). Ненулевой rate = audit-пайплайн молча теряет события для хотя бы одного downstream-consumer (SIEM-forwarder, кастомный hook). Лейбл `receiver_dispatch_uid` восстанавливает Django `dispatch_uid` под которым receiver зарегистрирован (project-internal constants в `constants.py`); fallback на `__qualname__` receiver'а если uid не задан. |

Анонимные authorize-запросы не вносят вклад в
`aa_oidc_authorize_denied_total` — они редиректятся на
`LOGIN_URL`, а не отклоняются. Операторам, отслеживающим
login-required-кейс, нужен `django_http_responses_total_by_status`
(предоставляется middleware `django-prometheus`) по
authorize-view.

Никакого `aa_oidc_active_tokens` Gauge нет. Approximation
active-токенов — operator-задача через PromQL:

```promql
sum(increase(aa_oidc_tokens_issued_total[1h]))
  -
sum(increase(aa_oidc_tokens_cleaned_total[1h]))
```

Подстраивайте time range под access-token TTL. Рецепт остаётся
корректным под multiprocess-scraping, потому что оба counter'а
multiprocess-safe; `Gauge.set_function` поверх
`AccessToken.objects.filter(...).count()` — нет.

Dead-letter alerting recipe — sum dispatch-counter'а по
каноническому failure-subset (`BCL_DEAD_LETTER_OUTCOMES`):

```promql
sum(rate(
  aa_oidc_bcl_dispatches_total{
    outcome=~"retries_exhausted|signing_kid_retired|signing_kid_resolve_failed|broker_unavailable|redirect_blocked|rp_client_error"
  }[5m]
))
```
