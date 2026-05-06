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
  `typecheck`, `package`, `concurrency` по ref'у, обновлённые actions. Workflow для публикации на
  PyPI удалён — форк туда не публикуется.
- URL'ы в `pyproject.toml` указывают на
  [6RUN0 форк](https://github.com/6RUN0/allianceauth-oidc-provider); ссылка на оригинал
  [Solar-Helix](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
  сохранена в поле `urls.Upstream`.
- В README.md появилась шапка форка, инструкция по установке прямо из git (имя пакета на PyPI
  занято апстримом) и русский сосед — [README.ru.md](README.ru.md).

## История апстрима

Что было до точки расхождения форка — смотрите `git log` и страницу релизов оригинала.
