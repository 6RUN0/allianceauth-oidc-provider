# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`allianceauth-oidc-provider` is a Django app that turns an [Alliance Auth](https://gitlab.com/allianceauth/allianceauth) installation into an OpenID Connect / OAuth2 provider. It is a thin policy/auditing layer on top of [`django-oauth-toolkit`](https://django-oauth-toolkit.readthedocs.io/) (DOT) — DOT does the OAuth/OIDC protocol work, this app adds Alliance-Auth-specific access control, claim mapping, safe logging, and a custom `Application` model.

Supported runtime: Python 3.10–3.12, Django 4.2, Alliance Auth 4.x, `django-oauth-toolkit>=3.2,<4`.

## Common commands

The project uses `tox` (per-Python-version envs against Django 4.2) plus a Makefile shim. Test data is loaded from Alliance Auth migrations, and Redis is replaced by `fakeredis` so no external services are required.

```sh
# install dev environment (uses pip + tox)
make dev

# full test matrix (py310/py311/py312 × django42), with coverage
make test                # == tox

# single env
tox -e py312-django42

# run tests directly without tox (must point Django at the test settings)
DJANGO_SETTINGS_MODULE=tests.test_settingsAA4 AA_USE_FAKE_REDIS=1 \
  python runtests.py allianceauth_oidc -v 2 --debug-mode

# run a single test class / method
DJANGO_SETTINGS_MODULE=tests.test_settingsAA4 AA_USE_FAKE_REDIS=1 \
  python runtests.py allianceauth_oidc.tests.test_token_policy.TestTokenPolicy -v 2
DJANGO_SETTINGS_MODULE=tests.test_settingsAA4 AA_USE_FAKE_REDIS=1 \
  python runtests.py allianceauth_oidc.tests.test_token_policy.TestTokenPolicy.test_userinfo_returns_expected_claims -v 2

# coverage report after a tox run (also produced as coverage.xml / htmlcov/)
coverage report -m

# pre-commit / linters (configured in .pre-commit-config.yaml + pyproject.toml)
uv run pre-commit run --all          # runs pyupgrade, isort, black, flake8, mypy, bandit, …
ruff check                            # quick lint pass (configured outside repo)

# build a wheel / sdist (flit)
make package
```

`runtests.py` does two notable things: it monkey-patches `django_redis.get_redis_connection` to a `FakeRedis` (so no real Redis is needed), and it shims `redis_version` to `7.4.0` because Alliance Auth checks that on startup. Honor `AA_USE_FAKE_REDIS=0` only if you actually want to talk to a real Redis.

Tests live in two places:
- `allianceauth_oidc/tests/` — the actual test suite for the package (this is what `tox` discovers).
- `tests/` — Django settings, URL conf, and Celery shim used to *run* those tests (`DJANGO_SETTINGS_MODULE=tests.test_settingsAA4`). Don't put new test cases there.

## Architecture

### Three-layer policy enforcement

Access control is enforced at three independent layers — each one is intentional, removing any of them opens a hole:

1. **`AuthAuthorizationView.dispatch()`** (`allianceauth_oidc/views.py`). Runs for both `GET` and `POST` to `/o/authorize/`. This is the gate that catches anonymous/unauthorized users **before** DOT's `AuthorizationView` can act. Putting checks only in `get()`/`post()` is a known footgun — there is a regression test (`test_post_no_perms_oauth_u1`) specifically for the POST-bypass case.
2. **`AllianceAuthOAuth2Validator.validate_code` / `validate_refresh_token`** (`auth_provider.py`). Re-runs the same `check_user_state_and_groups` policy when the client exchanges a code or refresh token. This is what causes "code issued, then user lost the group → `invalid_grant`" instead of a still-valid token.
3. **`AllianceAuthOAuth2Validator.save_bearer_token`** (`auth_provider.py`). Last-resort guard: a `PermissionDenied` here is converted to `oauth_errors.InvalidGrantError`, never a 500. This avoids the "token persisted but request rejected" race.

`security.py` centralizes the policy:
- `check_user_global_oidc_access(user)` — the global `allianceauth_oidc.access_oidc` permission gate (superusers bypass).
- `check_user_state_and_groups(user, app)` — app-level rule: "no states/groups configured ⇒ open; otherwise allow if user's state OR any of user's groups is whitelisted." Both functions use defensive `getattr`/`callable` checks because they are called from validators that may receive partially-mocked objects.

### Custom Application model

`AllianceAuthApplication` (`models.py`) extends DOT's `AbstractApplication` with:
- `states` (M2M to `allianceauth.authentication.State`) and `groups` (M2M to `auth.Group`) — the access whitelist.
- `active` — `is_usable()` returns this; a deactivated app cannot issue codes.
- `debug_mode` — per-app flag that escalates log level (see "Safe logging").
- A custom permission `access_oidc` ("Can Authenticate External Apps with OIDC") — *every* user needs this, regardless of state/group rules.

This requires `OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"` in Auth's settings, and `OAUTH2_VALIDATOR_CLASS` pointing at `AllianceAuthOAuth2Validator`. Without both, the policy layer is silently bypassed.

### Claim mapping

`AllianceAuthOAuth2Validator.get_additional_claims()` adds Alliance-Auth-specific claims on top of the standard set:

| Claim     | Source                                                          | Scope     |
|-----------|-----------------------------------------------------------------|-----------|
| `sub`     | `User.pk` (DOT default)                                         | `openid`  |
| `email`   | `user.email`                                                    | `email`   |
| `name`    | `user.profile.main_character.character_name`                    | `profile` |
| `picture` | `https://images.evetech.net/characters/{character_id}/portrait` | `profile` |
| `groups`  | `user.groups[*].name + [user.profile.state.name]`               | `profile` |
| `locale`  | `user.profile.language`                                         | `profile` |

The `groups` claim is bound to the `profile` scope (not a separate scope) — see the `oidc_claim_scope` override in `auth_provider.py`. The state name is appended to the groups list so consuming apps can map states the same way they map groups.

### Safe logging

Token endpoints handle credentials, so the logging layer is built around "never log raw secrets":

- `utils.redact_secret` returns `"<redacted>"` by default. Only when an admin opts in via `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True` does it return a masked fragment (`he…il`), with `_LOG_MASK_HEAD` / `_LOG_MASK_TAIL` controlling visible length.
- `utils.build_oidc_debug_meta` is the **only** sanctioned way to build a log-safe dict from a token request/response. It pulls `grant_type`, `scope`, `client_id`, `redirect_uri` (raw, non-secret) and runs everything else through `redact_secret`. Always extend this function rather than passing fresh fields to the logger.
- `utils.app_log` logs at INFO if `app.debug_mode` is True, otherwise at DEBUG. Per-app flag, not a global one — admins enable it on a single misbehaving client without flooding production logs. Callers that build expensive arguments (e.g. `list(queryset)`) must wrap them in `if logger.isEnabledFor(...)` themselves; `app_log` only handles lazy formatting of the message.
- Audit lives behind the `oidc_token_issued` Django signal (`signals.py`) with `use_caching=True`. The default receiver `audit_oidc_token_issued` is auto-connected in `AppConfig.ready()`. Add SIEM/audit forwarding by connecting another receiver — don't extend `TokenView`.

There is a regression test (`test_debug_logging_does_not_leak_tokens_or_secrets`) that exercises `debug_mode=True` and asserts that none of `access_token`, `refresh_token`, `id_token`, the auth `code`, or the client secret appear in the captured log output. Any change to logging must keep this passing.

### URL layout

`allianceauth_oidc/urls.py` re-publishes DOT's URL conf with two views overridden:
- `/o/authorize/` → `AuthAuthorizationView` (policy-aware).
- `/o/token/` → `TokenView` (audit signal + safe debug logging).

The rest (`/o/revoke_token/`, `/o/introspect/`, `/o/userinfo/`, `/o/.well-known/openid-configuration/`, `/o/.well-known/jwks.json`, `/o/logout/`) come straight from DOT. Mount with `namespace="oauth2_provider"` — DOT's templates rely on that namespace.

### Periodic cleanup

`tasks.clear_expired_tokens` is a Celery task wrapping DOT's `clear_expired()`. It is **not** scheduled by default; operators must add an entry to `CELERYBEAT_SCHEDULE` (see README). Without scheduling, expired tokens accumulate.

## Conventions

- **Line length 79** (black, isort, flake8 all configured to that). Per-file `noqa: E501` exemptions are documented in `pyproject.toml` for log-format strings that don't fit.
- **Logger name pattern**: `logging.getLogger(f"extensions.{__name__}")`. Tests assert against `extensions.allianceauth_oidc.views` etc., so don't rename without updating tests.
- **Defensive `getattr`** in `security.py` and `utils.py` is intentional — these helpers run inside DOT validators with partially-mocked request/user/client objects. Don't replace with attribute access.
- **Translations**: `allianceauth_oidc/locale/` + `.tx/transifex.yml`. The Transifex project is configured; new user-facing strings need to be wrapped in `gettext`.
- **Migrations**: there are 5 migrations on `AllianceAuthApplication`. DOT periodically alters its `AbstractApplication`, so new migrations may be needed when bumping the DOT version.
