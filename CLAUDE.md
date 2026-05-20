# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`allianceauth-oidc-provider` is a Django app that turns an
[Alliance Auth](https://gitlab.com/allianceauth/allianceauth) installation into an OpenID Connect / OAuth2
provider. It is a thin policy/auditing layer on top of
[`django-oauth-toolkit`](https://django-oauth-toolkit.readthedocs.io/) (DOT) — DOT does the OAuth/OIDC
protocol work, this app adds Alliance-Auth-specific access control, claim mapping, safe logging, and a
custom `Application` model.

Supported runtime: Python 3.10–3.13, Django 4.2 or 5.2, Alliance Auth 4.x or 5.x,
`django-oauth-toolkit>=3.2,<4`. The dev environment locks to the AA 5.x stack (Django 5.2);
AA 4.x compatibility is exercised via the off-lock `tests_aa4` nox session and CI matrix.
A broader cross-version sweep lives in `tests_matrix` (driven from `_nox/matrix.py`); `make test-all`
runs it.

## Common commands

The project uses `nox` (per-Python-version sessions against Django 4.2 and 5.2) plus a Makefile shim.
Test data is loaded from Alliance Auth migrations, and Redis is replaced by `fakeredis` so no external
services are required.

```sh
# install dev environment (uv-managed venv + pre-commit)
make dev                              # == uv sync && uv run pre-commit install

# default sessions: lint + tests
make test                             # == uv run nox -s tests
make lint                             # == uv run nox -s lint
uv run nox                            # both

# run a single test class / method (extra args go to `django test`)
uv run nox -s tests -- tests.test_token.TestPolicyMatrix
uv run nox -s tests -- tests.test_token.TestTokenPolicyGuards.test_authorize_then_state_change_invalidates_refresh
uv run nox -s tests -- --keepdb         # skip migrations on reruns
uv run nox -s tests -- --parallel 1     # disable parallelism (default is auto)

# run against a real Redis instead of the fakeredis monkey-patch
AA_USE_FAKE_REDIS=0 uv run nox -s tests

# type checking and coverage
make typecheck                        # mypy + basedpyright
make coverage                         # term + html + xml report

# pip-audit is opt-in (manual stage) because Alliance Auth pins old deps
make audit                            # == uv run nox -s audit
uv run pre-commit run pip-audit --hook-stage=manual --all-files

# build a wheel / sdist (flit driven by uv run)
make package
```

`tests/_fakeredis.py` is invoked from the test settings module *before* Alliance Auth is imported. It
monkey-patches `django_redis.get_redis_connection` with a `fakeredis`-backed shim and stubs
`info()['redis_version']` to `7.4.0`, which AA's startup feature-detection probes. Set
`AA_USE_FAKE_REDIS=0` to skip the patch and run against a real Redis.

The `tests` nox session runs Django's test runner with `--parallel=auto`, which forks one worker per CPU
core and gives each its own SQLite-in-memory database. The `coverage` session stays single-process —
`coverage combine` for forked workers is more pipeline plumbing than the sub-second saving is worth on
this suite. Pass `-- --parallel 1` to disable parallelism for a debugging session; Django's argparse
honours the last `--parallel` flag.

All tests live in `tests/` at the repo root, deliberately outside the `allianceauth_oidc/` package so
`flit build` does not ship them in the wheel/sdist:

- `tests/test_*.py` — actual test cases (Django `unittest.TestCase`-based).
- `tests/_oidc_testcase.py` — shared `OIDCTestCase` (raw fixture) and `GrantedOIDCTestCase`
  (extends `OIDCTestCase` and pre-grants the global `access_oidc` permission to `self.user1`
  in `setUp`). Tests that exercise the global-allow path subclass `GrantedOIDCTestCase`; tests
  that exercise the global-deny path subclass `OIDCTestCase` directly. The module also exports
  code-flow helpers (`run_code_flow`, `authorize_to_code`, `authorize_get_default`),
  `signal_capture()`, `json_body(resp, expected_status=None)`, and module-level constants
  (`REDIRECT_URI`, `SCOPE_FULL`, etc.).
- `tests/_factories.py` — composable fixture builders (`make_alliance`, `make_corp`, `make_character`,
  `make_user`, `make_app`).
- `tests/_fakeredis.py` — opt-out monkey-patch for `django_redis`; called from the test settings module.
- `tests/_jwt_helpers.py` — JWT decoding / shape-assertion helpers used by the RFC 9068 tests.
- `tests/test_settingsAA4.py` — Django settings module (`DJANGO_SETTINGS_MODULE=tests.test_settingsAA4`).
- `tests/urls.py`, `tests/views.py`, `tests/celery.py` — minimal Django app wiring for the test
  environment.
- `tests/oidc-test.key` — RSA key used by the OIDC config in test settings.

## Architecture

### Three-layer policy enforcement

Access control is enforced at three independent layers — each one is intentional, removing any of them
opens a hole:

1. **`AuthAuthorizationView.dispatch()`** (`allianceauth_oidc/views_authorize.py`; re-exported from
   `views.py`). Runs for both `GET` and `POST` to `/o/authorize/`. This is the gate that catches
   anonymous/unauthorized users **before** DOT's `AuthorizationView` can act. Putting checks only
   in `get()`/`post()` is a known footgun — there is a regression test
   (`test_post_no_perms_oauth_u1`) specifically for the POST-bypass case.
2. **`AllianceAuthOAuth2Validator.validate_code` / `validate_refresh_token` / `validate_bearer_token`**
   (`auth_provider.py`). Each calls `_enforce_policy`, which delegates to `AccessPolicy.decide`.
   This is what causes "code issued, then user lost the group → `invalid_grant`" instead of a
   still-valid token, and what kicks an active access-token off the resource-server path the
   moment its owner loses state/groups.
3. **`AllianceAuthOAuth2Validator.save_bearer_token`** (`auth_provider.py`). Last-resort guard: a
   `PermissionDenied` here is converted to `oauth_errors.InvalidGrantError`, never a 500. This avoids
   the "token persisted but request rejected" race. Also opens the outer `transaction.atomic` that
   wraps DOT's AT/RT writes together with the `IssuedCodeAudit` row insert.

`security.py` centralises the policy on a frozen-dataclass class `AccessPolicy` with the canonical
instance `DEFAULT_POLICY = AccessPolicy()`. Three public methods cover the three call shapes:

- `decide(user, app) -> AccessDecision` — structured outcome (`AllowedDecision` / `GlobalDeny` /
  `AppDeny`). Used by `AuthAuthorizationView` so the renderer branches on the decision type and
  `typing.assert_never` makes any future fourth variant a type-checker error.
- `is_allowed(user, app) -> bool` — convenience for `validate_code` / `validate_refresh_token` /
  `validate_bearer_token` via `_enforce_policy`.
- `enforce(user, app) -> None` — raise-form for `save_bearer_token`, which converts the raise into
  `InvalidGrantError`.
- `requires_pkce(app) -> bool` — same shape, evaluated against the per-app `pkce_required` flag.

The decision dataclasses use defensive `getattr`/`callable` checks because they are called from DOT
validators that may receive partially-mocked objects.

### Custom Application model

`AllianceAuthApplication` (`models.py`) extends DOT's `AbstractApplication` with:

- `states` (M2M to `allianceauth.authentication.State`) and `groups` (M2M to `auth.Group`) — the access
  whitelist.
- `active` — `is_usable()` returns this; a deactivated app cannot issue codes.
- `debug_mode` — per-app flag that escalates log level (see "Safe logging").
- `pkce_required` — per-app PKCE enforcement, evaluated by `AccessPolicy.requires_pkce` and surfaced
  through the `pkce.per_app_pkce_required` callable wired into `OAUTH2_PROVIDER['PKCE_REQUIRED']`.
- `access_token_format` — per-app override for the access-token wire format (`"opaque"` / `"jwt"` /
  blank). Blank inherits the deployment-wide
  `OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT']` (default `"opaque"`).
- `backchannel_logout_uri` — RP endpoint that accepts signed `logout_token` POSTs (OIDC BCL 1.0);
  validated against the SSRF gate in `_validate_backchannel_logout_uri` on every save.
- `backchannel_logout_on_revoke_only` — when checked, lifecycle triggers (deactivation, group/state
  changes, account deletion) skip this RP; only `oidc_revoke_user_tokens` fans out.
- `logo_url`, `allowed_origins` — operator-facing extras carried since migrations 0004/0007.
- A custom permission `access_oidc` ("Can Authenticate External Apps with OIDC") — *every* user needs
  this, regardless of state/group rules.

This requires two settings on the AA side:

```python
OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"  # top-level
OAUTH2_PROVIDER = {
    # ...
    "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
    "PKCE_REQUIRED": per_app_pkce_required,  # function object, NOT a dotted-path
}
```

`OAUTH2_VALIDATOR_CLASS` is **nested under** `OAUTH2_PROVIDER` — at top level DOT ignores it and the
policy layer is silently bypassed. The Django system check `allianceauth_oidc.E003` flags the wrong
shape at deploy time.

### Claim mapping

The claim builder lives in `claims.py` (`ClaimsBuilder`); `AllianceAuthOAuth2Validator
.get_additional_claims()` is a thin shim that calls it. Standard OIDC claims plus AA-specific extras:

| Claim                              | Source                                                                                   | Scope                       |
|------------------------------------|------------------------------------------------------------------------------------------|-----------------------------|
| `sub`                              | `User.pk` (DOT default)                                                                  | `openid`                    |
| `email`                            | `user.email` (only when non-empty)                                                       | `email`                     |
| `email_verified`                   | placeholder→`False`, else `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`, else AA's `REGISTRATION_VERIFY_EMAIL` | `email`     |
| `name`                             | `user.profile.main_character.character_name`                                             | `profile`                   |
| `picture`                          | `ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE.format(character_id=..., size=...)` (default `https://images.evetech.net/characters/{character_id}/portrait?size={size}`) | `profile` |
| `groups`                           | `sorted(user.groups[*].name) + [user.profile.state.name]`, capped at `MAX_GROUPS_IN_CLAIM` | `profile`                 |
| `locale`                           | `user.profile.language` (only when non-empty)                                            | `profile`                   |
| `eve_character_id`, `eve_corporation_id/name/ticker`, `eve_alliance_id/name/ticker`, `eve_faction_id/name`, `eve_main_character_id`, `eve_affiliation` | `EveCharacter` chain off `user.profile.main_character` | `profile` (default; `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE` overrides) |

The `groups` claim is bound to the `profile` scope (not a separate scope) — see
`build_oidc_claim_scope` in `claims.py`. The state name is appended to the groups list so consuming
apps can map states the same way they map groups. The EVE-prefix and scope are controlled by
`ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX` (default `"eve_"`) and `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE`
(default `"profile"`).

### Safe logging

Token endpoints handle credentials, so the logging layer is built around "never log raw secrets":

- `utils.SecretRedactor` is a frozen dataclass with three knobs (`enabled`, `head`, `tail`). Calling
  the instance turns a value into `"<redacted>"` by default. When `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True`
  it returns a masked fragment (`he…il`); `ALLIANCEAUTH_OIDC_LOG_MASK_HEAD` /
  `ALLIANCEAUTH_OIDC_LOG_MASK_TAIL` control visible length. `SecretRedactor.from_django()` builds
  one from the cached `OIDCSettings` snapshot.
- `utils.build_oidc_debug_meta` is the **only** sanctioned way to build a log-safe dict from a token
  request/response. It pulls `grant_type`, `scope`, `client_id`, `redirect_uri` (raw, non-secret)
  and runs everything else through a `SecretRedactor`. Always extend this function rather than
  passing fresh fields to the logger.
- `utils.app_log` logs at INFO if `app.debug_mode` is True, otherwise at DEBUG. Per-app flag, not a
  global one — admins enable it on a single misbehaving client without flooding production logs.
  Callers that build expensive arguments (e.g. `list(queryset)`) must wrap them in
  `if logger.isEnabledFor(...)` themselves; `app_log` only handles lazy formatting of the message.
- Audit lives behind four Django signals in `signals.py` (`oidc_token_issued`,
  `oidc_code_reuse_detected`, `oidc_token_introspected`, `oidc_logout_dispatched`) — all wired with
  `use_caching=True`. Default receivers (`audit_oidc_token_issued`, `audit_oidc_code_reuse_detected`,
  `audit_oidc_token_introspected`, `record_backchannel_logout_attempt`) are auto-connected in
  `AppConfig.ready()`. Add SIEM/audit forwarding by connecting another receiver under a unique
  `dispatch_uid` — don't extend the views.

There is a regression test (`test_debug_logging_does_not_leak_tokens_or_secrets` in
`tests/test_logging.py`) that exercises `debug_mode=True` and asserts that none of `access_token`,
`refresh_token`, `id_token`, the auth `code`, or the client secret appear in the captured log output.
Any change to logging must keep this passing.

### URL layout

`allianceauth_oidc/urls.py` re-publishes DOT's URL conf with six views overridden:

- `/o/authorize/` → `AuthAuthorizationView` (policy-aware).
- `/o/token/` → `TokenView` (audit signal + safe debug logging + outer `transaction.atomic`).
- `/o/introspect/` → `AllianceAuthIntrospectTokenView` (per-app gating + audit signal).
- `/o/userinfo/` → `AllianceAuthUserInfoView` (Cache-Control headers per OIDC §5.3.2).
- `/o/.well-known/openid-configuration` (optional trailing slash, `re_path`) →
  `AllianceAuthDiscoveryView` (adds the OIDC Discovery 1.0 §3 RECOMMENDED fields DOT omits, plus the
  `backchannel_logout_supported` flag).
- `/o/.well-known/jwks.json` → `AllianceAuthJwksInfoView` (adds `Access-Control-Allow-Origin: *` so
  browser-based RPs can fetch the JWKS).

`/o/revoke_token/` and `/o/logout/` come straight from DOT. Mount with `namespace="oauth2_provider"`
— DOT's templates rely on that namespace.

### Periodic cleanup

`tasks.clear_expired_tokens` is a Celery task wrapping DOT's `clear_expired()` and additionally
garbage-collects `IssuedCodeAudit` rows with `reuse_count=0` once they age past
`OAUTH2_PROVIDER['REFRESH_TOKEN_EXPIRE_SECONDS']`. It is **not** scheduled by default; operators
must add an entry to `CELERYBEAT_SCHEDULE` (see README). Without scheduling, expired tokens
accumulate.

The back-channel-logout dispatch path (`tasks.send_logout_token`) and the audit-row recorder
(`receivers.record_backchannel_logout_attempt`) also live in `tasks.py` / `receivers.py`; see
`docs/BACK_CHANNEL_LOGOUT.md` for the retry / dead-letter contract.

## Conventions

- **Line length 79** (black, isort, flake8 all configured to that). Per-file `noqa: E501` exemptions
  are documented in `pyproject.toml` for log-format strings that don't fit.
- **Logger name pattern**: `logging.getLogger(f"extensions.{__name__}")`. Tests assert against
  `extensions.allianceauth_oidc.views_authorize` / `.views_token` / etc., so don't rename without
  updating tests.
- **Defensive `getattr`** in `security.py` and `utils.py` is intentional — these helpers run inside
  DOT validators with partially-mocked request/user/client objects. Don't replace with attribute
  access.
- **Translations**: `allianceauth_oidc/locale/` + `.tx/transifex.yml`. The Transifex project is
  configured; new user-facing strings need to be wrapped in `gettext`.
- **Migrations**: the migration set on `AllianceAuthApplication` grows over time — count
  `allianceauth_oidc/migrations/0*.py` rather than relying on a hard-coded number in this file
  (which decays whenever a field is added). DOT periodically alters its `AbstractApplication`,
  so new migrations may be needed when bumping the DOT version. Beyond the original
  state/group/active/debug_mode set, the schema now also carries `pkce_required`,
  `access_token_format`, `back_channel_logout_uri`, `back_channel_logout_on_revoke_only`,
  `logo_url`, `allowed_origins`, plus the `IssuedCodeAudit` and `BackChannelLogoutAttempt` tables.
