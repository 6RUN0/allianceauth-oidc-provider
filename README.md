# allianceauth_oidc

> Fork of
> [Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
> maintained at
> [6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) — adds
> wire-level integration tests, an OIDC Conformance Suite harness, operator CLI commands,
> EVE-specific claims, runtime localisation (en / ru / uk), and a Russian-language
> [README.ru.md](README.ru.md).

A thin policy / auditing layer on top of
[`django-oauth-toolkit`](https://django-oauth-toolkit.readthedocs.io/) that turns an
[Alliance Auth](https://gitlab.com/allianceauth/allianceauth) installation into an OpenID Connect /
OAuth2 provider.

- [Overview](#overview)
- [Install](#install)
- [Configuration](#configuration)
- [Reference](#reference)
- [Operations](#operations)
- [Integrations](#integrations)
- [Development](#development)

## Overview

DOT does the OAuth / OIDC protocol work; this app adds Alliance-Auth-specific access control,
claim mapping, safe logging, and a custom `Application` model with `state` / `group` whitelists.

Every authorization-code exchange runs through three independent gates. Each layer is intentional;
removing any of them opens a hole, which is why the regression tests exercise each layer
separately.

![Three-layer policy enforcement: dispatch then validate_code then save_bearer_token](https://raw.githubusercontent.com/6RUN0/allianceauth-oidc-provider/current/assets/diagrams/policy-flow.svg)

The diagram source is `assets/diagrams/policy-flow.d2`; re-render with `make diagrams` after edits.

## Install

The plugin slots into a standard Alliance Auth project tree. AA's `auth-helper` generates this
layout (`myauth` is the project name you picked at `auth-helper init` time — substitute it
everywhere below):

```text
myauth/
├── manage.py
└── myauth/
    ├── settings/
    │   ├── base.py        # AA-shipped, do not edit
    │   └── local.py       # YOUR overrides — every setting in this guide goes here
    ├── urls.py            # YOUR project URL patterns
    └── ...
```

If you have a different layout, the file *names* are what matters: locate the file that holds
`INSTALLED_APPS` (settings) and the file that holds `urlpatterns` (URL conf), and apply the
edits below to those.

1. Install the fork from PyPI. The fork is published under
   `allianceauth-oidc-provider-eveo7` to avoid colliding with the upstream
   `allianceauth-oidc-provider` release; the import path
   (`allianceauth_oidc`) is unchanged, so settings/imports stay drop-in
   compatible:

   ```sh
   pip install allianceauth-oidc-provider-eveo7
   ```

   Do **not** install both `allianceauth-oidc-provider` and
   `allianceauth-oidc-provider-eveo7` into the same environment — both
   ship into the `allianceauth_oidc/` directory and pip will refuse the
   second install with a file conflict. Remove the upstream package
   first if it is present.

   Tracking `main` directly is also supported:

   ```sh
   pip install "git+https://github.com/6RUN0/allianceauth-oidc-provider.git@current"
   ```

2. **In `myauth/settings/local.py`**, append to `INSTALLED_APPS`:

   ```python
   INSTALLED_APPS += [
       "allianceauth_oidc",
       "oauth2_provider",
   ]
   ```

3. **In the same `myauth/settings/local.py`**, append the DOT + policy-validator configuration.
   The whole block is wrapped in an `if "allianceauth_oidc" in INSTALLED_APPS …` guard so the
   file stays valid even if the plugin is uninstalled later. Each key is explained in
   [Configuration → OAUTH2_PROVIDER keys](#oauth2_provider-keys); paste this verbatim and tune
   to taste:

   ```python
   from pathlib import Path

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
           "PKCE_REQUIRED": True,
           "ROTATE_REFRESH_TOKEN": True,
           "REFRESH_TOKEN_REUSE_PROTECTION": True,
           "ACCESS_TOKEN_EXPIRE_SECONDS": 60,
           "REFRESH_TOKEN_EXPIRE_SECONDS": 24 * 60 * 60,
       }
   ```

4. **In `myauth/urls.py`**, mount the OIDC URL conf under `/o/`:

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

5. From the project root (`myauth/`), run the migrations and restart Auth:

   ```sh
   python manage.py migrate
   supervisorctl restart myauth:    # or your process supervisor's equivalent
   ```

> [!NOTE]
> If you customise the public login template
> (`authentication/templates/public/login.html`), keep the SSO link's `next` parameter
> URL-encoded — without it the OAuth flow drops query parameters after redirect (e.g.
> `client_id` is lost):
>
> ```html
> <a href="{% url 'auth_sso_login' %}{% if request.GET.next %}?next={{ request.GET.next | urlencode }}{% endif %}"></a>
> ```

## Configuration

The previous section already shows the paste-ready settings block. This section is the per-key
reference for tuning. Two surfaces:

- DOT's `OAUTH2_PROVIDER` dict — required for the protocol to work.
- Our optional `ALLIANCEAUTH_OIDC_*` Django settings — for logging / claim shape / portrait
  template. All of them have sensible defaults.

Both go into `myauth/settings/local.py` next to the install snippet.

### OAUTH2_PROVIDER keys

| Setting | Recommended value | Why |
|---|---|---|
| `OAUTH2_PROVIDER_APPLICATION_MODEL` | `"allianceauth_oidc.AllianceAuthApplication"` | **Required.** Without this the state / group access policy is silently bypassed. Set as a top-level Django setting, not inside `OAUTH2_PROVIDER`. |
| `OIDC_ENABLED` | `True` | **Required.** Turns on DOT's OIDC layer (discovery, JWKS, id_token signing). |
| `OIDC_RSA_PRIVATE_KEY` | `Path("/path/to/key").read_text()` | **Required.** RSA key DOT uses to sign id_tokens. See [DOT docs](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key) for generation. |
| `OAUTH2_VALIDATOR_CLASS` | `"allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"` | **Required.** Implements the three-layer policy and AA-specific claims. |
| `APPLICATION_ADMIN_CLASS` | `"allianceauth_oidc.admin.ApplicationAdmin"` | **Required.** AA-aware admin for the custom `Application` model. |
| `SCOPES` | `{"openid": "...", "email": "...", "profile": "..."}` | **Required.** Scopes shown on the consent screen. Strings are user-facing labels. |
| `PKCE_REQUIRED` | `True` | Recommended per RFC 9700. Disable only if you control all clients and they support PKCE. |
| `ROTATE_REFRESH_TOKEN` | `True` | Recommended. Mints a fresh refresh token on every use; old one is invalidated. |
| `REFRESH_TOKEN_REUSE_PROTECTION` | `True` | Recommended. Replay-defence per RFC 6819 §5.2.2.3 — a refresh token presented twice revokes the entire token family. |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | `60` | Trade-off: shorter access-token TTL forces RPs to refresh more often (faster reaction to revocation, more token-endpoint round-trips); longer means slower revocation propagation but lighter traffic. |
| `REFRESH_TOKEN_EXPIRE_SECONDS` | `24*60*60` | Per-deployment risk tolerance. |

### Custom settings (ALLIANCEAUTH_OIDC_*)

| Setting | Default | Effect |
|---|---|---|
| `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS` | `False` | Replace `<redacted>` with masked fragments (`he…il`) in app debug logs. Enable only if log storage is restricted. |
| `ALLIANCEAUTH_OIDC_LOG_MASK_HEAD` | `2` | Visible characters at the start of a masked secret. |
| `ALLIANCEAUTH_OIDC_LOG_MASK_TAIL` | `2` | Visible characters at the end. |
| `ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX` | `"eve_"` | Prefix for the EVE-specific claims. `""` removes the prefix (collision risk); any other value namespaces them. |
| `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE` | `"profile"` | OIDC scope that gates the EVE claims. **Class-level binding** — changing it requires an Auth restart. |
| `ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE` | `"https://images.evetech.net/characters/{character_id}/portrait?size={size}"` | URL template for the `picture` claim. Both `{character_id}` and `{size}` placeholders are required; a malformed template skips the claim with a warning. |
| `ALLIANCEAUTH_OIDC_PORTRAIT_SIZE` | `128` | Pixel size requested from the portrait service. EVE supports 32 / 64 / 128 / 256 / 512 / 1024. |

### Periodic cleanup of expired tokens (Celery Beat)

The `clear_expired_tokens` task is shipped but **not** scheduled by default — operators add it
to `CELERYBEAT_SCHEDULE` in `myauth/settings/local.py`:

```python
from celery.schedules import crontab

CELERYBEAT_SCHEDULE["allianceauth_oidc_clear_expired_tokens"] = {
    "task": "allianceauth_oidc.clear_expired_tokens",
    "schedule": crontab(minute=0, hour="*/2"),  # every 2 hours
}
```

The task is idempotent (deletes only already-expired rows); broker authentication is the defence
against unauthorised re-runs.

## Reference

### Endpoints

| Endpoint | Path | Notes |
|---|---|---|
| Authorization | `/o/authorize/` | Policy-aware (three-layer gate). Overridden in this app. |
| Token | `/o/token/` | Audit signal + safe debug logging. Overridden in this app. |
| UserInfo | `/o/userinfo/` | DOT default. |
| Discovery | `/o/.well-known/openid-configuration/` | DOT default. |
| JWKS | `/o/.well-known/jwks.json` | DOT default. |
| Token revocation | `/o/revoke_token/` | RFC 7009. DOT default. |
| Token introspection | `/o/introspect/` | RFC 7662. DOT default. |
| RP-initiated logout | `/o/logout/` | DOT default. |
| Issuer (`iss` claim) | `https://your.host/o/` | Whatever your discovery URL resolves to. |

### Claims

Every standard OIDC claim is emitted under the scope conventionally associated with it; the
`groups` and `eve_*` claims are AA-specific and ride the `profile` scope by default so RPs that
already request `openid profile` get them without extra setup.

| Claim | Source | Scope |
|---|---|---|
| `sub` | `User.pk` (DOT default) | `openid` |
| `email` | `user.email` | `email` |
| `name` | `user.profile.main_character.character_name` | `profile` |
| `picture` | Portrait URL for the main character (see `ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE`) | `profile` |
| `groups` | `user.groups[*].name`, with `user.profile.state.name` appended | `profile` |
| `locale` | `user.profile.language` | `profile` |
| `eve_character_id` | `main_character.character_id` | `profile` (set by `ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE`) |
| `eve_corporation_id` / `_name` / `_ticker` | `main_character.corporation_*` | same |
| `eve_alliance_id` / `_name` / `_ticker` | `main_character.alliance_*` (omitted for NPC corps without an alliance) | same |

The `eve_*` prefix is configurable. Empty values are **omitted** from the payload, not emitted as
`null`, so RPs that key off `claim in payload` behave consistently.

The `groups` claim is capped at **256 entries** to keep id_tokens under the typical 8 KB
header / cookie limit. The state name is appended **after** truncation so consumers that rely on
the state being present don't lose it silently. Override the cap by subclassing
`AllianceAuthOAuth2Validator` and overriding the `MAX_GROUPS_IN_CLAIM` class attribute.

### Audit signal

Every successful token-issuance fires the `oidc_token_issued` Django signal
(`allianceauth_oidc.signals`). The default receiver writes a redacted audit log entry; connect
your own receiver to forward to a SIEM, write to a separate audit table, or push into an alerting
pipeline:

```python
from django.dispatch import receiver
from allianceauth_oidc.signals import oidc_token_issued

@receiver(oidc_token_issued)
def forward_to_siem(sender, *, app, user, request, body, **kwargs):
    # `body` is already redacted (build_oidc_debug_meta); never re-add raw secrets.
    ...
```

Don't extend `TokenView` to do this — the signal is the documented integration point and survives
DOT version bumps that change view internals.

## Operations

### Operator commands

Four `manage.py` commands cover the day-2 operational tasks without opening the admin UI. All
accept `--format=table|json|csv`; destructive commands honour `--dry-run`.

| Command | Purpose | Destructive? | Key flags |
|---|---|---|---|
| `oidc_create_app` | Bootstrap a new OIDC application (CI / Ansible-friendly). Prints the raw `client_secret` once. | yes | `--name`, `--user-id`, `--redirect-uri`, `--state`, `--group`, `--client-type`, `--grant-type`, `--debug-mode` |
| `oidc_rotate_secret` | Rotate `client_secret` on an existing app. Existing tokens stay valid until expiry. | yes | `--client-id`, `--dry-run` |
| `oidc_revoke_user_tokens` | Revoke every active access + refresh token for a user (off-boarding, compromise response). Idempotent. | yes | `--username`, `--dry-run` |
| `oidc_audit_tokens` | Read-only listing of active tokens. | no | `--username`, `--client-id`, `--include-expired` |

```sh
python manage.py oidc_create_app \
    --name="Grafana" --user-id=1 \
    --redirect-uri="https://grafana.example/login/generic_oauth" \
    --state=Member --group=Operators --format=json

python manage.py oidc_rotate_secret --client-id=abc123 --dry-run
python manage.py oidc_revoke_user_tokens --username=alice
python manage.py oidc_audit_tokens --client-id=abc123 --format=csv
```

`create_app` writes a Django admin `LogEntry` on success so the action is visible in `/admin/`'s
history without code changes; the destructive commands log at `INFO` / `WARNING`.

### Debug logging

Per-application `Debug Mode` (toggled in the admin) escalates token-flow logs from `DEBUG` to
`INFO`. Raw token values and secrets are **never** logged; the `_LOG_MASKED_SECRETS` knob (see
[Custom settings](#custom-settings-allianceauth_oidc_)) controls whether they appear as
`<redacted>` or masked fragments.

When debugging an app, look for lines like:

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views:78] OIDC DEBUG token issued
app_id=1 client_id=abc123 user_id=42
meta={'grant_type': 'authorization_code', ..., 'access_token': '<redacted>', 'id_token': '<redacted>'}
```

Paste the (separately captured) `id_token` into <https://jwt.io/> to inspect claims. The two
non-obvious fields:

- `iss` — issuer; must match the value the RP has configured exactly.
- `sub` — the user PK; useful for "why did this user end up here?" triage.

If you need the public key to verify the signature on jwt.io and have only the private key on
disk:

```sh
ssh-keygen -y -e -m pem -f /path/to/key
```

### Operational hardening (operator responsibility)

The provider implements the OAuth2 / OIDC protocol semantics; runtime hardening below is
intentionally left to the deployment so it integrates with whatever edge / infra you already
operate.

- **Rate-limit `/o/token/` and `/o/authorize/`.** Neither endpoint is rate-limited by this app;
  brute-force defence belongs at the edge (nginx `limit_req`, Cloudflare, a WAF) or via
  `django-ratelimit` in your Auth deployment. Without it, a network-level attacker can probe
  `client_secret` / `code` / `refresh_token` values at line speed.
- **Authenticate the Celery broker.** `clear_expired_tokens` is published to whichever broker
  your AA install uses; if that broker is reachable by untrusted parties, a malicious task
  submission can repeatedly invoke cleanup. The task is idempotent, but broker auth + network
  ACLs are the defensive layer.
- **Security headers.** This app does not set CSP / HSTS / `X-Frame-Options` /
  `X-Content-Type-Options`; rely on Alliance Auth's middleware stack and Django's `SECURE_*`
  settings to add them globally.

## Integrations

### Register an application

In `/admin/allianceauth_oidc/`, create an `Alliance Auth application`:

| Field | Value | Notes |
|---|---|---|
| `User` | any (e.g. `1`) | Owner — passed through to DOT but not used in this app's policy. |
| `Client type` | `confidential` | Public clients are out of scope; we don't ship a public-client recipe. |
| `Authorization grant type` | `Authorization code` | The only flow this app's policy is hardened against. |
| `Client secret` | auto-generated | Save it before clicking save when `HASH_CLIENT_SECRET` is on (default). |
| `Algorithm` | `RSA with SHA-2 256` | Matches `OIDC_RSA_PRIVATE_KEY`. |
| `States` / `Groups` | whitelist | Empty ⇒ open; non-empty ⇒ user must be in a listed state OR group. |

Every user who logs into any registered application also needs the global
`allianceauth_oidc.access_oidc` permission. Without it the dispatch-layer gate (Layer 1) returns
`PermissionDenied` regardless of state / group whitelist.

### Grafana

Tested without group-to-team mapping (group → team mapping requires Grafana Cloud / Enterprise
and is out of scope here).

```ini
[server]
root_url = <URL of your grafana server>

[auth.generic_oauth]
enabled = true
name = <Your Auth Name>
allow_sign_up = true
client_id = <client_id>
client_secret = <unhashed client_secret>
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://<your.auth.url>/o/authorize/
token_url = https://<your.auth.url>/o/token/
api_url = https://<your.auth.url>/o/userinfo/
```

### WikiJS

Pre-create the groups you want WikiJS users to land in on the AA side; WikiJS will map them at
login. (Create an `Administrators` group to grant the wiki admin pages.)

| WikiJS field | Value |
|---|---|
| Skip User Profile | off |
| Email claim | `email` |
| Display Name Claim | `name` |
| Map Groups | on |
| Groups Claim | `groups` |
| Allow Self Registration | on |

## Development

### Nox sessions

| Session | Purpose | In default `nox` run? |
|---|---|---|
| `lint` | pre-commit (ruff, mypy, basedpyright, …) | yes |
| `tests` | Django test suite (parallel) | yes |
| `coverage` | tests + term / HTML / XML coverage reports | no |
| `typecheck` | mypy + basedpyright (subset of `lint`, run separately for fast feedback) | no |
| `audit` | pip-audit | no |
| `markdown_lint` | rumdl + lychee + vale (each tool optional) | no |
| `makemessages` / `compilemessages` | i18n catalogue refresh + compile | no |
| `makemigrations` | generate Django migrations under test settings | no |
| `integration` | wire-level mock-RP via `LiveServerTestCase` | no |
| `conformance` | OIDC Conformance Suite via docker-compose | no |

### Integration tests (`nox -s integration`)

`tests/test_integration_mock_rp.py` boots a `LiveServerTestCase` and walks the OIDC code flow
with `requests` + `jwcrypto`, validating the id_token signature against a JWKS retrieved over the
wire. This catches regressions the standard `nox -s tests` set cannot — Django's test client
short-circuits the WSGI layer, so absolute-URL bugs in `iss` / `jwks_uri` and Bearer-header /
cookie issues only surface here.

The session forces `--parallel=1`: `LiveServerTestCase` shares its DB connection with the WSGI
thread, which does not survive the test runner's `fork()`.

### Conformance Suite (`nox -s conformance`)

Runs the [OpenID Foundation Conformance Suite](https://gitlab.com/openid/conformance-suite)
against the provider via Docker Compose: MongoDB + the suite + a provider container. The default
plan is driven through the suite's REST API by `tests/conformance/run_plan.py`.

This is the level above our own integration tests — it catches spec edge cases that our
regression tests wouldn't think to check. Run before tagging a release. See
[tests/conformance/README.md](tests/conformance/README.md) for prerequisites, the manual /
iterative workflow, configuration overrides, and the list of known conformance findings to
triage.
