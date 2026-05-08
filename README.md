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
- [Requirements](#requirements)
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

## Requirements

| Component             | Supported versions                              |
|-----------------------|-------------------------------------------------|
| Python                | 3.10, 3.11, 3.12, 3.13                          |
| Alliance Auth         | 4.x and 5.x                                     |
| Django                | 4.2 (with AA 4.x) or 5.2 (with AA 5.x)          |
| `django-oauth-toolkit`| `>=3.2,<4`                                      |

CI exercises the AA 5.x stack on every supported Python version and AA 4.x
backward compatibility on Python 3.12. Both stacks share the same code path —
no version-specific shims live in the package itself.

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

   Tracking `current` directly is also supported:

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

   # Per-app PKCE resolver. DOT does NOT auto-import this setting —
   # it must be a callable, not a dotted-path string. The adapter is
   # imported from a lightweight module that is safe to load before
   # ``apps.populate()`` (which Django runs after settings).
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

## Upgrading from a previous release

Greenfield installs follow [Install](#install) — the ordering caveats below do not apply. This
section is for operators carrying live OAuth applications across an upgrade.

### Per-app PKCE field (`pkce_required`)

`OAUTH2_PROVIDER['PKCE_REQUIRED']` changed from a boolean to a callable, and a new data
migration backfills `AllianceAuthApplication.pkce_required` from the previous global value.

**Run the steps in this order:**

1. `pip install -U allianceauth-oidc-provider-eveo7` — do not edit `local.py` yet.
2. `python manage.py migrate` — **leave `OAUTH2_PROVIDER['PKCE_REQUIRED']` at its previous
   boolean** while migrate runs. The data step reads the global at runtime and writes that
   value to every existing app, so live behaviour is preserved across the upgrade.
3. Edit `myauth/settings/local.py`: replace the boolean `PKCE_REQUIRED` with the callable as
   shown in [Install step 3](#install). Per-app overrides via Django admin from then on.
4. Restart Auth (`supervisorctl restart myauth:` or your supervisor's equivalent).
5. *Optional:* a long-lived process that already imported `OAUTH2_PROVIDER` can pick up the
   change without a full restart by calling `oauth2_settings.reload()`.

If steps 2 and 3 are run out of order — i.e. the callable is in place when `migrate` runs —
the data step detects the non-boolean value, fails over to RFC 9700 secure-by-default, and
force-sets every existing app to `pkce_required=True`. Recovery is to flip individual apps
back to `False` via Django admin. The matching `RuntimeWarning` is described under
[Operations → Per-app PKCE](#per-app-pkce).

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
| `PKCE_REQUIRED` | `per_app_pkce_required` (callable, imported from `allianceauth_oidc.pkce`) | Per-app override resolved from `AllianceAuthApplication.pkce_required`. New apps default to `True` (RFC 9700); existing apps land at the previous global value at migration time. Unknown `client_id` falls back to `True` and is logged at `WARNING`. Configurable through Django admin. **Note: must be assigned as a function reference, not a dotted-path string — DOT does not auto-import this setting.** |
| `ROTATE_REFRESH_TOKEN` | `True` | Recommended. Mints a fresh refresh token on every use; old one is invalidated. |
| `REFRESH_TOKEN_REUSE_PROTECTION` | `True` | Recommended. Replay-defence per RFC 6819 §5.2.2.3 — a refresh token presented twice revokes the entire token family. |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | `3600` | Trade-off: shorter access-token TTL forces RPs to refresh more often (faster reaction to revocation, more token-endpoint round-trips); longer means slower revocation propagation but lighter traffic. **Do not copy the test-suite literal `60`** — that value is test-only (used by `tests/test_settingsAA4.py` to exercise expiry paths without sleeps) and races against real RP login flows that need at least one /userinfo round-trip plus client-side `clockTolerance` (~5 s). The `passport-openidconnect` strategy used by Wiki.js, Outline, and similar reject sub-minute lifetimes outright. `3600` (1 hour) matches the production defaults of Auth0 / Keycloak / Google. |
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
| `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` | `None` | Tri-state operator override for the `email_verified` claim. `True` always emits `true` (e.g. trust signal originates outside AA — users imported from an already-verifying external IdP). `False` always emits `false`. `None` (default) falls through to the auto decision tree: synthetic placeholder addresses from the optional `aa-skip-email` plugin → `false`; otherwise mirrors AA's `REGISTRATION_VERIFY_EMAIL` setting. |

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
| `email_verified` | Auto: `false` for synthetic placeholders (when `aa-skip-email` is installed); otherwise mirrors AA's `REGISTRATION_VERIFY_EMAIL`. Override via `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`. | `email` (paired with `email`) |
| `acr` | `"0"` (RFC 6711 "no specific level") when the client sent `acr_values`; absent otherwise. | id_token only |
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

#### id_token vs /userinfo

Per OIDC Core 1.0 §5.4, scope-bound claims (everything in the table above except `sub`, `iss`,
`aud`, standard JWT timestamps, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`, `c_hash`,
`jti`) live in `/userinfo` by default — they do **not** travel inside the id_token. An RP that
needs them in the id_token specifically must opt in via the OIDC `claims` request parameter, e.g.
`claims={"id_token": {"email": null, "groups": null}}`. This keeps id_tokens lean and avoids the
"every claim everywhere" anti-pattern that breaks header / cookie size budgets.

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

### Application fields

Beyond DOT's `AbstractApplication` schema, `AllianceAuthApplication` adds:

- `states` (M2M) and `groups` (M2M) — access whitelist; empty = open.
- `active` — `is_usable()` returns this; deactivated apps cannot issue codes.
- `debug_mode` — per-app flag escalating log level (see *Debug logging*).
- `pkce_required` — per-app PKCE enforcement; resolved by
  `pkce.per_app_pkce_required` (delegates to `AccessPolicy.pkce_required`).

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

### Per-app PKCE

`AllianceAuthApplication.pkce_required` is a per-app boolean flipped through Django admin (column
on the changelist, checkbox on the edit form, list filter). DOT consults it on every authorize
request via the `per_app_pkce_required` callable wired into `OAUTH2_PROVIDER`.

- **New apps** default to `True` per RFC 9700 (secure-by-default).
- **Existing apps after upgrade** are backfilled from the previous global
  `OAUTH2_PROVIDER['PKCE_REQUIRED']` at migration time. Migrating from a global `False` lands
  every existing row at `False`; from a global `True`, every row lands at `True`. Operators opt
  in/out per-app afterward via admin.
- **Unknown `client_id`** (none of the registered apps match) falls back to `True` and is logged
  at `WARNING` so anomalous traffic is visible in the audit log.
- **No caching layer** — each authorize request reads the row through DOT's per-request hook with
  a single SELECT bounded to the `pkce_required` column.

> **Toggling `pkce_required` does not affect already-issued authorization codes.** Codes carry
> their issuance-time PKCE contract; the token-exchange enforces the same contract. An admin
> toggle while a flow is in progress neither retroactively secures nor retroactively weakens
> that flow.
>
> **Migration warning on a non-boolean global.** If `manage.py migrate` raises a Python
> `RuntimeWarning` mentioning
> `OAUTH2_PROVIDER['PKCE_REQUIRED'] is <type> (expected bool); backfilling pkce_required=True`,
> your previous `local.py` already defined a custom resolver, **or** you swapped
> `PKCE_REQUIRED` for the `per_app_pkce_required` callable before running migrate (see
> [Upgrading from a previous release](#upgrading-from-a-previous-release) for the correct
> ordering), **or** the key is missing / `None`. Any non-boolean value is ambiguous, so the
> migration falls back to RFC 9700 secure-by-default — every existing app is set to `True`
> and the global setting is left untouched. Review per-app values via Django admin afterward.
> Greenfield installs (no pre-existing app rows) skip the warning entirely.

**Bulk operations.** Single toggles use admin; for >5 apps the ORM is faster:

```python
# manage.py shell
from allianceauth_oidc.models import AllianceAuthApplication

# Disable PKCE for everything matching a name prefix:
AllianceAuthApplication.objects.filter(
    name__startswith="Legacy-"
).update(pkce_required=False)

# Or by client_id list:
AllianceAuthApplication.objects.filter(
    client_id__in=["abc", "def"]
).update(pkce_required=False)
```

`QuerySet.update()` does not call `Model.save()`, so it bypasses `pre_save` / `post_save`
signals and does not write a Django admin `LogEntry` for each row touched. The trade-off
is intentional — bulk updates are atomic and fast. If you need an audit trail, loop over
`.all()` and call `instance.save(update_fields=["pkce_required"])` per row, or paste a one-line
record into your operations log noting the filter expression and timestamp.

Reverse direction is identical (`pkce_required=True`). For *new* apps created from CLI rather
than admin, `oidc_create_app --no-pkce-required` opts out at creation time without a follow-up
admin visit; the default is `True`.

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

WikiJS ships two compatible strategies: **Generic OpenID Connect / OAuth 2.0** (strict OIDC,
validates `id_token` against JWKS) and **Generic OAuth 2.0** (no `id_token` validation, just
`/userinfo`). Either works against this provider; the OIDC strategy is recommended unless your
deployment hits cryptographic edge cases (custom `iss`, JWKS rotation, clock skew).

Pre-create the groups you want WikiJS users to land in on the AA side; WikiJS will map them at
login. (Create an `Administrators` group to grant the wiki admin pages.)

| WikiJS field | Value |
|---|---|
| Authorization Endpoint URL | `https://auth.example.com/o/authorize/` |
| Token Endpoint URL | `https://auth.example.com/o/token/` |
| User Info Endpoint URL | `https://auth.example.com/o/userinfo/` |
| Issuer | exact value of `issuer` from `https://auth.example.com/o/.well-known/openid-configuration` (mind the trailing slash — strict validators reject mismatched issuers) |
| Skip User Profile | **off** — see warning below |
| Logout URL *(optional)* | `https://auth.example.com/o/logout/` |
| Client ID | `<client_id>` from `AllianceAuthApplication` admin |
| Client Secret | `<client_secret>` from `AllianceAuthApplication` admin |
| Scopes | `openid profile email` |
| User ID Claim | `sub` |
| Email claim | `email` |
| Display Name Claim | `name` |
| Avatar Claim | `picture` |
| Map Groups | on |
| Groups Claim | `groups` |
| Allow Self Registration | on |

> **Do not enable «Skip User Profile».** The flag tells WikiJS to read profile claims out of the
> `id_token` only, skipping the call to `/userinfo`. This provider follows OIDC Core 1.0 §5.4
> strictly — `email`, `name`, `picture`, `groups`, `locale` are emitted **only** at `/userinfo`,
> never inside `id_token`. WikiJS with `Skip User Profile = on` lands at the
> *"Missing or invalid email address from profile"* error during user creation.
>
> **Mind `ACCESS_TOKEN_EXPIRE_SECONDS`.** WikiJS goes through the token endpoint then makes one
> further call to `/userinfo`; with `clockTolerance` defaults around 5 s plus network latency, an
> access token shorter than ~30 s is unsafe in practice. Stick to the recommended `3600` (see
> [`OAUTH2_PROVIDER` keys](#oauth2_provider-keys)).

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
