# allianceauth-oidc-provider-eveo7

A thin policy / auditing layer on top of
[`django-oauth-toolkit`](https://django-oauth-toolkit.readthedocs.io/) that turns an
[Alliance Auth](https://gitlab.com/allianceauth/allianceauth) installation into an OpenID Connect /
OAuth2 provider.

> Fork of
> [Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
> maintained at
> [6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) — adds
> wire-level integration tests, an OIDC Conformance Suite harness, operator CLI commands,
> EVE-specific claims, runtime localisation (en / ru / uk), and a Russian-language
> [README.ru.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/README.ru.md).

- [Overview](#overview)
- [Requirements](#requirements)
- [Install](#install)
- [Upgrading from a previous release](#upgrading-from-a-previous-release)
- [Configuration](#configuration)
- [Reference](#reference)
- [Operations](#operations)
- [Integrations](#integrations)
- [Limitations](#limitations)
- [Development](#development)
- [Links](#links)
- [License](#license)

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
backward compatibility on Python 3.10–3.12 (AA 4.13.x declares
`requires-python <3.13`, so Python 3.13 is excluded from the AA 4.x dimension).
Both stacks share the same code path — no version-specific shims live in the
package itself.

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

   For Prometheus metrics, install the extra:
   `pip install allianceauth-oidc-provider-eveo7[metrics]` (see the
   [Observability section](#observability--prometheus-metrics)).

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

6. Verify the provider responds:

   ```sh
   curl -s https://your.host/o/.well-known/openid-configuration | python -m json.tool
   ```

   You should see `issuer`, `authorization_endpoint`, `jwks_uri`, and
   `backchannel_logout_supported`.

> **Note:** If you customise the public login template
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

### RP-Initiated Logout default-on (0.3.1)

`OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` now defaults to `True` via the AppConfig —
the `/o/logout/` route and the `end_session_endpoint` field in
`.well-known/openid-configuration` become live without operator opt-in. DOT's upstream default
is `False`; the override is applied through `setdefault`, so an explicit `False` in your
settings is preserved.

If your deployment relies on the previous behaviour (`/o/logout/` 404, no `end_session_endpoint`
in discovery), set the key explicitly:

```python
OAUTH2_PROVIDER["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = False
```

Disabling RP-init logout while back-channel logout RPs are registered breaks the Single-Logout
chain at the first hop — `manage.py check` emits `allianceauth_oidc.W003` to surface the
configuration smell. See [System checks](#system-checks-managepy-check) for the warning text.

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
| `OIDC_RSA_PRIVATE_KEYS_INACTIVE` | `[]` (or list of retiring PEMs) | Optional. PEMs of previously-active signing keys still published in JWKS so already-issued tokens validate during the rotation window. Used by `manage.py oidc_jwks_rotate` workflow: mint a fresh key with the command, append the old PEM here, swap `OIDC_RSA_PRIVATE_KEY` to the new one, drop entries from this list after `ACCESS_TOKEN_EXPIRE_SECONDS + clockTolerance` has elapsed. |
| `OAUTH2_VALIDATOR_CLASS` | `"allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"` | **Required.** Implements the three-layer policy and AA-specific claims. |
| `APPLICATION_ADMIN_CLASS` | `"allianceauth_oidc.admin.ApplicationAdmin"` | **Required.** AA-aware admin for the custom `Application` model. |
| `SCOPES` | `{"openid": "...", "email": "...", "profile": "..."}` | **Required.** Scopes shown on the consent screen. Strings are user-facing labels. |
| `PKCE_REQUIRED` | `per_app_pkce_required` (callable, imported from `allianceauth_oidc.pkce`) | Per-app override resolved from `AllianceAuthApplication.pkce_required`. New apps default to `True` (RFC 9700); existing apps land at the previous global value at migration time. Unknown `client_id` falls back to `True` and is logged at `WARNING`. Configurable through Django admin. **Note: must be assigned as a function reference, not a dotted-path string — DOT does not auto-import this setting.** |
| `ACCESS_TOKEN_GENERATOR` | `"allianceauth_oidc.tokens.dispatching_access_token_generator"` | **Required only when activating JWT mode** (RFC 9068). Dotted-path string is fine here — `ACCESS_TOKEN_GENERATOR` IS in DOT's `IMPORT_STRINGS`, so DOT resolves the path at startup. Contrast with `PKCE_REQUIRED` (function-reference). See [JWT access tokens](#jwt-access-tokens-rfc-9068). |
| `ROTATE_REFRESH_TOKEN` | `True` | Recommended. Mints a fresh refresh token on every use; old one is invalidated. |
| `REFRESH_TOKEN_REUSE_PROTECTION` | `True` | Recommended. Replay-defence per RFC 6819 §5.2.2.3 — a refresh token presented twice revokes the entire token family. |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | `3600` | Trade-off: shorter access-token TTL forces RPs to refresh more often (faster reaction to revocation, more token-endpoint round-trips); longer means slower revocation propagation but lighter traffic. **Do not copy the test-suite literal `60`** — that value is test-only (used by `tests/test_settingsAA4.py` to exercise expiry paths without sleeps) and races against real RP login flows that need at least one /userinfo round-trip plus client-side `clockTolerance` (~5 s). The `passport-openidconnect` strategy used by Wiki.js, Outline, and similar reject sub-minute lifetimes outright. `3600` (1 hour) matches the production defaults of Auth0 / Keycloak / Google. |
| `REFRESH_TOKEN_EXPIRE_SECONDS` | `24*60*60` | Per-deployment risk tolerance. |
| `OIDC_ISS_ENDPOINT` | unset | **Required when ANY application has `backchannel_logout_uri` set.** Absolute issuer URL (e.g. `"https://auth.example.org/o"`). The Celery worker that POSTs `logout_token`s has no HTTP request context, so it cannot derive `iss` at runtime — `oidc_issuer(None)` falls through to this setting. A Django system check (`allianceauth_oidc.E001`) fires at `manage.py check` if a back-channel logout is configured without this setting; CI fails loudly instead of crashing the first end-user logout. See [OIDC Back-Channel Logout 1.0](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/BACK_CHANNEL_LOGOUT.md). |
| `OIDC_RP_INITIATED_LOGOUT_ENABLED` | `True` (default-on) | OIDC RP-Initiated Logout 1.0 — `/o/logout/` + `end_session_endpoint` in discovery. DOT's upstream default is `False`; the AppConfig's `_apply_default_oauth2_provider_settings` flips it to `True` only when the key is absent, so an explicit `False` opt-out is preserved. Pair with `OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT` (DOT default `True`) — DOT renders `oauth2_provider/logout_confirm.html` on logout requests; this app ships an AA-themed override under `allianceauth_oidc/templates/allianceauth_oidc/logout_confirm.html` (resolved by Django via template precedence). Set the prompt setting to `False` to skip the confirm step for headless flows. |

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
| `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT` | `"opaque"` | Wire format for newly issued access tokens when an app's `access_token_format` field is blank. Set to `"jwt"` to enable RFC 9068 globally; per-app `access_token_format` overrides this. Operators must also wire `ACCESS_TOKEN_GENERATOR` (above) for JWT mode to activate; the startup log emits a `WARNING` if only one of the two is configured. See [JWT access tokens](#jwt-access-tokens-rfc-9068). |
| `ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` | `4096` | Soft size guard for issued JWT access tokens. The generator emits `logger.warning` if a token exceeds this length (likely cause: a fixture user with hundreds of groups). The token is **not** mutated or rejected — operators decide whether to slim claims, raise upstream proxy `Authorization`-header limits (Apache `LimitRequestFieldSize`, nginx `large_client_header_buffers`, HAProxy `tune.bufsize`), or reduce group churn. Effective only under JWT mode. |
| `ALLIANCEAUTH_OIDC_POLICY_URI` | unset | OIDC Discovery 1.0 §3 `op_policy_uri`. Absolute URL of the Authorization Server's privacy policy; surfaced in `.well-known/openid-configuration` when set. Some compliance frameworks (GDPR Art. 13, NIS2) require RPs to link back to AS-side privacy policies — advertising the URL here lets RP login pages auto-link without per-RP static configuration. Omit the key (or set to empty string) to leave it out of discovery. |
| `ALLIANCEAUTH_OIDC_TOS_URI` | unset | OIDC Discovery 1.0 §3 `op_tos_uri`. Absolute URL of the Authorization Server's terms-of-service page; surfaced in `.well-known/openid-configuration` when set. Independent from `ALLIANCEAUTH_OIDC_POLICY_URI` — emit either or both. Omit the key (or set to empty string) to leave it out of discovery. |
| `ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS` | `False` | Persist successful back-channel-logout attempts to `BackChannelLogoutAttempt` in addition to failures. Default keeps the table strictly a dead-letter store (failures only) — flip to `True` when SIEM needs proof-of-delivery rows. Failures are always recorded regardless. |
| `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE` | `False` | Bypass the private / loopback / link-local / multicast / CGNAT DNS gate (both admin-save and worker dispatch-time re-check) on `backchannel_logout_uri`. Required for dev / staging against RPs on `192.168.x.x`, `10.x.x.x`, k8s overlay, etc. With `DEBUG=False` raises `W005`; with `DEBUG=True` stays quiet. See [Local testing on a private network](#local-testing-on-a-private-network). |
| `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION` | `False` | Production-only acknowledgement that pairing `DEBUG=False` with `_LOGOUT_URI_ALLOW_PRIVATE=True` is intentional. Without this opt-in, the same combination triggers `E006` and `manage.py check` fails — a safety net so dev-time SSRF-bypass settings don't leak into prod by accident. |

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

### Observability — Prometheus metrics

The provider ships an **opt-in** Prometheus surface that cooperates with
[`django-prometheus`](https://github.com/korfuri/django-prometheus). Operators install the
extra to activate it:

```sh
pip install allianceauth-oidc-provider-eveo7[metrics]
```

Without the extra, the receiver chain still wires (every signal hits a no-op stub), so install
or test paths are byte-identical with or without metrics enabled. The provider **never** mounts
its own `/metrics` view or middleware — exposing the shared `prometheus_client.REGISTRY` is
`django-prometheus`'s job; operators control where `/metrics` becomes reachable.

All metric names use the `aa_oidc_*` prefix so a Grafana dashboard built around it cleanly
composes with sibling AA modules that adopt the same convention. Published metrics:

| Metric | Type | What it counts |
|---|---|---|
| `aa_oidc_tokens_issued_total` | Counter | Successful access/refresh/id-token issuances (labelled by `grant_type`, `format`) |
| `aa_oidc_authorize_denied_total` | Counter | Authorize-endpoint rejections (labelled by `reason`) |
| `aa_oidc_bcl_delivery_seconds` | Histogram | End-to-end latency of a BCL `logout_token` POST attempt |
| `aa_oidc_bcl_dispatches_total` | Counter | BCL terminal-state outcomes (success / retry-exhausted / dead-letter) |
| `aa_oidc_policy_rejections_total` | Counter | Three-layer policy denials (labelled by call-site: code / refresh / bearer / save) |
| `aa_oidc_code_reuse_audit_misses_total` | Counter | Code-reuse audit-row inserts that lost a unique-index race |
| `aa_oidc_code_audit_skipped_total` | Counter | Code-flow exchanges that proceeded without an audit row (skip path) |
| `aa_oidc_tokens_cleaned_total` | Counter | Rows deleted by `clear_expired_tokens` (DOT tokens + audit GC) |
| `aa_oidc_audit_receiver_failures_total` | Counter | Audit-receiver exceptions swallowed before they would have broken the signal chain |

See [docs/METRICS.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/METRICS.md) for the full contract: label cardinality, histogram
bucket layout, the no-op stub API, and the cross-module `aa_<module>_*` namespacing rules.

## Reference

### Endpoints

| Endpoint | Path | Notes |
|---|---|---|
| Authorization | `/o/authorize/` | Policy-aware (three-layer gate). Overridden in this app. |
| Token | `/o/token/` | Audit signal + safe debug logging. Overridden in this app. |
| UserInfo | `/o/userinfo/` | OIDC Core §5.3. Overridden in this app — adds `Cache-Control: no-store` and `Pragma: no-cache` per §5.3.2. |
| Discovery | `/o/.well-known/openid-configuration/` | OIDC Discovery 1.0 §3 / RFC 8414. Overridden in this app — emits the §3 RECOMMENDED fields DOT omits plus `backchannel_logout_supported`. |
| JWKS | `/o/.well-known/jwks.json` | RFC 7517. Overridden in this app — adds `Access-Control-Allow-Origin: *` so browser-based RPs can fetch the JWKS. |
| Token revocation | `/o/revoke_token/` | RFC 7009. DOT default. |
| Token introspection | `/o/introspect/` | RFC 7662. Overridden in this app — adds per-app gating plus the `oidc_token_introspected` audit signal. |
| Token management UI | `/o/authorized_tokens/` (+ `/o/authorized_tokens/<pk>/delete/`) | DOT default. Lets a signed-in user list and revoke their own outstanding tokens. No customisation needed; mounted as-is. |
| RP-initiated logout | `/o/logout/` | DOT view; default-on via AppConfig (`OIDC_RP_INITIATED_LOGOUT_ENABLED=True` set if absent). |
| Issuer (`iss` claim) | `https://your.host/o` | **No trailing slash.** Without `OIDC_ISS_ENDPOINT`, DOT derives it by stripping `/.well-known/openid-configuration` from the discovery URL — the slash goes with the suffix, so the canonical issuer is the mount prefix minus its slash. RPs validate `iss` byte-for-byte against discovery's `issuer`; if you pin `OIDC_ISS_ENDPOINT`, match this exactly. |

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
| `eve_faction_id` / `_name` | `main_character.faction_*` (omitted when the character has no faction) | same |
| `eve_main_character_id` | Alias of `eve_character_id` to disambiguate when RPs also pull authenticated-character claims | same |
| `eve_affiliation` | Composite `"<corp_ticker>[ / <alliance_ticker>]"` rendered for human-readable logs | same |

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

### Audit signals

`allianceauth_oidc.signals` exposes **five** Django signals (all wired
`use_caching=True`). Default receivers are auto-connected in `AppConfig.ready()` under stable
`dispatch_uid`s so test suites and operators can `disconnect()` them cleanly:

| Signal | Fires on | Default receiver |
|---|---|---|
| `oidc_token_issued` | Every successful access/refresh/id token issuance | `audit_oidc_token_issued` |
| `oidc_code_reuse_detected` | Replay of a previously-exchanged authorization code | `audit_oidc_code_reuse_detected` |
| `oidc_token_introspected` | Every RFC 7662 introspection request | `audit_oidc_token_introspected` |
| `oidc_logout_required` | A logout-relevant lifecycle event needs BCL fan-out (revoke / deactivate / group or state change / account delete) | (no audit receiver — consumed by the dispatch task) |
| `oidc_logout_dispatched` | A back-channel `logout_token` POST attempt terminated (success, retry-exhausted, dead-letter) | `record_backchannel_logout_attempt` |

Connect your own receivers to forward to a SIEM, write to a separate audit table, or push into
an alerting pipeline:

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

#### Sampling high-volume audit signals

`oidc_token_introspected` fires on **every** RFC 7662 introspection request. Resource servers
that introspect on every API call hit it at request rate — forwarding raw to a SIEM that
charges per event volume gets expensive fast. The default receiver writes one `INFO` log line
per event; SIEM forwarders should sample or aggregate rather than pass-through:

```python
import secrets
from django.dispatch import receiver
from allianceauth_oidc.signals import oidc_token_introspected

# 1% reservoir sampler; tune to whatever the SIEM budget allows.
_SAMPLE_RATE = 0.01

@receiver(oidc_token_introspected, dispatch_uid="siem.introspect")
def forward_introspect_sampled(sender, *, request, introspector, body, **kwargs):
    if secrets.SystemRandom().random() > _SAMPLE_RATE:
        return
    # Forward `body` (curated, secret-free per OIDCIntrospectionAuditBody)
    # plus the introspector identity. NEVER forward raw token values.
    ...
```

`oidc_token_issued` and `oidc_code_reuse_detected` are low-rate (issuance and an actual reuse
incident respectively) — pass-through is fine for both.

### Audit tables

#### Code-reuse audit table

RFC 6749 §10.5 SHOULD-clause defence-in-depth: every successful authorization-code exchange
writes a row to `IssuedCodeAudit` (`code_hash`, `application`, `application_client_id_snapshot`,
`access_token_pk`, `refresh_token_pk`, `reuse_count`, `last_reuse_at`, `created_at`). If the
same code is presented a second time, `validate_code` revokes the linked tokens and fires
`oidc_code_reuse_detected` for SIEM correlation. The `application_client_id_snapshot` column is
populated at row insert and survives admin-driven RP deletion (the `application` FK is
`SET_NULL`), so per-RP forensic queries on historical rows keep working.

**Retention**:

- Rows with `reuse_count = 0` are garbage-collected automatically by `clear_expired_tokens`
  once they age past `OAUTH2_PROVIDER['REFRESH_TOKEN_EXPIRE_SECONDS']` — past that point the
  code could no longer be replayed against any token the AS would mint, so the audit row
  carries no further value.
- Rows with `reuse_count >= 1` are **preserved forever** — they are forensic evidence of an
  attempted replay. Operators clean them up explicitly (admin → "Issued code audits") once
  the incident-review window closes.

The `oidc_code_reuse_detected` signal also fires on every replay, so SIEM correlation works
in real time without polling the table. Connect a custom receiver under a unique
`dispatch_uid` to route reuse events through the alerting pipeline.

#### Back-channel logout audit table

`BackChannelLogoutAttempt` is the dead-letter / proof-of-delivery store for the BCL dispatcher.
Columns: `application` (FK, `SET_NULL`), `application_client_id_snapshot`,
`application_name_snapshot`, `user_pk`, `jti`, `success`, `attempt_count`, `reason`,
`created_at`. The snapshot columns survive admin-driven RP deletion, so per-RP forensic queries
on historical rows keep working. Visible in `/admin/` under "Back channel logout attempts".

By default only **failed** attempts land here — the table is strictly a dead-letter store. Set
`ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True` to also persist successful deliveries (proof-of-fan-out
for SIEM). The `oidc_logout_dispatched` signal fires on every terminal attempt regardless, so
real-time SIEM correlation works without polling.

See [docs/BACK_CHANNEL_LOGOUT.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/BACK_CHANNEL_LOGOUT.md) for the retry / dead-letter
contract.

### Application fields

Beyond DOT's `AbstractApplication` schema, `AllianceAuthApplication` adds:

- `states` (M2M) and `groups` (M2M) — access whitelist; empty = open.
- `active` — `is_usable()` returns this; deactivated apps cannot issue codes.
- `debug_mode` — per-app flag escalating log level (see *Debug logging*).
- `pkce_required` — per-app PKCE enforcement; resolved by
  `pkce.per_app_pkce_required` (delegates to `AccessPolicy.requires_pkce`).
- `access_token_format` — per-app override for the access-token wire format
  (`"opaque"` / `"jwt"` / blank). Blank inherits the deployment-wide
  `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT` (default `"opaque"`). See
  [JWT access tokens](#jwt-access-tokens-rfc-9068).

## Operations

### Operator commands

Seven `manage.py` commands cover the day-2 operational tasks without opening the admin UI. All
accept `--format=table|json|csv` where output is structured; destructive commands honour
`--dry-run`.

| Command | Purpose | Destructive? | Key flags |
|---|---|---|---|
| `oidc_create_app` | Bootstrap a new OIDC application (CI / Ansible-friendly). Prints the raw `client_secret` once. | yes | `--name`, `--user-id`, `--redirect-uri`, `--state`, `--group`, `--client-type`, `--grant-type`, `--debug-mode` |
| `oidc_rotate_secret` | Rotate `client_secret` on an existing app. Existing tokens stay valid until expiry. | yes | `--client-id`, `--dry-run` |
| `oidc_revoke_user_tokens` | Revoke every active access + refresh token for a user (off-boarding, compromise response). Idempotent. | yes | `--username`, `--reason`, `--dry-run` |
| `oidc_audit_tokens` | Read-only listing of active tokens. | no | `--username`, `--client-id`, `--include-expired` |
| `oidc_jwks_rotate` | Mint a fresh RSA private key for JWKS rotation; prints PEM + RFC 7638 thumbprint (`kid`) + a four-step rotation recipe. **Read-only** — never touches settings or DB; operator wires the new PEM into `OIDC_RSA_PRIVATE_KEY` and moves the previous one into `OIDC_RSA_PRIVATE_KEYS_INACTIVE` manually. | no | `--out`, `--key-size` |
| `oidc_show_effective_policy` | Inspect the per-app state / group whitelist as it evaluates against a given user, including the global gate. Useful when triaging an unexpected `invalid_grant`. | no | `--username`, `--client-id` |
| `oidc_fix_uuid_columns` | Realign DOT's `UUIDField` columns (`oauth2_provider_idtoken.jti`, `oauth2_provider_refreshtoken.token_family`) with Django's native-`uuid` type on MariaDB `>= 10.7` (fixes the `1406 Data too long` failure on `/o/token/` for `jti` and on refresh-token rotation for `token_family`, after a cross-10.7 MariaDB upgrade). Preserves per-column nullability; no-op on every other backend / already-converted columns. See [docs/MARIADB.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/MARIADB.md). | yes | `--dry-run`, `--format` |

```sh
python manage.py oidc_create_app \
    --name="Grafana" --user-id=1 \
    --redirect-uri="https://grafana.example/login/generic_oauth" \
    --state=Member --group=Operators --format=json

python manage.py oidc_rotate_secret --client-id=abc123 --dry-run
python manage.py oidc_revoke_user_tokens --username=alice
python manage.py oidc_audit_tokens --client-id=abc123 --format=csv
```

`oidc_create_app` writes a Django admin `LogEntry` on success so the action is visible in `/admin/`'s
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

### JWT access tokens (RFC 9068)

Access tokens are opaque random strings by default — operators can opt in to
[RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) JWT tokens per-application or
globally when downstream RPs (oauth2-proxy, mod_auth_openidc, WikiJS, custom
services) prefer to validate tokens locally without an introspection round-trip.
JWT mode is **opt-in** and **stateful**: the JWT lives in
`oauth2_provider_accesstoken.token`, so revocation, introspection, and audit
continue to work.

Activate by setting two keys in `OAUTH2_PROVIDER`:

```python
OAUTH2_PROVIDER = {
    # ... your existing settings ...
    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
    "ACCESS_TOKEN_GENERATOR": (
        "allianceauth_oidc.tokens.dispatching_access_token_generator"
    ),
    # Recommended companion: shorten access-token TTL when activating JWT
    # mode to bound the PII-at-rest window in the AccessToken table.
    # See docs/JWT_ACCESS_TOKENS.md "Data minimization" section.
    "ACCESS_TOKEN_EXPIRE_SECONDS": 300,  # 5 minutes; default was 3600
}
```

> **Important:** Both keys are needed. `ACCESS_TOKEN_GENERATOR` accepts the dotted-path string
> because it IS in DOT's `IMPORT_STRINGS` tuple — DOT resolves it at startup.
> `PKCE_REQUIRED` is NOT in `IMPORT_STRINGS` and therefore requires the function
> reference. If you set `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt"`
> but forget `ACCESS_TOKEN_GENERATOR`, JWT mode will not activate and
> `AllianceAuthOIDC.ready()` emits a startup `WARNING` flagging the
> misconfiguration. The check is log-only — startup never aborts on a
> misconfigured dotted path.

**Per-app override.** Every `AllianceAuthApplication` carries an optional
`access_token_format` field (`"opaque"` / `"jwt"` / blank). Blank inherits the
deployment-wide default. This lets you flip a single non-critical RP first,
verify, then flip the global default. Editable through Django admin.

**Claim mapping.** Identity claims (`email`, `name`, `groups`, `eve_*`, …) ride
exactly the same scope-gating as the id_token via DOT's canonical
`get_oidc_claims` hook — AT and id_token claim sets are byte-equivalent for the
same scope. RFC 9068 framing claims (`typ="at+jwt"`, `aud=client_id`,
`client_id`, `exp`, `iat`, `jti`, `scope`) are added on top. The provider signs
with `RS256` against `OIDC_RSA_PRIVATE_KEY`; the published `kid` is the RFC 7638
thumbprint of the key.

**Per-app → global migration sequence, RP cookbook, key rotation discipline,
data-minimization, troubleshooting** — see
[docs/JWT_ACCESS_TOKENS.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/JWT_ACCESS_TOKENS.md). The recipe in §7
walks through the recommended rollout (per-app first, global last) and points
at `manage.py oidc_audit_tokens --include-expired` whose `format` column
makes the per-token wire format inspectable from the operator side.

### Back-channel logout (OIDC BCL 1.0)

Sub-only [back-channel logout](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/BACK_CHANNEL_LOGOUT.md) is wired
in. Set `backchannel_logout_uri` on an application to enable per-RP
fan-out; the AS POSTs a signed `logout_token` whenever a session
ends (revoke / deactivate / group or state change / account delete).
Five trigger sites cover the realistic operator workflows. SSRF
defenses (host DNS check with 3 s wall-clock, scheme allow-list,
`allow_redirects=False`), spec-compliant `events` URI, and a
secret-pin regression test on every log line keep the dispatch path
safe. Session-scoped logout (`sid`) is intentionally deferred to
feature v2.

`OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` is required once any RP
registers a `backchannel_logout_uri` — the Celery worker has no HTTP
request context. A Django system check
(`allianceauth_oidc.E001`, severity `Error`) fails `manage.py check`
at deploy time if the setting is missing.

### System checks (`manage.py check`)

The provider registers six errors and six warnings against Django's
system-check framework. CI should fail on errors and surface warnings
as configuration smells worth investigating.

| ID | Severity | Trigger | Operator action |
|---|---|---|---|
| `allianceauth_oidc.E001` | Error | Application has `backchannel_logout_uri` set but `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` is unset. | Set `OIDC_ISS_ENDPOINT` to the absolute issuer URL. The Celery worker that POSTs `logout_token`s has no HTTP request context, so it cannot derive `iss` at runtime; without this setting the very first logout dispatch crashes. |
| `allianceauth_oidc.E002` | Error | `OAUTH2_PROVIDER_APPLICATION_MODEL` does not resolve to `AllianceAuthApplication` (or a subclass). | Set `OAUTH2_PROVIDER_APPLICATION_MODEL = "allianceauth_oidc.AllianceAuthApplication"`. The stock DOT model bypasses the three-layer policy enforcement — every authenticated user would be able to authenticate any registered app. |
| `allianceauth_oidc.E003` | Error | `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']` does not resolve to `AllianceAuthOAuth2Validator` (or a subclass). | Set `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS'] = "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator"`. The stock DOT validator drops layers 2 and 3 of the policy gate (`validate_code` / `validate_refresh_token` / `save_bearer_token`) — code-flow exchanges and refresh grants stop re-checking state/group membership. |
| `allianceauth_oidc.E004` | Error | `OAUTH2_PROVIDER['SCOPES']` does not contain the `openid` scope. | Add `"openid"` to the `SCOPES` dict. DOT's default `{"read": ..., "write": ...}` silently disables id_token issuance — discovery still resolves and access tokens still mint, but OIDC RPs fail at the token endpoint with `invalid_scope` or receive a token response without an `id_token`. |
| `allianceauth_oidc.E005` | Error | `OAUTH2_PROVIDER['PKCE_REQUIRED']` is not (or does not wrap) `allianceauth_oidc.pkce.per_app_pkce_required`. Without the adapter, DOT falls back to its own resolver and the per-app `pkce_required=False` override silently no-ops. Public clients shipped under this gap are vulnerable to auth-code interception per the RFC 9700 PKCE BCP. | Set `OAUTH2_PROVIDER['PKCE_REQUIRED'] = per_app_pkce_required` (pass the **function object**, not a dotted-path — DOT does not import this key). |
| `allianceauth_oidc.E006` | Error | The dangerous combination has a concrete victim: `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` AND `DEBUG=False` AND at least one `AllianceAuthApplication` row carries a non-empty `backchannel_logout_uri`. Signed `logout_token` JWTs would be POSTed to private-IP targets in a production-shaped deployment. | Set `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=False` in production. To explicitly accept the trade-off on an isolated lab/air-gapped staging, also set `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True` — both knobs must be set for the dangerous path to engage without an error. |
| `allianceauth_oidc.W001` | Warning | `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True` while `DEBUG=False`. Masked-fragment logging (`he…il`) is a development aid; enabling it in a production-shaped environment leaks identifiable prefixes/suffixes of access tokens, refresh tokens, and client secrets into the log stream. | Set the flag to `False` (or remove it) in production. Keep it `True` only on isolated staging hosts where the trade-off is intentional. |
| `allianceauth_oidc.W002` | Warning | `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT='jwt'` but `ACCESS_TOKEN_GENERATOR` is not the dispatching generator (JWT mode silently inactive), OR the dispatcher wired without the default format set to `'jwt'` (per-app override still works but the global default does not). | Wire `OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] = "allianceauth_oidc.tokens.dispatching_access_token_generator"`. Both halves must agree for JWT to be the global default. |
| `allianceauth_oidc.W003` | Warning | `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']` is explicitly `False` while one or more applications carry a `backchannel_logout_uri`. The Single-Logout chain breaks at the first hop because RP-initiated logout is the entry-point that triggers back-channel fan-out. | Either remove `backchannel_logout_uri` from the affected applications (listed in the warning text), or re-enable RP-initiated logout (it is on by default — set the key to `True` or remove the explicit `False`). |
| `allianceauth_oidc.W004` | Warning | One or more **active** applications have a `backchannel_logout_uri` using `http://` while `DEBUG=False`. The admin form rejects new `http://` URIs in production, but legacy rows persisted under `DEBUG=True` survive a flip. The worker re-checks DNS but not scheme, so `logout_token` JWTs (carrying `iss`/`aud`/`sub`/`jti`) keep flowing in cleartext. | Edit each affected application to use `https://`, or deactivate the row if the RP has been retired. |
| `allianceauth_oidc.W005` | Warning | `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` while `DEBUG=False` (without a registered `backchannel_logout_uri` to trigger E006). The SSRF gate on back-channel logout targets is disabled — if a private-IP URI is later registered, the worker will POST signed `logout_token`s to `127.0.0.1` / `169.254.169.254` / k8s overlay / CGNAT IPs. | Set the flag to `False` (or remove it) in production. Keep it `True` only on dev / staging hosts that intentionally point at private RPs. |
| `allianceauth_oidc.W006` | Warning | A DOT `UUIDField` column (`oauth2_provider_idtoken.jti` and/or `oauth2_provider_refreshtoken.token_family`) is still `char(32)` on a MariaDB `>= 10.7` backend. Django 5.x treats that MariaDB as having a native `uuid` type and writes the 36-char dashed form, which overflows the legacy column with `1406 Data too long` — failing id_token issuance on `/o/token/` (`jti`) or refresh-token rotation (`token_family`). Database-tagged (runs at `migrate` / `check --database`). | Run `manage.py oidc_fix_uuid_columns` to convert the column(s) to the native `uuid` type Django now expects. See [docs/MARIADB.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/MARIADB.md). |

The check ids are stable across releases; muting via Django's
`SILENCED_SYSTEM_CHECKS` is supported but discouraged — fix the
underlying configuration so the next operator does not stumble on
the same drift.

### Local testing on a private network

Two switches let you run a full BCL flow against RPs that resolve
to private addresses (typical dev / staging on `192.168.x.x`,
`10.x.x.x`, k8s overlay, CGNAT `100.64.0.0/10`).

| Setting | Effect |
|---|---|
| `DEBUG = True` | Admin form accepts `http://` BCL URIs. `W001`, `W004`, `W005` stay quiet. |
| `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True` | Both DNS gates (admin save AND worker dispatch-time re-check) short-circuit; private / loopback / link-local / multicast / reserved / CGNAT targets pass. |

Typical configurations:

```python
# Dev on localhost / LAN — silent, full BCL works
DEBUG = True
ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True
```

```python
# Staging on a k8s overlay (10.244.x.x, 100.64.x.x) — works, with W005 surfaced
DEBUG = False
ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE = True
```

`W005` in the staging variant is **informational**, not blocking —
it makes the "I have intentionally accepted SSRF risk in this
environment" choice visible at every `manage.py check`. The same
posture holds for `W001` (masked-secret logging) and `W004`
(`http://` BCL): warnings, not errors.

### Debug logging

Per-application `Debug Mode` (toggled in the admin) escalates token-flow logs from `DEBUG` to
`INFO`. Raw token values and secrets are **never** logged; the `_LOG_MASKED_SECRETS` knob (see
[Custom settings](#custom-settings-allianceauth_oidc_)) controls whether they appear as
`<redacted>` or masked fragments.

When debugging an app, look for lines like:

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views_token:204] OIDC DEBUG token issued
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
| Issuer | exact value of `issuer` from `https://auth.example.com/o/.well-known/openid-configuration` — canonical form has no trailing slash (`https://your.host/o`); copy it verbatim, strict validators reject mismatches (see [Endpoints](#endpoints)) |
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

## Limitations

- Authorization-code flow only; public clients are out of scope.
- Session-scoped (`sid`) back-channel logout deferred to feature v2 (sub-only today).
- No built-in rate-limiting on `/o/token/` and `/o/authorize/` — operator
  responsibility (see the
  [operational hardening notes](#operational-hardening-operator-responsibility)).
- Does not mount its own `/metrics` view (delegated to django-prometheus).

## Development

### Nox sessions

| Session | Purpose | In default `nox` run? |
|---|---|---|
| `lint` | pre-commit (ruff, mypy, basedpyright, …) | yes |
| `tests` | Django test suite (parallel) | yes |
| `coverage` | tests + term / HTML / XML coverage reports | no |
| `tests_timing` | tests single-process with the slowest-cases (`--durations`) report | no |
| `typecheck` | mypy + basedpyright (subset of `lint`, run separately for fast feedback) | no |
| `audit` | pip-audit | no |
| `markdown_lint` | rumdl + lychee + vale (each tool optional) | no |
| `makemessages` / `compilemessages` | i18n catalogue refresh + compile | no |
| `messages_check` | `.po` / `.pot` / `.mo` catalogue integrity gate | no |
| `makemigrations` | generate Django migrations under test settings | no |
| `integration` | wire-level mock-RP via `LiveServerTestCase` | no |
| `conformance` / `conformance_basic` | OIDC Conformance Suite via docker-compose | no |
| `preflight` | `lint` + `typecheck` + `tests` + the migration / messages / Makefile gates in one go (pre-PR gate) | no |
| `tests_matrix` | Run the suite across every supported Python (off-lock, uv venv) | no |
| `tests_aa4` | Run the suite against the Alliance Auth 4.x stack | no |
| `tests_compat` | Run the suite against an arbitrary `allianceauth` pin | no |
| `tests_mariadb` | Run the suite against a real MariaDB instead of sqlite (see [docs/MARIADB.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/MARIADB.md)) | no |
| `migrations_check` | Verify migrations are in sync and free of unsafe operations | no |
| `migrations_concurrency_check` | Scan raw `RunSQL` migrations for blocking (non-online) DDL | no |
| `actions_lint` | Lint GitHub Actions workflows (`actionlint` + `zizmor`) | no |
| `diagrams` | Render diagram-as-code under `assets/diagrams/` to SVG | no |
| `makefile` / `makefile_check` | Regenerate / drift-check the `Makefile` against the session registry | no |
| `verify_wheel` | Build the wheel into a tempdir and audit its file inventory | no |
| `mutation` | Cosmic-ray mutation testing over production modules | no |
| `mutation_parallel` | Resume a partial cosmic-ray sweep with N isolated workers | no |
| `mutation_html` | Render the cosmic-ray HTML report from `mutation.sqlite` | no |
| `mutation_check` | Gate CI on the mutation survival rate of `mutation.sqlite` | no |

The `mutation*` sessions have their own setup / resume / report-rendering recipe in
[docs/mutation-testing.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/docs/mutation-testing.md).

### The `Makefile` is generated

The `Makefile` is a thin shim over these sessions (`make test` → `nox -s tests`, etc.)
and is **generated, not hand-edited**. Its single source of truth is the `TARGETS` table in
[`_nox/makefile.py`](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/_nox/makefile.py); edit a target there (or add one for a new session) and
regenerate with `make makefile` (`nox -s makefile`). A `makefile_check` gate — wired into
`preflight`, pre-commit, and CI — keeps the two honest with three drift checks: the committed
file matches the render, every nox session has a `make` target, and no target names a session
that no longer exists. Run `make help` for the full target list.

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
[tests/conformance/README.md](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/tests/conformance/README.md) for prerequisites, the manual /
iterative workflow, configuration overrides, and the list of known conformance findings to
triage.

## Links

- Changelog: <https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/CHANGELOG.md>
- Issue tracker: <https://github.com/6RUN0/allianceauth-oidc-provider/issues>
- Upstream project:
  <https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider>

## License

MIT — see [LICENSE](https://github.com/6RUN0/allianceauth-oidc-provider/blob/current/LICENSE).
