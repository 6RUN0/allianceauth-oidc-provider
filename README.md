# allianceauth_oidc

> Fork of
> [Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
> maintained at
> [6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) — adds
> wire-level integration tests, an OIDC Conformance Suite harness, operator CLI commands,
> EVE-specific claims, runtime localisation (en/ru/uk), and a Russian-language
> [README.ru.md](README.ru.md).

## Allianceauth OIDC Provider

## Features

- OIDC / OAuth2
  - Scopes Available
    - openid
    - email
    - profile
      - Includes `groups` claim with all a members groups and state as a list of strings
- Application level permissions
  - global access
  - State access
  - group access

## Code flow + three-layer access policy

Every authorization-code exchange traverses three independent gates. Removing any one of them opens a
hole, which is why the regression tests exercise each layer separately.

```mermaid
sequenceDiagram
    participant RP as Relying Party
    participant Auth as /o/authorize/
    participant DOT as django-oauth-toolkit
    participant Token as /o/token/
    participant Validator as AllianceAuthOAuth2Validator

    RP->>Auth: GET/POST authorize, response_type=code
    Note over Auth: Layer 1 — dispatch()<br/>global access_oidc<br/>+ state/group whitelist
    Auth->>DOT: forward (if policy passes)
    DOT-->>RP: 302 redirect with auth code
    RP->>Token: POST code + client_secret
    Token->>Validator: validate_code(code, request)
    Note over Validator: Layer 2 — re-checks<br/>state/group on exchange
    Validator-->>Token: ok / invalid_grant
    Token->>Validator: save_bearer_token(...)
    Note over Validator: Layer 3 — last guard;<br/>PermissionDenied -> invalid_grant
    Validator-->>RP: 200 access_token + id_token
```

## Example

![Imgur](https://i.imgur.com/gcrFcRL.png)

## Setup/Install

1. Install the fork from git (the package name `allianceauth-oidc-provider` collides with the
   upstream PyPI release, so install by VCS URL rather than `pip install allianceauth-oidc-provider`):

   ```sh
   pip install "git+https://github.com/6RUN0/allianceauth-oidc-provider.git@current"
   ```

1. add to `INSTALLED_APPS` in your `local.py`

   ```python
   INSTALLED_APPS += [
       # your other apps #
       'allianceauth_oidc',
       'oauth2_provider',
       # your other apps #
   ]
   ```

1. Extra Settings Required

   ```python

   # at the top of the file
   from pathlib import Path

   # Add these to the file further down
   if 'allianceauth_oidc' in INSTALLED_APPS and 'oauth2_provider' in INSTALLED_APPS:
       OAUTH2_PROVIDER_APPLICATION_MODEL='allianceauth_oidc.AllianceAuthApplication'
       OAUTH2_PROVIDER = {
           # https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key
           "OIDC_ENABLED": True,
           # Load your private key
           "OIDC_RSA_PRIVATE_KEY": Path("/path/to/key/file").read_text(),
           "OAUTH2_VALIDATOR_CLASS": "allianceauth_oidc.auth_provider.AllianceAuthOAuth2Validator",
           "SCOPES": {
               "openid": "User Profile",
               "email": "Registered email",
               "profile": "Main Character affiliation and Auth groups"
           },
           # PKCE is mandatory for public clients per RFC 9700 (OAuth 2.0
           # Security BCP) and recommended for confidential ones; only
           # disable it if you know all your registered clients support
           # PKCE and you have a documented reason.
           "PKCE_REQUIRED": True,
           "APPLICATION_ADMIN_CLASS": "allianceauth_oidc.admin.ApplicationAdmin",
           'ACCESS_TOKEN_EXPIRE_SECONDS': 60,
           'REFRESH_TOKEN_EXPIRE_SECONDS': 24*60*60,
           # Rotate refresh tokens on every use AND detect reuse — if a
           # refresh token is presented twice, DOT revokes the entire
           # token family (RFC 6819 §5.2.2.3 replay defence).
           'ROTATE_REFRESH_TOKEN': True,
           'REFRESH_TOKEN_REUSE_PROTECTION': True,
       }
   ```

   Please see [this](https://django-oauth-toolkit.readthedocs.io/en/stable/oidc.html#creating-rsa-private-key)
   for more info on creating and managing a private key
1. Add the endpoints to your `urls.py`

   ```python
   from .settings.local import INSTALLED_APPS

   # ...
   # Here your other imports and urlpatterns
   # ...

   if "allianceauth_oidc" in INSTALLED_APPS and "oauth2_provider" in INSTALLED_APPS:
       urlpatterns.append(
           path(
               "o/",
               include("allianceauth_oidc.urls", namespace="oauth2_provider"),
           )
       )
   ```

1. run migrations
1. restart auth

## Optional settings (recommended)

### Masking secrets in debug logs

By default, the provider never logs raw token values or secrets. When an application has _Debug Mode_ enabled,
it can log additional debug metadata, but secrets remain redacted unless you explicitly allow masked output.

Add to your settings (optional):

```python
# When False (default): secrets are logged as "<redacted>"
# When True: secrets are logged as masked fragments (head…tail)
ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS = False

# How many characters of a secret to show in logs when masking is enabled
ALLIANCEAUTH_OIDC_LOG_MASK_HEAD = 2
ALLIANCEAUTH_OIDC_LOG_MASK_TAIL = 2
```

Security note: enable masked logging only if your log storage is properly restricted.

### EVE-specific claims (`eve_*`)

The provider emits Alliance-Auth-domain claims alongside the standard OIDC
ones — character/corporation/alliance metadata read from the user's main
character. Default prefix: `eve_`. Default scope: `profile` (already requested
by most RPs as part of `openid profile`).

| Claim | Source | Notes |
|---|---|---|
| `eve_character_id` | `main_character.character_id` | Integer EVE ID |
| `eve_corporation_id` / `_name` / `_ticker` | `main_character.corporation_*` | Denormalised on the character row |
| `eve_alliance_id` / `_name` / `_ticker` | `main_character.alliance_*` | Omitted for NPC corps without an alliance |

Override the prefix or scope:

```python
# Default `eve_` — set to `""` for un-prefixed claims (collision-prone), or
# any other prefix to namespace claims for federation with other providers.
ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX = "eve_"

# Default `profile`. Set to `eve` (or any custom value) to require an
# explicit RP scope opt-in. NB: scope binding is class-level — changing this
# setting requires an Auth process restart to take effect.
ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE = "profile"
```

Empty fields are **omitted** rather than emitted as `null` so RPs that key off
`claim in payload` behave consistently.

### Portrait (`picture` claim) URL

The `picture` claim defaults to the official EVE image server. If you front it through
a CDN mirror or want a different size, override these settings:

```python
# Default: "https://images.evetech.net/characters/{character_id}/portrait?size={size}"
ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE = "https://cdn.example/portraits/{character_id}-{size}.png"

# EVE's image server supports 32/64/128/256/512/1024. Default: 128.
ALLIANCEAUTH_OIDC_PORTRAIT_SIZE = 256
```

The template must contain `{character_id}` and `{size}` placeholders; a
malformed template skips the `picture` claim with a warning instead of
crashing the token endpoint.

### Periodic cleanup of expired tokens (Celery Beat)

To prevent the database from growing indefinitely, schedule the cleanup task:

```python
from celery.schedules import crontab

CELERYBEAT_SCHEDULE["allianceauth_oidc_clear_expired_tokens"] = {
    "task": "allianceauth_oidc.clear_expired_tokens",
    "schedule": crontab(minute=0, hour="*/2"),  # every 2 hours
    "apply_offset": True,
}
```

### Operator commands

Four `manage.py` commands cover the common operational tasks without
opening the admin UI. All four accept `--format=table|json|csv`;
destructive commands honour `--dry-run`.

```sh
# Create a new OIDC application non-interactively (CI / Ansible-friendly).
python manage.py oidc_create_app \
    --name="Grafana" \
    --user-id=1 \
    --redirect-uri="https://grafana.example/login/generic_oauth" \
    --state=Member \
    --group=Operators \
    --format=json

# Rotate the client_secret of a registered app. Existing tokens stay
# valid until expiry; combine with `oidc_revoke_user_tokens` for an
# immediate cut-off.
python manage.py oidc_rotate_secret --client-id=abc123 --format=json
python manage.py oidc_rotate_secret --client-id=abc123 --dry-run

# Revoke every active access + refresh token for a user (off-boarding,
# compromise response). Idempotent; safe to re-run.
python manage.py oidc_revoke_user_tokens --username=alice
python manage.py oidc_revoke_user_tokens --username=alice --dry-run

# Read-only audit: who is currently authenticated against which app.
python manage.py oidc_audit_tokens
python manage.py oidc_audit_tokens --username=alice --include-expired
python manage.py oidc_audit_tokens --client-id=abc123 --format=csv
```

Destructive operations (`create_app`, `rotate_secret`,
`revoke_user_tokens`) log at INFO/WARNING and `create_app` also writes
a Django admin LogEntry so the action shows up in `/admin/`'s history
view without code changes.

### Operational hardening (operator responsibility)

This app implements OAuth2/OIDC protocol semantics, but the runtime
hardening below is intentionally left to the deployment so it integrates
with whatever edge / infra you already operate:

- **Rate limiting on `/o/token/` and `/o/authorize/`.** Neither endpoint
  is rate-limited by this app; brute-force defence belongs at the edge
  (nginx `limit_req`, Cloudflare, a WAF) or via `django-ratelimit` in your
  Auth deployment. Without it, a network-level attacker can probe
  `client_secret` / `code` / `refresh_token` values at line speed.
- **Celery broker authentication.** `clear_expired_tokens` is published to
  whichever Celery broker your AA install uses; if that broker is reachable
  by untrusted parties, a malicious task submission can repeatedly invoke
  cleanup. The task itself is idempotent (it only deletes already-expired
  rows), but broker auth + network ACLs are the defensive layer that
  matters here.
- **Security headers.** This app does not set CSP / HSTS / X-Frame-Options
  / X-Content-Type-Options on its responses; rely on Alliance Auth's
  middleware stack and Django's `SECURE_*` settings to add them globally.

## Application setup

### The Big 4

- Authorization: `https://your.url/o/authorize/`
- Token: `https://your.url/o/token/`
- Profile: `https://your.url/o/userinfo/`
- Issuer `https://your.url/o/`

### Claims

- `openid profile email`

### Claim key mapping

- `name` Eve Main Character Name ( Profile Grant )
- `email` Registered email on auth ( Email Grant )
- `groups` List of all groups with the members state thrown in too ( Profile Grant )
- `sub` PK of user model
- `picture` URL to the main character avatar ( Profile Grant )
- `locale` User preferred language ( Profile Grant )

### Create an application

Before configuring the external application you want to go on your auth admin pannel at
`/admin/allianceauth_oidc` and create a new alliance auth application.

- `User` can be set to 1, this is a parameter for the upstream library not used in this application
- `client type` should be confidential
- `authorization grant type` should be `Authorization code`
- `Client secret` needs to be saved somewhere **before** hitting save if you leave the hashing on
  (it won't be displayed again)
- `Algorithm`: `RSA with SHA-2 256`

Then you can set which states or group can access this application. \
_Note that they will also need the `allianceauth_oidc.access_oidc` role to access any application._

### WikiJS

Manually create and groups you care for your users to have in the wiki and the service will map them
for you. This greatly cuts down on group spam.
in auth create `Administrators` to give access to the full wiki admin site.

#### Administration > Authentication > Generic OpenID Connect / OAuth2

- Skip User Profile `off`
- Email claim `email`
- Display Name Claim `name`
- Map Groups `on`
- Groups Claim `groups`
- Allow Self Registration `on`

### Grafana

Tested only with access no group mapping as yet

Group>Team mapping requires Grafana cloud or Enterprise and is outside of the scope of this doc.

#### /etc/grafana/grafana.ini

```ini
[server]
root_url = <URL of your grafana server>

[auth.generic_oauth]
enabled = true
name = <Your Auth Name>
allow_sign_up = true
client_id = <client id from the application>
client_secret = <client secret from the application (unhashed)>
scopes = openid,email,profile
empty_scopes = false
email_attribute_path = email
name_attribute_path = name
auth_url = https://<your.auth.url>/o/authorize/
token_url = https://<your.auth.url>/o/token/
api_url = https://<your.auth.url>/o/userinfo/
```

### Debugging an application

1. Enable _Debug Mode_ for the specific application in the auth admin site.
1. then in your `gunicorn.log` look for long lines similar to this after you attempt to log in,

```text
[01/Jan/2099 00:00:00] INFO [extensions.allianceauth_oidc.views:78] OIDC DEBUG token issued app_id=1 client_id=abc123 user_id=42 meta={'grant_type': 'authorization_code', 'scope': 'openid email profile', 'client_id': 'abc123', 'redirect_uri': 'https://app.example/cb', 'code': '<redacted>', 'refresh_token_req': None, 'client_secret': None, 'assertion': None, 'token_type': 'Bearer', 'expires_in': 111, 'scope_resp': 'openid email profile', 'access_token': '<redacted>', 'refresh_token': '<redacted>', 'id_token': '<redacted>'}
```

1. take the `id_token` field and paste it into <https://jwt.io/> to debug the data being sent to the
   application. it should be fairly self explanitory expect for these 2 fields.

- `iss` is the issuer that must match exactly in the applications own settings.
- `sub` is your user id if you need to debug why user is being sent.

If you want to check the token signature on jwt.io and lost your public key your can use:

```sh
ssh-keygen -y -e -m pem -f /path/to/key/file
```

This will output the public key in the PEM format for jwt.io to check the signature.

> [!NOTE]
> If you are using a custom theme (or have overridden the public login template),
> please double-check your login page template at:
> `authentication/templates/public/login.html`
> Make sure the SSO login link URL-encodes the next parameter.
> Otherwise, query parameters can be truncated and OAuth/OIDC
> flows may fail (e.g. missing client_id after redirect).
>
> ```html
> <a
>   href="{% url 'auth_sso_login' %}{% if request.GET.next %}?next={{ request.GET.next | urlencode }}{% endif %}"
> ></a>
> ```

## Development

### Integration tests (mock-RP over real HTTP)

`nox -s integration` runs the wire-level integration tests in
`tests/test_integration_mock_rp.py`. They boot a `LiveServerTestCase`
and walk the OIDC code flow with `requests` + `jwcrypto`, validating
the id_token signature against a JWKS retrieved over the wire. This
catches regressions the standard `nox -s tests` set cannot — Django's
test client short-circuits the WSGI layer, so absolute-URL bugs in
`iss` / `jwks_uri` and Bearer-header / cookie issues only surface here.

```sh
uv run nox -s integration                   # run the full mock-RP suite
uv run nox -s integration -- --keepdb       # forward args to django test
```

The session is excluded from the default `nox` run because real-HTTP
tests are an order of magnitude slower than the test-client suite and
force `--parallel=1` (LiveServerTestCase is incompatible with the test
runner's `fork()`).

### Conformance Suite (`nox -s conformance`)

`nox -s conformance` runs the [OpenID Foundation Conformance Suite][suite]
against the provider via Docker Compose: MongoDB + the suite + a
provider container. The default plan is driven through the suite's
REST API by `tests/conformance/run_plan.py`.

This is the level above our own integration tests — it catches spec
edge cases that our regression tests wouldn't think to check. Run
before tagging a release. See [tests/conformance/README.md](tests/conformance/README.md)
for prerequisites, the manual / iterative workflow, configuration
overrides, and the list of known conformance findings to triage.

[suite]: https://gitlab.com/openid/conformance-suite
