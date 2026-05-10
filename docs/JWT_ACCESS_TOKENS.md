# JWT access tokens (RFC 9068)

## 1. Overview

This module ships with two access-token wire formats:

- **Opaque** (default) — random URL-safe strings. Validation requires
  `/o/introspect/` round-trip on every gated request. RPs that use
  `passport-openidconnect`, Wiki.js, Outline, etc. accept this without
  configuration changes.
- **JWT (RFC 9068)** — JSON Web Tokens with `typ="at+jwt"`, signed with
  `RS256` against the same `OIDC_RSA_PRIVATE_KEY` that signs id_tokens.
  Off-the-shelf reverse-proxy auth tools (oauth2-proxy, mod_auth_openidc,
  HAProxy `oauth2-bouncer`, Envoy `oauth2_proxy`) validate locally
  against the published JWKS — zero round-trips on the hot path.

JWT mode is **opt-in** (default `"opaque"`) and **stateful**: each issued
JWT lives in `oauth2_provider_accesstoken.token` exactly like the opaque
counterpart, so revocation, introspection, and audit signal continue to
work. Per-app override (`AllianceAuthApplication.access_token_format`)
lets you flip a single non-critical RP first, then promote the global
default once you are happy with the result.

## 2. Opt-in path

Set both keys in `OAUTH2_PROVIDER`:

```python
OAUTH2_PROVIDER = {
    # ... your existing settings ...
    "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "jwt",
    "ACCESS_TOKEN_GENERATOR": (
        "allianceauth_oidc.tokens.dispatching_access_token_generator"
    ),
    "ACCESS_TOKEN_EXPIRE_SECONDS": 300,  # see "Data minimization"
}
```

Both keys are needed. `ACCESS_TOKEN_GENERATOR` is in DOT's `IMPORT_STRINGS`
tuple so the dotted path is fine; `PKCE_REQUIRED` is not, which is why the
PKCE adapter uses a function reference — see the README's OAUTH2_PROVIDER
table.

When only one of the two is set, `AllianceAuthOIDC.ready()` emits a
startup `WARNING` that names the missing key. The check is log-only and
wrapped in `try/except`, so a typo in the dotted path never aborts
Django startup — it shows up in the log instead.

After applying migrations and restarting Auth, every newly issued AT in
your deployment is a JWT (subject to per-app overrides — see §7).

## 3. Claim mapping

The provider reuses DOT's canonical `oidc_claim_scope` map for the JWT.
That means the AT and id_token claim sets are byte-equivalent for the
same scope set, modulo RFC 9068 framing claims that id_token does not
carry. There is no claim-set divergence to maintain.

| Claim | Source | Scope | Notes |
|-------|--------|-------|-------|
| `sub` | `User.pk` (or `client_id` for client_credentials) | `openid` | RFC 9068 §3 fallback when no end user |
| `email` | `user.email` | `email` | |
| `email_verified` | Auto / `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` | `email` | Same logic as id_token |
| `name` | `user.profile.main_character.character_name` | `profile` | |
| `picture` | EVE portrait URL | `profile` | |
| `groups` | `user.groups[*].name + state.name` | `profile` | Capped at 256 entries |
| `locale` | `user.profile.language` | `profile` | |
| `eve_*` | EVE character / corp / alliance data | `profile` (configurable) | |

RFC 9068 framing claims, added on top:

| Claim | Value |
|-------|-------|
| `typ` (header) | `"at+jwt"` |
| `alg` (header) | `"RS256"` |
| `kid` (header) | RFC 7638 thumbprint of the signing key |
| `iss` | Resolved via `oauth2_settings.oidc_issuer(request)` |
| `aud` | `client_id` (AA convention; identifies the application) |
| `client_id` | `client_id` (duplicates `aud` per RFC 9068 §3) |
| `exp` | `iat + ACCESS_TOKEN_EXPIRE_SECONDS` |
| `iat` | Token issuance time (Unix epoch seconds) |
| `jti` | UUID4 hex |
| `scope` | Space-delimited request scopes |
| `auth_time` | `user.last_login` Unix epoch (omitted for client_credentials) |

## 4. Data minimization

JWT mode pays both costs of stateful storage AND PII-on-the-wire: the
DB row exists for revocation, but the JWT also carries identity claims
in plaintext (only base64url-encoded, signed but not encrypted). The
mitigation is **token TTL discipline** — a short `exp` window bounds
how long any single leaked PII payload stays valid.

Recommended: `OAUTH2_PROVIDER["ACCESS_TOKEN_EXPIRE_SECONDS"] = 300` (5
minutes) at minimum. RPs refresh more often, but the PII-at-rest window
shrinks proportionally. The same logic applies to the existing WikiJS
guidance in `CLAUDE.md`; for JWT mode it becomes the default rather
than the special case.

For deployments where JWT mode would force PII into less-secure
pipelines (analytics, full-traffic logs, cold backups), keep the
default `"opaque"` and configure RPs to introspect.

## 5. Key rotation

The signing key is `OIDC_RSA_PRIVATE_KEY`. Rotation discipline:

1. **Provision the new key** offline. Generate via the same procedure
   as the original — see the [DOT documentation][dot-oidc].
2. **Configure overlap**. DOT supports
   `OIDC_RSA_PRIVATE_KEYS_INACTIVE` for keys that are still trusted
   for verification but no longer used for signing. Add the **old**
   key to that list, set the **new** key as `OIDC_RSA_PRIVATE_KEY`,
   and reload Auth. JWKS now publishes both `kid`s.
3. **Wait the longer of `ACCESS_TOKEN_EXPIRE_SECONDS` and the longest
   downstream RP cache TTL**. Existing JWTs signed with the old key
   keep validating against the published JWKS during this window.
4. **Remove the old key** from `OIDC_RSA_PRIVATE_KEYS_INACTIVE`. JWKS
   stops publishing it. Any straggler JWT signed with the old key now
   fails — by design.

Skipping the overlap (steps 2-3) instantly invalidates every in-flight
JWT and triggers an outage proportional to the active session count.

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
# RFC 9068 audience matches client_id by AA convention.
oidc_extra_audiences = ["your-client-id"]
# Validate JWT locally against the published JWKS — no /introspect roundtrip.
skip_jwt_bearer_tokens = true
extra_jwt_issuers = "https://your-auth.example.com/o=your-client-id"
```

### mod_auth_openidc (Apache)

```apache
OIDCProviderMetadataURL https://your-auth.example.com/o/.well-known/openid-configuration
OIDCClientID your-client-id
OIDCClientSecret your-client-secret
OIDCScope "openid profile email"
# Accept JWT access tokens issued by us, validating locally.
OIDCOAuthVerifyJwksUri https://your-auth.example.com/o/.well-known/jwks.json
OIDCOAuthRemoteUserClaim sub
```

### Discord SSO (custom integration)

Discord's bot framework does not directly speak OIDC; if you have a
custom bridge that already resolves `sub` from your AA OIDC provider,
JWT mode does not change that bridge — the same `sub` claim is still
the user identifier. Local JWT validation requires you to import the
`jose` / `jwcrypto` library and verify against the published JWKS.

### WikiJS

WikiJS's OpenID Connect strategy uses `passport-openidconnect`, which
**does not validate JWT access tokens locally** — it validates the
`id_token` and stores the AT for later use against `/userinfo`. JWT
mode therefore has no functional effect on WikiJS:

- Pro: no configuration change required when activating JWT mode.
- Con: WikiJS gains nothing from JWT mode in itself — the savings only
  show up if you front WikiJS with oauth2-proxy or similar.

## 7. Migration: opaque → JWT

The recommended sequence is **per-app first, global last**:

1. Apply migration 0012 (adds the `access_token_format` field).
2. In Django admin, pick a single non-critical RP. Set its
   `access_token_format` to `"jwt"`. Save.
3. Wire `ACCESS_TOKEN_GENERATOR` in `local.py` (the dispatcher itself
   does nothing without the per-app override or global default).
4. Restart Auth. The picked RP now issues JWTs; everything else stays
   opaque.
5. Verify with `manage.py oidc_audit_tokens --include-expired
   --client-id=<picked-rp>`. The output gains a `format` column;
   confirm `jwt` for the picked RP and `opaque` everywhere else.
6. After a settling period (24-72 hours), set
   `OAUTH2_PROVIDER["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"]
   = "jwt"` and restart. Every other RP starts issuing JWT on its
   next token request.

## 8. Rollback

To revert the global to opaque, flip the setting:

```python
OAUTH2_PROVIDER["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "opaque"
```

In-flight JWTs remain valid until their `exp`; the publishing JWKS
still serves the signing key, so RPs that already validated a JWT
before the flip continue to honour it. Newly issued tokens are opaque
again. No data migration is involved.

To revert a single RP, set its `access_token_format` back to blank in
admin (or `"opaque"` if you want to lock it).

`ACCESS_TOKEN_GENERATOR` can stay wired even after rolling back — the
dispatcher resolves `"opaque"` and delegates to oauthlib's default
generator, which is the same callable DOT would have used otherwise.

## 9. Verifying tokens

### Operator-side

```sh
# After issuing a fresh AT, decode it (no signature check):
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

For full validation including signature, use `jwcrypto` (already a
transitive dependency of DOT) against the published JWKS.

### Audit signal

Custom receivers connected to `oidc_token_issued` see a `format` field
on the `body` argument:

```python
@receiver(oidc_token_issued)
def forward_to_siem(sender, *, body, token, **kwargs):
    fmt = body.get("format")  # "opaque" | "jwt" | None
    ...
```

## 10. Troubleshooting

**Symptom: I activated JWT mode but tokens are still opaque.**

Most likely you set `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT="jwt"`
without also wiring `ACCESS_TOKEN_GENERATOR`. Check the startup log for
the `WARNING` from `extensions.allianceauth_oidc.apps`.

**Symptom: an upstream proxy rejects the AT with "header too long".**

The token exceeds the proxy's `Authorization`-header limit. Check the
warning emitted by `extensions.allianceauth_oidc.tokens` for the actual
size and consider raising the proxy limit (Apache
`LimitRequestFieldSize`, nginx `large_client_header_buffers`, HAProxy
`tune.bufsize`) or trimming the user's group membership. The
`ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` setting tunes the warning
threshold but does not affect issuance — the threshold is informational
only.

**Symptom: client_credentials grant fails with `sub` validation.**

The provider correctly emits `sub=client_id` for client_credentials
(per RFC 9068 §3). Some RPs validate `sub` against a user database and
reject anything not matching a known user. That's an RP-side
configuration issue; configure the RP to accept the
client_credentials-shaped `sub` or skip `sub` validation for
machine-to-machine tokens.

**Symptom: I rotated the key and every active session broke.**

You skipped the overlap step (§5.2). Restore the previous key as
`OIDC_RSA_PRIVATE_KEY` and add the new key to
`OIDC_RSA_PRIVATE_KEYS_INACTIVE`, then redo the rotation correctly.
