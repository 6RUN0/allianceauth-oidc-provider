# OIDC Back-Channel Logout 1.0

## 1. Overview

This module implements
[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
in **sub-only** mode. When the AS terminates a user's session (revoke,
deactivate, group/state change, or account delete), it POSTs a signed
`logout_token` to every Relying Party that registered a
`backchannel_logout_uri`. The RP is then obliged by spec §2.6 to
"log out all of the user's sessions" for that `sub`.

What sub-only means in practice:

- The `logout_token` payload carries `sub` (the user's primary key) but
  NEVER `sid`. The RP logs the user out across all of its tabs/devices,
  not just the originating session.
- The companion discovery flag
  `backchannel_logout_session_supported` is intentionally NOT emitted.
  Session-scoped logout is deferred to **feature v2** of this provider
  (see §8 below).

## 2. Operator setup

Two settings + a Celery worker must be in place before any RP can be
registered.

1. **Pin the issuer.** The Celery worker has no HTTP request context,
   so the AS cannot derive `iss` at logout-token build time. Add the
   absolute issuer URL to `OAUTH2_PROVIDER`:

   ```python
   OAUTH2_PROVIDER = {
       # ...
       "OIDC_ISS_ENDPOINT": "https://auth.example.org/o",
   }
   ```

   A Django system check (`allianceauth_oidc.E001`) fires at
   `manage.py check` when any `AllianceAuthApplication` has a
   `backchannel_logout_uri` set AND `OIDC_ISS_ENDPOINT` is missing.
   Severity is `Error` — `manage.py check` exits non-zero, so CI
   pipelines fail loudly instead of letting the first end-user logout
   crash at runtime.

2. **Run a Celery worker.** Back-channel logout is fan-out by design;
   one logout event produces N outbound POSTs to N RPs. The worker
   reuses the same broker / result-backend Alliance Auth already
   relies on. No new entry in `CELERYBEAT_SCHEDULE` is required —
   logout tasks are eager, triggered by signals.

3. **Register the RP.** In Django admin → OIDC application → set
   `backchannel_logout_uri` to the RP's endpoint. The URL MUST be
   `https://` unless `settings.DEBUG=True` (development); the admin
   form rejects `http://` in production. A DNS-bound SSRF guard
   resolves the URL's host with a 3-second wall-clock deadline and
   rejects private / loopback / link-local / multicast / reserved
   addresses (RFC 1918, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4,
   240.0.0.0/4). Set
   `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` only for dev /
   compose-network setups.

## 3. Trigger sites (T1)

A logout fan-out fires when ANY of these five sites detects a session
that should end:

| Site | Reason string | Condition |
|---|---|---|
| `manage.py oidc_revoke_user_tokens` | `user_revoked` | Always, post-revoke |
| `User.is_active` flip True → False | `user_deactivated` | Unconditional on RT/AT presence |
| `m2m_changed` on `User.groups` (post_remove / post_clear) | `groups_changed` | When `AccessPolicy.is_allowed` newly denies |
| `allianceauth.authentication.signals.state_changed` | `state_changed` | When `AccessPolicy.is_allowed` newly denies |
| `pre_delete` + `post_delete` on `User` | `user_deleted` | Unconditional on RT/AT presence |

Spec §2.6 explicitly permits the AS to emit multiple `logout_tokens`
for the same `(user, application)` if two triggers fire in one
transaction (e.g. revoke + cascading deactivate). The RP MUST dedup on
`jti` (which is unique per outbound POST).

## 3.1 Per-app trigger filtering

By default, all five trigger sites above fire a `logout_token` to
every RP with a non-blank `backchannel_logout_uri`. For some classes
of relying party — audit, analytics, long-term-access dashboards —
the operator may want session continuity preserved across automatic
lifecycle events and only end sessions on an explicit revoke
command.

The per-app `backchannel_logout_on_revoke_only` BooleanField narrows
the fan-out:

| Flag value | What fires for this RP |
|---|---|
| `False` (default) | All five triggers fire (v1 behaviour) |
| `True` | ONLY `oidc_revoke_user_tokens` (`reason="user_revoked"`); the four lifecycle reasons (`user_deactivated`, `groups_changed`, `state_changed`, `user_deleted`) are silently skipped |

### When to enable

- Audit / analytics RPs that need to keep recording activity across
  brief account churn (group rotations, temporary deactivations).
- RPs whose own session lifecycle is longer than the AS-side
  membership state and where the operator explicitly accepts the
  "stale-session" risk in exchange for continuity.

### Semantics of "skipped"

A skipped event is **silent** on the audit signal — no
`oidc_logout_dispatched` event is emitted. This keeps the audit log
clean for the typical default-`False` deployment. When an operator
needs to confirm that gating actually triggered (e.g. troubleshooting
"why didn't BCL fire on this group change"), set `debug_mode=True`
on the affected RP and re-run the trigger; the dispatcher emits an
INFO-level log line containing the literal substring
`skipped by on_revoke_only flag` and the originating reason. With
`debug_mode=False`, the same call routes to DEBUG and stays hidden.

### Custom receivers

Operators wiring their own receivers to `oidc_logout_required` MUST
use `reason="user_revoked"` when they want the dispatch to bypass
the flag. Unknown / custom reason strings are treated as non-revoke
and skipped when `backchannel_logout_on_revoke_only=True`.

## 4. logout_token structure

Header:

```json
{ "typ": "logout+jwt", "alg": "RS256", "kid": "<RFC 7638 thumbprint>" }
```

Payload (closed set — no fields beyond these are emitted, ever):

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

Spec literals you MUST NOT "fix":

- `events` URI is `http://...`, not `https://...`. Spec §2.4.
- `nonce` claim is NEVER present (spec MUST NOT).
- `sid` claim is NEVER present in v1 — sub-only logout per §2.6.

Identity / PII claims (`email`, `name`, `picture`, `groups`, `locale`,
`scope`, `client_secret`, character data) are NEVER emitted in the
logout_token. A regression test
(`TestBackChannelLogoutTokenBuilder.test_payload_never_contains_pii`)
keeps the absence pinned.

## 5. Retry & idempotency

The Celery task `allianceauth_oidc.send_logout_token` carries scalar
arguments (`user_pk`, `application_pk`, `jti`, `signing_kid`, `iat`)
so the broker NEVER stores a JWT. On each attempt the worker rebuilds
the token against the captured `signing_kid` and the pinned
`(jti, iat)`, so retries are byte-identical. Default retry schedule
is exponential backoff with `retry_backoff_max=125 s` as the
per-attempt delay ceiling; with `max_retries=5` the realised
sequence is 5 s, 10 s, 20 s, 40 s, 80 s — cumulative wall-clock
≤ 155 s (≈ 2:35), inside the 3-minute window the spec recommends
for RP `iat` freshness. A higher `max_retries` would actually
exercise the 125 s ceiling.

Status-code routing:

| RP response | Action |
|---|---|
| 2xx | Success; audit signal `oidc_logout_dispatched(success=True)` |
| 3xx | Blocked — `allow_redirects=False`; `reason="redirect_blocked"`; no retry |
| 4xx | `reason="rp_client_error"`; no retry |
| 5xx | Celery autoretry; final failure → `reason="retries_exhausted"` |
| `SigningKeyRetiredError` | `reason="signing_kid_retired"`; no HTTP call |

Outbound HTTP discipline:

- `requests.post(allow_redirects=False, timeout=(5, 10))`.
- Response body is NEVER read; only `status_code`.
- `User-Agent: allianceauth-oidc/<version>`.

## 6. Security model

- **SSRF defense.** `Application.clean()` resolves the host with a
  bounded `concurrent.futures.ThreadPoolExecutor` (3 s wall-clock),
  not `socket.setdefaulttimeout` — the latter is a process-global
  mutable and does NOT bound `getaddrinfo` (a libc resolver call).
  Private / loopback / link-local / multicast / reserved /
  unspecified (`0.0.0.0` / `::`) IPs are rejected unless the
  dev-only escape hatch
  `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` is set.
  IPv4-mapped IPv6 (`::ffff:a.b.c.d`) and 6to4 (`2002:…`) addresses
  are unmapped to their embedded IPv4 before predicate checks, so a
  resolver returning a v6-encoded private address cannot bypass the
  gate.

- **DNS-failure policy is non-blocking.** Transient resolver failures
  (`gaierror`, `socket.timeout`, `OSError`,
  `concurrent.futures.TimeoutError`) log a WARNING and allow the
  admin form to save. Operators decide whether to alert on the
  frequency — graylog dashboard, log aggregator, etc. — and a
  malicious / drifted RP URL still has to pass the SSRF rejection at
  the next save.

- **No tokens in logs.** All log lines in `logout.py` and
  `tasks.send_logout_token` route through `build_logout_debug_meta`,
  which has a fixed allow-list of fields (`application_pk`,
  `application_name`, `backchannel_logout_uri`, `jti`, `status_code`,
  `reason`). The
  `TestBackChannelLogoutLogging.test_*_branch_log_has_no_token_material`
  tests verify no `logout_token`, `access_token`, `refresh_token`,
  `id_token`, or `client_secret` leaks into captured log output
  across the 3xx / 4xx / kid-retired branches.

- **No PII in tokens.** Per §4 above — closed payload set.

## 7. Audit / observability

Two Django signals are emitted:

- `oidc_logout_required(sender, user, application, reason=None)` —
  raised by every trigger site BEFORE any HTTP fan-out happens. The
  default receiver (`logout.dispatch_backchannel_logout`) enqueues
  the Celery task; custom receivers can connect under a different
  `dispatch_uid` for SIEM forwarding.

- `oidc_logout_dispatched(sender, application, jti, success, attempt_count, user_pk=None, reason=None)`
  — fired by `tasks.send_logout_token` on every attempt (success,
  3xx, 4xx, kid-retired, retries-exhausted) AND by the dispatcher
  when the broker is unavailable. Receivers can forward
  `LogoutAuditBody` (the curated audit payload) to log aggregators
  without leaking secrets. `user_pk` is a plain integer so the
  `user_deleted` flow can still report the affected user after the
  user row has been deleted.

## 7.1 Dead-letter audit table

`BackChannelLogoutAttempt` records every terminal
`oidc_logout_dispatched` event as one immutable audit row. Operators
inspect it from Django admin → **Alliance Auth OIDC → Back-Channel
Logout attempts**.

| Column                            | Source signal field | Notes                                                  |
|-----------------------------------|---------------------|--------------------------------------------------------|
| `application`                     | `application`       | FK to `AllianceAuthApplication`. `SET_NULL` on delete — admin-driven RP deletion does NOT wipe the row. |
| `application_client_id_snapshot`  | `application`       | `client_id` snapshot captured at insert; survives FK becoming NULL. Indexed for per-RP forensic queries on historical rows. |
| `application_name_snapshot`       | `application`       | Display-name snapshot captured at insert; survives FK becoming NULL. |
| `user_pk`                         | `user_pk`           | Plain int; `NULL` after the user row is gone.          |
| `jti`                             | `jti`               | 32-char hex from `uuid4().hex`. Empty for pre-mint failures. |
| `success`                         | `success`           | `True` = HTTP 2xx; `False` = every other terminal outcome. |
| `attempt_count`                   | `attempt_count`     | Celery attempt number (1-based). `0` for dispatcher-side failures. |
| `reason`                          | `reason`            | Trigger reason on success, failure mode on failure.    |
| `created_at`                      | wall clock          | `auto_now_add`; indexed for `-created_at` ordering.    |

**What gets recorded.** By default, **only failures** —
`success=False` rows with one of `redirect_blocked`,
`rp_client_error`, `retries_exhausted`, `signing_kid_retired`,
`signing_kid_resolve_failed`, or `broker_unavailable`. Successful
dispatches are silently dropped to keep the table focused on what
needs operator attention.

Set `ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True` in Django settings to
also record successful dispatches (e.g. for full SIEM correlation
or compliance trails). Off by default; flipping the flag affects
new events only — historical rows are not backfilled.

**Read-only by design.** The admin disables add and change; the
audit row is a faithful record of what happened on the wire and
MUST NOT be edited. Delete remains available so superusers can
prune the table manually or via a scheduled Celery task on a
retention policy.

**Retention.** No automatic cleanup is shipped — the table grows
linearly with failure volume. For a moderately-trafficked install
that means handfuls of rows per week. Operators with high failure
volume (or a compliance retention ceiling) can wire a Celery beat
task that runs `BackChannelLogoutAttempt.objects.filter(
created_at__lt=cutoff).delete()` on a schedule, mirroring the
pattern used for `clear_expired_tokens` in the README's
`Periodic cleanup of expired tokens (Celery Beat)` section.

**Forwarding to SIEM.** Connect a second receiver to
`oidc_logout_dispatched` under a different `dispatch_uid` —
`record_backchannel_logout_attempt` does not consume the signal.
SIEM forwarders typically combine `application_id` + `user_pk` +
`reason` into a structured log line; the curated
`LogoutAuditBody` TypedDict documents the safe-to-forward field
set.

## 8. Out of scope — feature v2 (session-scoped logout)

Sub-only logout terminates **all** of the user's sessions on the RP.
A future feature iteration may add session-scoped logout (`sid`
claim on the `logout_token`). The v1 omission is intentional, not
an oversight; the session-scoped flow requires coupling with DOT's
`RefreshToken.token_family` or a dedicated `OIDCSession` model, and
the spec explicitly permits the AS to opt out of session scoping.

## 9. RP integration

Most off-the-shelf OIDC libraries support back-channel logout out of
the box:

- **oauth2-proxy** — set the redirect URI on the AS and configure the
  RP's back-channel logout endpoint.
- **mod_auth_openidc (Apache)** — `OIDCSessionType server-cache` plus
  a registered logout endpoint per the module docs.
- **Wiki.js / Outline / Grafana** — see vendor docs for "OIDC
  back-channel logout"; the
  `backchannel_logout_supported: true` flag in the discovery doc is
  the feature-detection probe.

For each RP:

1. Register the back-channel logout endpoint on the RP side.
2. Set `backchannel_logout_uri` in Django admin → OIDC application.
3. Trigger a logout (e.g. `manage.py oidc_revoke_user_tokens
   --username=test`).
4. Confirm the RP's logs show a `logout_token` POST with `aud =
   <client_id>` and the user's `sub` matching the AS's user.pk.
