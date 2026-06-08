# Changelog

All notable changes to this fork are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(0.x.y range — minor bumps may include breaking changes).

This is the changelog for the
[6RUN0/allianceauth-oidc-provider](https://github.com/6RUN0/allianceauth-oidc-provider) fork.
Upstream history at
[Solar-Helix-Independent-Transport/allianceauth-oidc-provider](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
is preserved in `git log`; this file documents fork-specific changes only.

## [Unreleased]

## [0.4.1] - 2026-06-08

### Changed

- The `oidc_fix_idtoken_jti` management command (shipped in 0.4.0) is
  renamed `oidc_fix_uuid_columns` and now realigns **both** DOT
  `UUIDField` columns affected by the MariaDB `>= 10.7` native-uuid
  overflow, preserving each column's nullability. No backward-compatible
  alias is kept — the old name shipped only one release prior.

### Fixed

- `oauth2_provider_refreshtoken.token_family` overflow on MariaDB
  `>= 10.7`. Like `idtoken.jti`, `token_family` is a DOT `UUIDField`; on
  a schema carried across the 10.7 boundary it stays `char(32)` and
  overflows with `1406 Data too long` during refresh-token rotation.
  `allianceauth_oidc.W006` now scans both DOT UUID columns (`jti` is
  `NOT NULL`, `token_family` is nullable) and the renamed
  `oidc_fix_uuid_columns` command converts both — emitting `UUID NULL`
  for `token_family` so existing `NULL` rows are preserved. See
  `docs/MARIADB.md`.

## [0.4.0] - 2026-06-08

### Added

- MariaDB `>= 10.7` native-`uuid` safety net for DOT's idtoken `jti`
  column. Django 5.x treats MariaDB `>= 10.7` as having a native `uuid`
  type and writes `UUIDField` values in the 36-char dashed form; a
  `oauth2_provider_idtoken.jti` column left at the legacy `char(32)` by
  an upgrade across the 10.7 boundary then overflows and fails every
  id_token issuance on `/o/token/` with `1406 Data too long for column
  'jti'`. Two new surfaces address it: the `allianceauth_oidc.W006`
  database-tagged system check flags the mismatch at `manage.py check
  --database` / `migrate`, and the `manage.py oidc_fix_idtoken_jti`
  command converts the column to the native `uuid` type (no-op on every
  other backend / already-converted column; honours `--dry-run` /
  `--format`). DOT owns the table, so the corrective ships as a command
  rather than a migration. Operator guide:
  [docs/MARIADB.md](docs/MARIADB.md).

### Fixed

- RP-initiated logout confirmation page now renders. The
  `logout_confirm.html` override lived under
  `templates/allianceauth_oidc/`, but DOT's `RPInitiatedLogoutView`
  loads `oauth2_provider/logout_confirm.html`, so the override never
  rendered and the page fell back to DOT's unstyled default. The
  template moved to `templates/oauth2_provider/` to shadow DOT's copy
  and now extends `allianceauth/base-bs5.html` so the logout page
  matches the Alliance Auth shell. The `authorize.html` / `denied.html`
  templates were modernized to Bootstrap 5 classes at the same time. A
  new `tests/test_templates_render.py` drives each template through its
  view to guard against silent override breakage.
- `BackChannelLogoutAttempt.jti` widened from `char(32)` to
  `varchar(255)` (migration `0020`). The column was sized to exactly
  our own minted jti (`uuid4().hex`, 32 chars), but the
  `oidc_logout_dispatched` signal accepts third-party senders and a jti
  per RFC 7519 is an arbitrary string (canonical dashed UUID is 36
  chars, a SHA-256 hex digest is 64). Any longer value overflowed the
  audit column on MySQL/MariaDB with error 1406 while passing silently
  on sqlite. 255 matches DOT's string-column convention and covers
  every realistic jti format.
- Documented issuer in the README endpoints table corrected from
  `https://your.host/o/` to `https://your.host/o` (no trailing slash).
  Without `OIDC_ISS_ENDPOINT`, DOT derives the issuer by stripping
  `/.well-known/openid-configuration` off the discovery URL, so the
  mount-prefix slash leaves with the suffix and the canonical `iss` has
  no trailing slash. RPs validate `iss` against discovery's `issuer`
  byte-for-byte, so the slash mattered. New regression tests in
  `tests/test_discovery.py` pin it: discovery `issuer` carries no
  trailing slash, the id_token `iss` equals discovery's `issuer`, and
  the request-derived issuer (no `OIDC_ISS_ENDPOINT`) resolves to the
  mount prefix minus its slash.

### Tooling

- The `Makefile` is now generated from the `TARGETS` table in
  `_nox/makefile.py` instead of being hand-edited. New `makefile` /
  `makefile_check` nox sessions regenerate it and drift-check it; the
  `makefile_check` gate is wired into `preflight`, pre-commit, and CI
  and enforces that the committed file matches the render, every nox
  session has a `make` target, and no target names a session that no
  longer exists.
- New `tests_mariadb` nox session and CI job exercise the suite against
  a real MariaDB (testcontainers locally, a service container in CI)
  so the MySQL-family code paths are covered, not just typeless sqlite.
  Skips cleanly when neither Docker nor a database is reachable.
  Guide: [docs/MARIADB.md](docs/MARIADB.md).
- New pre-commit gates: `pygrep-hooks` (rejects Mock-method typos,
  `logger.warn`, `eval()`, U+FFFD, and blanket `type: ignore`),
  `name-tests-test`, and `djlint` (Django template lint/format).
- New `migrations_concurrency_check` nox/CI gate scans raw `RunSQL`
  migrations for blocking (non-online) DDL on MySQL/MariaDB.
- New `messages_check` nox/CI gate verifies `.po` / `.pot` / `.mo`
  catalogue integrity without gating translation completeness.
- The AA 5.x cross-version sweep (`tests_matrix`) now builds its argv
  through a pure, unit-tested helper in `_nox/matrix.py`.

## [0.3.2] - 2026-06-05

No wire-protocol or runtime-behaviour changes since `0.3.1`; operators
upgrading need no action. The one code change is a `django-oauth-toolkit`
3.3 compatibility fix (model-state only, no schema migration).

### Fixed

- Compatibility with `django-oauth-toolkit` 3.3. DOT 3.3 reworked the
  `help_text` of the inherited `client_secret` field on its abstract
  `AbstractApplication`; because that field is materialised into this
  app's `0001` migration, `makemigrations --check` went dirty under DOT
  3.3 (caught by `test_makemigrations_check_dry_run_clean` on the
  off-lock AA4 matrix). `AllianceAuthApplication` now overrides
  `client_secret` with attributes mirroring the frozen `0001` state,
  pinning the model so `makemigrations --check` stays clean across the
  whole supported range (`>=3.2,<4`). Metadata-only change — no schema
  migration and no database effect.

### Documentation

- Close 14 README/code drifts found in a two-critic review. Operators
  were missing the entire Prometheus surface, two of five audit signals,
  and the dead-letter table — all shipped, none documented. Now covered:
  the `[metrics]` extra and the nine `aa_oidc_*` metrics (linking
  `docs/METRICS{,.ru}.md`), the `OIDC_RSA_PRIVATE_KEYS_INACTIVE` rotation
  window, all five audit signals with their default receiver names (was
  three), and the `BackChannelLogoutAttempt` dead-letter table. Three
  BCL / private-network settings move into the main settings table,
  `/o/authorized_tokens/` joins the endpoints table, and `README.ru.md`
  reaches parity (`logo_url`, `backchannel_logout_uri`,
  `backchannel_logout_on_revoke_only`).

### Tooling

- CI: the `pip-audit` job now runs `actions/checkout` before its local
  composite `./.github/actions/setup` step. Local action references
  resolve against files already on the runner, so without the checkout
  the runner could not find `action.yml` and the job failed.
- Dev: wire the `codegraph` code-intelligence MCP server via `.mcp.json`
  (its `.codegraph/` index directory is git-ignored) and document the
  `codegraph` / `agentmemory` MCP workflow in `CLAUDE.md`.

## [0.3.0] - 2026-05-21 [YANKED]

Tagged but never published to PyPI. The release pipeline raced
against `main.yml` on the first run after the cross-workflow CI gate
was added (commit `663c22f`). The git tag `v0.3.0` exists on the
repository and cannot be deleted (tag protection rules), but no
artefact was uploaded to PyPI.

Install `0.3.1` instead — it contains the identical functional
payload re-tagged after the gate was fixed (commit `6407535`,
`ci(release): bounded polling instead of single-shot CI gate`).

## [0.3.1] - 2026-05-21

> ⚠️ **Operator-visible behavior change**: OIDC RP-Initiated Logout is now
> enabled by default. `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']`
> defaults to `True` via AppConfig; the `/o/logout/` route and the
> `end_session_endpoint` field in discovery become live without operator
> opt-in. Set the key explicitly to `False` in your settings to preserve
> the previous (upstream DOT) behavior — `setdefault` preserves any
> explicit value. See the new `manage.py check` warning
> `allianceauth_oidc.W003` if you disable RP-init logout while
> back-channel logout RPs are registered.

### Security

- BCL Server-Side Request Forgery hardening. Three independent gates
  now defend the worker's outbound `requests.post` against DNS
  rebinding TOCTOU and unsafe-target bypasses:
  (1) the admin-form `clean()` validator,
  (2) a new `pre_save` signal that closes the
  `Application.objects.create(...)` / fixtures / data-migration path
  by-passing `full_clean()`,
  (3) a new request-time `_request_time_ssrf_gate_passes` helper that
  re-resolves the host immediately before `requests.post` and
  fail-closes on transient resolver errors (audit
  `reason="dns_resolve_failed"` / `"unsafe_target_ip"`).
  The shared `_is_unsafe_address` predicate now unmaps IPv4-in-IPv6
  (`::ffff:...`) and 6to4 (`2002:...`) before evaluation and adds
  `is_unspecified` to the rejected set — closing `0.0.0.0`, `::`,
  and 6to4-wrapped private IPv4 bypasses the original five-predicate
  chain missed.

- BCL fan-out skips deactivated apps. `Application.active=False` is
  documented as the kill-switch for compromised/retired clients;
  previously the fan-out filtered tokens but not the Application, so
  a deactivated RP kept receiving signed `logout_token` POSTs (with
  `sub`/`iss`/`aud`/`jti`) on lifecycle events.
  `logout.apps_with_active_tokens` now joins `active=True` and
  `dispatch_backchannel_logout` short-circuits via
  `application.is_usable(None)` next to the existing blank-URI gate.

- `auth_provider._enforce_policy` gained the missing
  `case _: assert_never(decision)` arm on the `AccessDecision` match.
  A future fourth union variant would otherwise let the function
  fall off the end, returning `None`, which oauthlib treats as
  falsy at `validate_code` / `validate_refresh_token` callsites —
  surfacing as `invalid_grant` instead of the loud `TypeError` that
  `assert_never` produces. Mirrors the existing pattern in
  `views_authorize.AuthAuthorizationView.dispatch`.

### Added

- OIDC Back-Channel Logout 1.0 (sub-only v1). Set
  `backchannel_logout_uri` on an application to register an RP for
  fan-out; five trigger sites (revoke command, `User.is_active`
  flip, group / state change, account delete) emit
  `oidc_logout_required` and a Celery task POSTs a signed
  `logout_token` to every registered RP. SSRF defenses: scheme
  allow-list, DNS host check via per-call
  `concurrent.futures.ThreadPoolExecutor` (3 s wall-clock, defends
  against the `setdefaulttimeout` no-op trap), private/loopback/
  link-local/multicast/reserved/unspecified-IP rejection with IPv4-
  in-IPv6 + 6to4 unmap and
  `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE` dev escape hatch.
  Outbound HTTP discipline: `allow_redirects=False`, body never
  read, bounded `timeout=(5, 10)`. Retries are byte-identical
  (worker rebuilds the JWT against pinned `(jti, iat, signing_kid)`).
  Discovery emits `backchannel_logout_supported: true`;
  `backchannel_logout_session_supported` is intentionally absent
  (sub-only v1). Per-app opt-in via
  `AllianceAuthApplication.backchannel_logout_on_revoke_only` to
  receive logout tokens only on explicit `oidc_revoke_user_tokens`
  invocations. Operator guide:
  [docs/BACK_CHANNEL_LOGOUT.md](docs/BACK_CHANNEL_LOGOUT.md).

- JWT access tokens (RFC 9068). Opt-in via two `OAUTH2_PROVIDER` keys —
  `ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT = "jwt"` AND
  `ACCESS_TOKEN_GENERATOR =
  "allianceauth_oidc.tokens.dispatching_access_token_generator"`. Per-app
  override via `AllianceAuthApplication.access_token_format` (`"opaque"` /
  `"jwt"` / blank). Default format remains `"opaque"` for zero-disruption
  upgrades. Tokens stay stateful — JWT lives in
  `oauth2_provider_accesstoken.token` so introspection, revocation, and
  the `oidc_token_issued` audit signal continue to work; the audit body
  gains a `format` field. Identity claims gated through DOT's canonical
  `get_oidc_claims` hook, so AT and id_token claim sets are byte-equivalent
  for the same scope. New configurable size guard
  `ALLIANCEAUTH_OIDC_JWT_SIZE_WARN_BYTES` (default `4096`) emits
  `WARNING` on oversize tokens without mutating issuance. Discovery
  endpoint advertises `access_token_signing_alg_values_supported:
  ["RS256"]`. Operator guide:
  [docs/JWT_ACCESS_TOKENS.md](docs/JWT_ACCESS_TOKENS.md) covers opt-in,
  RP cookbook (oauth2-proxy / mod_auth_openidc / WikiJS), key rotation,
  data minimization, and rollback.

- OIDC RP-Initiated Logout 1.0 (`/o/logout/`) default-on via
  `AllianceAuthOIDC.ready` AppConfig hook. Discovery advertises
  `end_session_endpoint`; the route is `oauth2_provider`'s
  `RPInitiatedLogoutView`, gated by DOT internally. Operators retain
  full control via `OAUTH2_PROVIDER['OIDC_RP_INITIATED_LOGOUT_ENABLED']`
  — `setdefault` semantics preserve any explicit value (including
  `False` for opt-out).

- Eleven new Django system checks at `manage.py check` — six errors,
  five warnings, all under the `allianceauth_oidc.*` namespace:
  - `E001` (Error) — `backchannel_logout_uri` registered without
    `OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']` (Celery worker has no
    HTTP request to derive `iss`).
  - `E002` (Error) — `OAUTH2_PROVIDER_APPLICATION_MODEL` does not
    resolve to `AllianceAuthApplication`. Stock DOT model bypasses
    the three-layer policy enforcement.
  - `E003` (Error) — `OAUTH2_PROVIDER['OAUTH2_VALIDATOR_CLASS']`
    does not resolve to `AllianceAuthOAuth2Validator`. Stock DOT
    validator drops layers 2 and 3 of the policy gate.
  - `E004` (Error) — `OAUTH2_PROVIDER['SCOPES']` does not contain
    the `openid` scope. DOT's default `{"read": ..., "write": ...}`
    silently disables id_token issuance.
  - `E005` (Error) — `OAUTH2_PROVIDER['PKCE_REQUIRED']` is not (or
    does not wrap) `allianceauth_oidc.pkce.per_app_pkce_required`.
    Without the adapter the per-app override silently no-ops, leaving
    public clients vulnerable to auth-code interception per RFC 9700.
  - `E006` (Error) — the dangerous triple-combination has a concrete
    victim: `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True` AND
    `DEBUG=False` AND at least one registered `backchannel_logout_uri`.
    Silenced by the explicit
    `ALLIANCEAUTH_OIDC_ALLOW_PRIVATE_BCL_IN_PRODUCTION=True` opt-in.
  - `W001` (Warning) — `ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True`
    while `DEBUG=False`. Masked-fragment logging is a development aid;
    enabling it in production leaks identifiable token/secret
    fragments into log storage.
  - `W002` (Warning) — half-wired JWT mode: default format set to
    `jwt` without the dispatching `ACCESS_TOKEN_GENERATOR`, or the
    generator wired without the default format set to `jwt`. Both
    halves must agree for JWT to be the global default.
  - `W003` (Warning) — `OIDC_RP_INITIATED_LOGOUT_ENABLED=False`
    while applications carry `backchannel_logout_uri`. The Single-
    Logout chain breaks at the first hop because the RP-init logout
    endpoint is the entry-point that triggers BCL fan-out.
  - `W004` (Warning) — an active application carries a
    `backchannel_logout_uri` using `http://` while `DEBUG=False`.
    Legacy rows persisted under `DEBUG=True` survive a flip; the
    worker re-checks DNS but not scheme.
  - `W005` (Warning) — `ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True`
    while `DEBUG=False` without a registered `backchannel_logout_uri`
    (else `E006` fires). The SSRF gate on BCL targets is disabled.

- `oidc_token_introspected` audit signal (RFC 7662 introspection
  endpoint). Fires on every `/o/introspect/` call with the
  `OIDCIntrospectionAuditBody` TypedDict
  (`introspector`, `token_sha256`, `active`, `client_id`). SIEM/audit
  forwarders attach a custom receiver — the default receiver logs at
  INFO with secrets redacted.

- `oidc_code_reuse_detected` audit signal + `IssuedCodeAudit` model
  implementing RFC 6749 §10.5 reuse detection. DOT 3.2 deletes the
  `Grant` row on first exchange; the new side-table preserves the
  code-hash → tokens link past the Grant's lifetime so reuse triggers
  revocation of the linked access + refresh tokens, not just
  `invalid_grant`. Stored as `sha256(code)`; plaintext code never
  persisted.

- `manage.py oidc_show_effective_policy` — operator inspection of
  the per-app state/group whitelist as it actually evaluates against
  a user, including the global gate. Useful when a user reports an
  unexpected `invalid_grant` and the operator needs to know which
  layer denied.

- `manage.py oidc_revoke_user_tokens --reason TEXT` — optional
  free-form audit string threaded into the `oidc_token_issued`
  revoke audit body and the BCL fan-out trigger.

- `manage.py oidc_jwks_rotate` — operator command to rotate the
  JWKS signing key. Generates a fresh RSA key, retires the current
  active key (rows pinned to the old `signing_kid` keep producing
  byte-identical retries until they expire), and refreshes the
  JWKS endpoint. Honours `--dry-run` to preview the rotation
  without persistence.

- Admin: bulk-action "Send test back-channel logout" on
  `AllianceAuthApplication` changelist. Fires
  `oidc_logout_required` with `reason="admin_test"` on a no-op
  user, exercising the full dispatcher → Celery → RP HTTP path for
  operator validation without affecting real sessions.

- Clickjacking defence on `/o/authorize/`. Response now carries
  `X-Frame-Options: DENY` plus
  `Content-Security-Policy: frame-ancestors 'none'` to defeat the
  RFC 9700 §2.5 attack: an attacker iframes the authorize page to
  capture user interaction. DOT does not set these by default.

- `aa_oidc_policy_rejections_total` Prometheus counter, labelled
  by `stage` (`authorize` / `validate_silent_auth` /
  `validate_code` / `validate_refresh` / `validate_bearer` /
  `save_bearer`) and `reason` (`global` / `app` / `app_unusable`
  / `no_client` / `unknown`). Cross-cuts the three-layer policy
  enforcement so dashboards can answer "which gate fires the most
  at which stage" with a single counter.

- `aa_oidc_code_reuse_audit_misses_total` Prometheus counter,
  labelled by `client_id`. `_handle_potential_code_reuse`
  increments when the reuse path is hit for a code with no
  matching `IssuedCodeAudit` row. After the atomic-wrap of
  `save_bearer_token` + audit insert the race-window source is
  closed, so the counter now exclusively fires on never-issued
  codes (fuzzers / wrong-provider replays). Operators correlate
  against the `oidc_code_reuse_detected` signal — the two should
  be disjoint.

- `aa_oidc_audit_receiver_failures_total` Prometheus counter,
  labelled by `signal` and `receiver_dispatch_uid`. Increments
  per receiver that raised during `send_robust` dispatch of any
  audit signal (`oidc_token_issued`, `oidc_code_reuse_detected`,
  `oidc_token_introspected`, `oidc_logout_dispatched`). Non-zero
  rate means the audit pipeline is silently dropping events for
  at least one downstream consumer.

- Discovery (`/o/.well-known/openid-configuration/`) advertises
  nine additional fields per OIDC Discovery 1.0 §3 / RFC 8414 §2:
  `response_types_supported` narrowed to `["code"]` (was DOT's full
  implicit/hybrid enum); `response_modes_supported`,
  `code_challenge_methods_supported` (S256), `acr_values_supported`
  (`["0"]` per RFC 6711), `prompt_values_supported`,
  `claims_parameter_supported` (True), `request_parameter_supported`
  / `request_uri_parameter_supported` (both False — JAR/PAR not
  implemented), `op_policy_uri` / `op_tos_uri` (operator-provided
  via `ALLIANCEAUTH_OIDC_POLICY_URI` /
  `ALLIANCEAUTH_OIDC_TOS_URI`).

### Changed

- `tests/test_migrations.py` `MIGRATION_TARGET` constant bumped to
  `"0015_backchannellogoutattempt"` so post-migrate live-model
  `objects.create(...)` calls hit a schema with every field added
  this cycle (`pkce_required`, `access_token_format`,
  `backchannel_logout_uri`, `backchannel_logout_on_revoke_only`,
  `BackChannelLogoutAttempt`). PKCE-specific assertions still
  cover the `0011` data step because the chain runs forward.

## [0.2.0b2] - 2026-05-09

### Fixed

- `manage.py oidc_audit_tokens --help` (and the three sibling commands
  `oidc_create_app`, `oidc_revoke_user_tokens`, `oidc_rotate_secret`)
  raised `TypeError: expected string or bytes-like object, got
  '__proxy__'` on Python 3.12+. argparse's `HelpFormatter._fill_text`
  now passes the description / argument-help straight into `re.sub`,
  which refuses to coerce the `gettext_lazy` proxy object that the
  commands had been using. The four commands switched to non-lazy
  `gettext`; the active language is fixed at process start for
  short-lived management commands, so lazy evaluation bought nothing.
  `# type: ignore[assignment]` casts that papered over the
  `BaseCommand.help: str` mismatch are no longer needed and were
  removed.

### Documentation

- README `OAUTH2_PROVIDER` example and key reference now recommend
  `ACCESS_TOKEN_EXPIRE_SECONDS = 3600` instead of `60`. The test-suite
  literal `60` (used by `tests/test_settingsAA4.py` to exercise expiry
  paths without sleeps) was inappropriate as a production starter:
  `passport-openidconnect`-based RPs (Wiki.js, Outline, etc.) reject
  sub-minute access-token lifetimes outright, and even tolerant clients
  race the user's /userinfo round-trip against the TTL when network
  latency creeps up. New value matches the production defaults of
  Auth0 / Keycloak / Google.
- WikiJS integration section expanded: full URL set (authorization /
  token / `userinfo` / issuer / logout), explicit warning that
  `Skip User Profile` must stay off — otherwise WikiJS reads claims
  out of `id_token` only and fails with "Missing or invalid email
  address from profile" because we now follow OIDC Core 1.0 §5.4
  strictly (scope-bound claims live at `/userinfo`, not in `id_token`).
  Strategy choice (Generic OpenID Connect / OAuth 2.0 vs. Generic
  OAuth 2.0) documented with the trade-off.

### Changed

- AA-version test stacks declared as PEP 735 dependency groups
  (`aa4`, `aa5`) in `pyproject.toml` instead of being hard-coded inside
  the `tests_aa4` nox session body. The session now installs via
  `uv pip install -e . --group aa4`, letting uv intersect the package's
  `allianceauth>=4,<6` contract with the group's `<5` narrowing. No
  user-visible changes; the matrix runs the same combinations.
  `uv tree --group aaN` now enumerates each supported stack from
  `pyproject.toml` directly.

## [0.2.0b1] - 2026-05-08

Minor bump (0.1 → 0.2) marks a widened dependency contract: this is the
first release that officially supports Alliance Auth 5.x. Operators
upgrading from `0.1.x` should review the **Compatibility** notes below
before deploying.

### Added

- Official support for Alliance Auth 5.x (Django 5.2). The dev
  environment locks to AA 5.0.1 + Django 5.2.x as the new primary;
  AA 4.x backward compatibility stays under CI through the new
  off-lock `tests_aa4` nox session, exercised on Python 3.10 / 3.11 /
  3.12 (Python 3.13 is excluded because AA 4.13.x declares
  `requires-python <3.13`). The package contract widens to
  `allianceauth>=4,<6`; no version-specific shims live inside the
  package itself.
- Classifier `Framework :: Django :: 5.2` advertised on PyPI
  alongside the existing `Framework :: Django :: 4.2`.

### Changed

- `tests/test_settingsAA4.py` overrides `STORAGES["staticfiles"]`
  back to plain `StaticFilesStorage`. AA 5.x ships with
  `ManifestStaticFilesStorage` as the default, which would otherwise
  refuse to serve unhashed asset paths from templates without a
  `staticfiles.json` produced by `collectstatic`. The override is
  inert under AA 4.x / Django 4.2 (no behavioural change there) and
  unblocks the suite under AA 5.x / Django 5.2.

### Compatibility

- Existing AA 4.x deployments keep working unchanged — no migration,
  no settings edit required.
- Operators planning the AA 4.x → 5.x jump should follow Alliance
  Auth's own upgrade guide; this provider has no AA-version-specific
  configuration knobs to flip.

## [0.1.0b6] - 2026-05-08

### Added

- `email_verified` claim emitted alongside `email` in both `/userinfo`
  and `id_token` per OIDC Core 1.0 §5.1. The value reflects AA's
  email-confirmation state via a three-tier decision tree:
  synthetic placeholder detection (`aa_skip_email`, soft dependency)
  short-circuits to `false`; otherwise
  `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED` (operator override) wins
  when set; otherwise AA's `REGISTRATION_VERIFY_EMAIL` setting is
  mirrored. `email` and
  `email_verified` are emitted as a coupled pair so neither appears
  without the other.
- `acr=0` claim emitted in the id_token when the client supplies
  `acr_values` per OIDC Core 1.0 §3.1.2.6. The provider does not
  implement Authentication Context Class Reference levels, so RFC 6711
  "no specific level" is the honest answer instead of silently
  dropping the claim.
- New tri-state setting `ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`:
  `True` — always emit `email_verified=true` (e.g. trust signal
  originates outside AA: users imported from an already-verifying
  external IdP); `False` — always emit `false`; `None` / unset
  (default) — fall through to the auto decision tree.
- OIDC Discovery (`/o/.well-known/openid-configuration`) now advertises
  `grant_types_supported` and `claim_types_supported` per OIDC
  Discovery 1.0 §3. Closes the
  `EnsureServerConfigurationSupportsRefreshToken` warning the OpenID
  Conformance Suite raised on the `oidcc-refresh-token` plan.
- Soft dependency on the `aa-skip-email` companion plugin: synthetic
  placeholder addresses stamped by it are flagged
  `email_verified=false` regardless of the global setting — those
  addresses exist precisely because the user skipped verification.

### Changed

- The id_token no longer carries scope-bound claims (`email`, `name`,
  `picture`, `groups`, `locale`, `eve_*`) by default per OIDC Core 1.0
  §5.4. DOT mirrored id_token and `/userinfo` through one
  scope-filtered dict, leaking these claims into the id_token at
  `scope=email`. They now remain in `/userinfo` unless the client
  explicitly opts in via the OIDC `claims` request parameter — the
  override `get_id_token_dictionary` filters against a reserved-claims
  whitelist (`sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`,
  `acr`, `amr`, `azp`, `at_hash`, `c_hash`, `jti`) plus
  client-requested id_token claims. Closes the
  `EnsureIdTokenDoesNotContainEmailForScopeEmail` finding from the
  `oidcc-scope-email` conformance plan.

### Tooling

- Conformance harness per-module poll timeout raised from 180s to
  360s. Empirically moved four browser-driven modules
  (`oidcc-max-age-10000`, `oidcc-ui-locales`, `oidcc-claims-locales`,
  `oidcc-scope-email`) from TIMEOUT to stable PASSED without masking
  real hangs — modules that truly wedge still surface within six
  minutes.
- `tests/conformance/diagnostic_export/` added to `.gitignore`:
  per-plan HTML report archives downloaded via the suite's
  `GET /api/plan/exporthtml/{id}` are ephemeral artefacts,
  regeneratable from any rerun.

### Tests

- `signals.py` reaches 100% line and branch coverage. Three direct
  unit tests now exercise the previously-unreached defensive
  `except (AttributeError, TypeError, ValueError, KeyError)` block in
  `audit_oidc_token_issued`: an `AttributeError` swallow path, a
  `body=None` happy-path branch, and a negative case asserting that
  unrelated exceptions (`RuntimeError`) still propagate — guarding
  against accidental widening of the except into `Exception:`.

## [0.1.0b5] - 2026-05-08

### Added

- Per-app PKCE override via the new `AllianceAuthApplication.pkce_required`
  boolean. New applications default to `True` (RFC 9700 secure-by-default);
  existing rows are backfilled from the previous global value at migration
  time, preserving live behaviour. Unknown `client_id` falls back to `True`
  with a logged warning (fail-safe to strict). Configurable via Django
  admin (changelist column, edit-form checkbox, list filter).

### Changed

- `OAUTH2_PROVIDER['PKCE_REQUIRED']` now points at a callable
  (`per_app_pkce_required`) living in the lightweight
  `allianceauth_oidc.pkce` module. The adapter resolves `client_id` to
  an application row via `.only("pkce_required")` and delegates the
  decision to `AccessPolicy.requires_pkce(app)` in `security.py`,
  which stays a pure-logic method (no ORM, testable through the
  `AppLike` Protocol DI seam). Unknown `client_id` is logged at
  `WARNING` (with `%a` for log-injection safety) and falls back to
  `True`.
- The PKCE schema/data migration is now split: `0010` adds the column
  (schema-only, reversible), `0011` performs the
  environment-dependent backfill in a separate file. Greenfield
  installs (no pre-existing rows) skip the data step entirely.
- The data backfill now accepts only an explicit `bool` value verbatim;
  any other shape (callable, `None`, missing key, `str`, `int`) is
  ambiguous and falls back to `pkce_required=True` per RFC 9700,
  emitting a `RuntimeWarning` rather than a raw stderr write.
- `AccessDecision` is now a tagged discriminated union
  (`AllowedDecision | GlobalDeny | AppDeny`) instead of a single
  `NamedTuple` with three nullable fields. The invariant
  "`deny_reason=APP` ⇒ `app is non-None`" now lives in the type;
  `AuthAuthorizationView.dispatch` uses `match` plus
  `typing_extensions.assert_never` for exhaustiveness, replacing
  the previous `assert decision.app is not None`-by-comment.
- `AccessPolicy.pkce_required(app)` renamed to
  `AccessPolicy.requires_pkce(app)` so the policy method does not
  collide with the `AppLike.pkce_required` attribute it reads. The
  rename is internal API; production callers wire through
  `OAUTH2_PROVIDER['PKCE_REQUIRED'] = per_app_pkce_required` and
  are unaffected.

> ⚠️ **Configuration change**: `OAUTH2_PROVIDER['PKCE_REQUIRED']` semantics
> changed from a boolean to a callable. Existing operator settings that
> use `True`/`False` continue to work but no longer match the recommended
> configuration shown in the README. Update to import
> `per_app_pkce_required` from `allianceauth_oidc.pkce` and assign it as
> the value to take advantage of per-app overrides. If running migrations
> against a long-lived process, call `oauth2_settings.reload()` to refresh
> DOT's cached descriptor; new processes pick up the change automatically.
>
> ⚠️ **Upgrade ordering**: run `manage.py migrate` **before** swapping
> `OAUTH2_PROVIDER['PKCE_REQUIRED']` from the previous boolean to the
> `per_app_pkce_required` callable. The migration's data step reads the
> previous global at runtime; the reverse order causes every existing
> app to be force-flipped to `pkce_required=True` (RFC 9700 fail-safe).
> The full upgrade recipe is in the `Upgrading from a previous release`
> section of the README.

### Build

- Build backend switched from `flit_core` to `uv_build`. `version` and
  `description` are now static `[project]` fields in `pyproject.toml`
  (single source of truth); runtime `__version__` resolves via
  `importlib.metadata.version("allianceauth-oidc-provider-eveo7")`
  with a `0.0.0+local` fallback for editable / source checkouts.
  Wheel contents are bit-equivalent to the previous build (same
  `allianceauth_oidc/*` + locale catalogues, no test artefacts).

### Tooling

- Internal typing tightened. New `TokenLike` / `OAuthRequestLike`
  Protocols in `security.py` and a local `ClaimsUser` Protocol in
  `auth_provider.py` replace the previous `object`-typed parameters
  on `TokenAudit`, `audit_oidc_token_issued`, `ClaimsBuilder`,
  `app_log`, and `build_oidc_debug_meta`. Opaque attribute access on
  these helpers is now statically typo-checked.
- mypy strict ramp: `mypy_django_plugin.main` is enabled (django-stubs
  was already in the dev group but never wired in), plus
  `check_untyped_defs`, `warn_unused_ignores`, `warn_no_return`,
  `warn_unreachable`, `strict_equality`, `extra_checks`, and the
  `redundant-expr` / `possibly-undefined` / `truthy-bool` /
  `unused-awaitable` / `explicit-override` error codes. Ten
  Django command / AppConfig overrides gained `@override` decorators
  (via `typing_extensions` to keep the 3.10 floor) as a result of
  `explicit-override`.
- ruff `select` expanded from 11 groups to 28: added `DJ`, `LOG`, `G`,
  `RET`, `DTZ`, `ISC`, `BLE`, `PTH`, `TC`, `TID`, `A`, `FURB`,
  `TRY`, `PERF`, `SLF`, `ICN`, `PGH`, `ARG`, plus the four pylint
  groups `PLE`, `PLW`, `PLC`, `PLR`. Carve-outs at framework-contract
  boundaries (signal handlers, view dispatch, oauthlib validator
  overrides, Django migrations) keep the noise focused on real
  signals.
- New pre-commit hooks: `vulture` (dead-code detection,
  `min_confidence=80` with Django-contract `ignore_names`),
  `xenon` (cyclomatic complexity at `D/B/A` thresholds), and
  `uv lock --check` (locks-file drift on `pyproject.toml` /
  `uv.lock` changes).
- `[tool.coverage]` consolidated into `pyproject.toml`; the legacy
  `.coveragerc` was deleted. New `branch = true`, plus `exclude_also`
  patterns for `if TYPE_CHECKING:`, `assert_never(...)`, Protocol
  method-body stubs (`...`), `def __repr__`, and
  `raise AssertionError`. Total coverage 96% → 97% on the unchanged
  suite, mostly from honest exclusion of unreachable branches.
- `[tool.ruff.lint.per-file-ignores]` cleaned up: redundant
  duplicates removed (`tests/test_settingsAA4.py` now declares only
  the file-specific `N999`), stale `D107` ignore dropped from
  migrations, codes alphabetised within each list, and a docblock
  added explaining ruff's accumulate-not-override semantics.

## [0.1.0b4] - 2026-05-06

### Changed

- The policy-flow diagram in the README is now a pre-rendered D2 SVG,
  not a Mermaid code block. PyPI's `readme-renderer` does not support
  Mermaid extensions, so v0.1.0b3's project page rendered the diagram
  as raw Mermaid source. The new layout keeps the diagram as
  diagram-as-code (`assets/diagrams/policy-flow.d2`) but commits the
  rendered output (`policy-flow.svg`) alongside, and the README
  references it via a raw GitHub URL on the repo's default branch.
  Result: the image renders identically on GitHub, on PyPI, and on
  every other Markdown viewer.

### Tooling

- New `nox -s diagrams` session and `make diagrams` shim render
  `assets/diagrams/*.d2` to SVG via the `d2` binary. Same opt-in
  skip-with-warning pattern as `markdown_lint` and `actions_lint` —
  contributors without `d2` installed get a clean run with a clear
  pointer to install instructions (Gentoo overlay / d2lang.com).

## [0.1.0b3] - 2026-05-06

`v0.1.0b1` and `v0.1.0b2` were tagged but never reached PyPI:

- `v0.1.0b1` — the bundled twine pre-check inside
  `pypa/gh-action-pypi-publish@v1.9.0` rejects
  `Metadata-Version: 2.4` produced by modern flit-core (PEP 685,
  2024).
- `v0.1.0b2` — the same broken twine runs again *during*
  `twine upload` itself (not only the pre-check), so disabling the
  pre-check via `verify-metadata: false` was insufficient.

`v0.1.0b3` switches the publisher to `uv publish`, which understands
`Metadata-Version: 2.4` natively and supports PyPI Trusted
Publishing automatically. It is therefore the actual first PyPI
publication of the fork. The earlier tags remain in git history as
markers of the failed attempts. See the `fix(ci):` commits for the
full diagnosis.

This release also bumps three actions to Node 24 (`actions/checkout`
v4 → v6, `actions/upload-artifact` v4 → v7, `astral-sh/setup-uv` v5
→ v8) to clear the GitHub-Actions Node-20 deprecation warning, and
applies zizmor's security findings (`persist-credentials: false` on
all checkouts, `enable-cache: false` on all setup-uv usages — the
latter to mitigate cache-poisoning across release runs).

### Added

- Russian translation (`locale/ru/LC_MESSAGES/django.po`) covering the consent / logout templates,
  model verbose names + help text, AppConfig name, and operator-command help. Compiled `.mo` ships
  with the wheel so deployments don't need an extra `compilemessages` step.
- Wire-level integration test suite (`tests/test_integration_mock_rp.py`) driven by
  `LiveServerTestCase` + real `requests` + `jwcrypto`. Catches absolute-URL / Bearer-header / cookie
  bugs that Django's test client masks. Surfaced one real bug: `dateformat.format(user.last_login,
  "U")` crashes when `last_login is None` — `force_login` masks it via the `user_logged_in` signal.
- OIDC Conformance Suite scaffold under `tests/conformance/` — docker-compose stack (mongo + suite
  nginx + suite server + provider container), `run_plan.py` REST driver, idempotent `seed.py`,
  minimal `Dockerfile.provider` re-using `tests.test_settingsAA4`. End-to-end pipeline finds real
  conformance gaps; first-run findings recorded inline in the conformance README.
- Operator CLI commands: `oidc_create_app`, `oidc_rotate_secret`, `oidc_revoke_user_tokens`,
  `oidc_audit_tokens`. All accept `--format=table|json|csv`; destructive ones honour `--dry-run`.
- EVE-specific claims (`eve_character_id`, `eve_corporation_*`, `eve_alliance_*`) emitted alongside
  the standard OIDC set, with a configurable `ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX` and scope binding.
- Mermaid diagrams documenting the three-layer policy enforcement in the main README and the
  conformance docker-compose network topology in the conformance README.

### Tooling

- New `nox` sessions: `integration` (mock-RP, `--parallel=1`), `conformance` (docker-compose +
  `run_plan.py`), `makemessages` / `compilemessages` (i18n), `makemigrations` (Django migration
  generator against test settings), `markdown_lint` (rumdl + lychee + vale, each independently
  optional). `Makefile` shims wrap the new sessions.
- `.rumdl.toml` lifts `MD013` line length to 120 columns and excludes code blocks / tables (where
  wrapping breaks copy-paste fidelity).
- `.gitignore` carve-out for `allianceauth_oidc/locale/**/*.mo` and `locale/django.pot` — the
  blanket `*.mo` / `*.pot` ignores stay so stray binaries elsewhere don't sneak in.
- Type-checking ignores updated for the `django-stubs` bump that retired `LogEntry.objects.log_action`
  (deprecated in Django 5.1) — runtime call still works on Django 4.2.

### Build

- `uv.lock` refreshed against upstream (`uv sync --all-groups --upgrade`); three new transitive
  packages pulled in (`ijson`, `jsonseq`, `python-discovery`); no removals.
- Supported Python versions widened to `>=3.10,<3.14` (following allianceauth). CI matrix now covers
  four versions: 3.10 / 3.11 / 3.12 / 3.13.

### Project

- GitHub Actions rewritten under a modern uv pipeline: separate `test`, `lint`, `typecheck`,
  `package` jobs, `concurrency` keyed on the ref, updated action versions. The auto-publish
  workflow to PyPI has not been restored — the fork's release stays manual
  (`uv build && twine upload dist/*`); see below regarding the new distribution name.
- URLs in `pyproject.toml` switched to point at the
  [6RUN0 fork](https://github.com/6RUN0/allianceauth-oidc-provider); `urls.Upstream` retains the
  original [Solar-Helix](https://github.com/Solar-Helix-Independent-Transport/allianceauth-oidc-provider)
  reference.
- README.md gained a fork-banner block at the top, an install-from-PyPI step under the fork's
  distribution name (see below), and a Russian sibling [README.ru.md](README.ru.md).
- The fork is now publishable to PyPI under a fork-specific distribution name,
  `allianceauth-oidc-provider-eveo7`. The natural name `allianceauth-oidc-provider` collides with the
  upstream PyPI release, so the fork's `pyproject.toml` `[project] name` was renamed to surface on
  PyPI without conflict. The import path (`allianceauth_oidc`) is unchanged — settings and imports
  stay drop-in compatible. Upload remains manual for now (`uv build && twine upload dist/*`); a
  GitHub Actions release workflow is not part of this change.
- `pyproject.toml` gained a `maintainers` entry for the fork (Boris Talovikov,
  `boris.t.66@gmail.com`); the upstream `authors` entry is preserved so the original author stays
  visible in PyPI metadata.

## Upstream history

For changes prior to this fork's divergence, see `git log` and the upstream releases page.

[Unreleased]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b2...v0.3.1
[0.3.0]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b2...v0.3.0
[0.2.0b2]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.2.0b1...v0.2.0b2
[0.2.0b1]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b6...v0.2.0b1
[0.1.0b6]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b5...v0.1.0b6
[0.1.0b5]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b4...v0.1.0b5
[0.1.0b4]: https://github.com/6RUN0/allianceauth-oidc-provider/compare/v0.1.0b3...v0.1.0b4
[0.1.0b3]: https://github.com/6RUN0/allianceauth-oidc-provider/releases/tag/v0.1.0b3
