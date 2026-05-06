# OIDC Conformance Suite harness

Runs the [OpenID Foundation Conformance Suite][suite] against the
provider, end-to-end, in three Docker containers (MongoDB + Java
suite + our provider).

[suite]: https://gitlab.com/openid/conformance-suite

## What this is for

`tests/test_conformance.py` and `tests/test_integration_mock_rp.py`
are our own regression tests; they catch the bugs *we know about*.
The conformance suite catches the bugs *the spec writers know about*
— corner cases of OIDC Core 1.0, RFC 6749, RFC 7009, RFC 7636, etc.,
that an in-tree test wouldn't think to check. Run it before tagging
a release and after any change to the protocol surface.

## Prerequisites

- Docker 24+ (uses Compose V2 — `docker compose`, not `docker-compose`)
- ~2 GB free disk for the suite + MongoDB images (pulled from
  `registry.gitlab.com/openid/conformance-suite{,/nginx}`; pinned to
  release-v5.1.43 by default)
- Ports 8443 (suite) and 8080 (provider) free on the host
- `/etc/hosts` entry `127.0.0.1 localhost.emobix.co.uk` (the public
  DNS record points there too, so this is usually only needed when
  your network resolver blocks the lookup)

## One-shot run

```sh
uv run nox -s conformance
```

The session:

1. `docker compose -f tests/conformance/docker-compose.yml up -d --wait`
   — brings up all three services and blocks on health checks.
2. `python tests/conformance/run_plan.py` — submits the full
   `oidcc-basic-certification-test-plan` (~80 modules), polls each,
   exits non-zero if any FAIL.
3. `docker compose down` — tears the stack down.

A complete run takes 10–15 minutes on a developer laptop.

## Manual / iterative use

When iterating on a specific module, drive the suite from its UI:

```sh
docker compose -f tests/conformance/docker-compose.yml up -d --wait
open https://localhost.emobix.co.uk:8443
```

The browser will warn about a self-signed cert; that's expected. The
suite UI lets you create plans, run individual modules, and inspect
trace logs.

## Run a different plan

```sh
# Smoke run (fewer modules, ~2 minutes):
uv run python tests/conformance/run_plan.py --plan oidcc-test-plan

# Other certification plans (query the suite for the full list):
curl -ks https://localhost.emobix.co.uk:8443/api/plan/available \
  | python -c "import json,sys; [print(p['planName']) for p in json.load(sys.stdin) if p['planName'].startswith('oidcc-')]"
```

Use `--strict-warnings` to fail the run on WARNING-level results
(e.g. when preparing a certification submission).

## Configuration

`run_plan.py` reads from environment variables that are pre-set by
docker-compose; override them when targeting another deployment:

| Variable                    | Default                                                       | What it controls                            |
|-----------------------------|---------------------------------------------------------------|---------------------------------------------|
| `CONFORMANCE_SUITE_URL`     | `https://localhost.emobix.co.uk:8443`                         | Suite REST endpoint (driven by run_plan.py) |
| `CONFORMANCE_PUBLIC_URL`    | `http://provider:8080`                                        | discoveryUrl + iss; Docker-DNS by default   |
| `CONFORMANCE_CLIENT_ID`     | `conformance-client`                                          | Pre-registered client_id                    |
| `CONFORMANCE_CLIENT_SECRET` | `conformance-secret`                                          | Pre-registered client_secret                |
| `CONFORMANCE_USERNAME`      | `conformance`                                                 | Test user the suite logs in as              |
| `CONFORMANCE_PASSWORD`      | `conformance-pass`                                            | Test user password                          |
| `CONFORMANCE_REDIRECT_URI`  | `https://localhost.emobix.co.uk:8443/test/a/conformance/callback` | Pre-registered redirect_uri             |

`seed.py` reads the same set; both are kept in sync deliberately.

## Networking model

The four containers share the default compose bridge network:

```
+-------------+       +---------+       +--------+
|  run_plan.py|----TLS+--nginx--+--HTTP-+ server |
|  (host)     | 8443  |         |       +--------+
+-------------+       +---------+         |
       |                                  | http://provider:8080
       v                                  v
   localhost.emobix.co.uk:8443       +----------+
   (cert valid)                      | provider |
                                     +----------+
```

- The suite (Java service) and its embedded headless browser both
  reach our provider via the Docker DNS name ``provider`` on port
  8080.
- ``CONFORMANCE_PUBLIC_URL`` defaults to that same URL so ``iss`` in
  the discovery doc / id_token validates from the suite's view.
- The host's web browser opens the suite UI at
  ``https://localhost.emobix.co.uk:8443/`` (TLS terminated by the
  suite's own nginx). It does NOT touch our provider directly except
  to debug — port 8080 is published to the host for that purpose.

## Troubleshooting

- **`localhost.emobix.co.uk` doesn't resolve.** This is a public DNS
  record that points at 127.0.0.1, owned by emobix.co.uk for exactly
  this purpose. If your network blocks it, add an `/etc/hosts` entry:
  `127.0.0.1 localhost.emobix.co.uk`.
- **Suite hangs at the login page.** AA's Django login form must
  expose `id_username` / `id_password` inputs and a submit button —
  the standard Django auth template does. If you've overridden it,
  update the `browser.tasks` block in `run_plan.py` to match the new
  selectors.
- **Provider container won't start.** Likely the AA migrations failed.
  Run `docker compose logs provider` and look for the `migrate` step.
  AA wants Redis on startup — fakeredis is enabled via
  `AA_USE_FAKE_REDIS=1`, which the entrypoint script sets.

## Known conformance findings

A first run of this scaffolding against the provider surfaced these
issues. They are *real* spec violations from the suite's perspective;
fix priority is up to you. The pipeline gates on all of them, so a
green run requires addressing each one.

| Module                             | Failure                                                      | Root cause                                                                                                                                |
|------------------------------------|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `oidcc-discovery-endpoint-verification` | `discoveryUrl is missing '/.well-known/openid-configuration'` | Django's `APPEND_SLASH` redirects `/.../openid-configuration` → `/.../openid-configuration/`; the suite doesn't follow. Add a no-slash route or disable `APPEND_SLASH` for this path. |
| `oidcc-discovery-endpoint-verification` | `Expected https protocol for *_endpoint`                      | All endpoints in the discovery doc are advertised as `http://` because the docker-compose serves the provider on plain HTTP. Add a TLS-terminating sidecar (e.g. nginx with self-signed cert) or proxy through the suite's nginx. |

Fixing both requires touching product code (URL conf for the
no-slash redirect, plus a deployment/networking change for HTTPS) —
out of scope for the scaffolding commit. The suite makes a clean
target for an iterative "fix one, re-run" loop.

## Known limitations

- This harness is a *scaffold*. The first run will likely surface
  conformance failures or warnings the unit tests don't catch — that
  is the entire point. Triage and fix per module.
- No Selenium grid: the suite uses its bundled headless browser. If
  the AA login template changes drastically, hand-edit
  `browser.tasks` in `run_plan.py`.
- `oidcc-config` exercises dynamic registration optionally; we don't
  implement it, so those modules will SKIP.
