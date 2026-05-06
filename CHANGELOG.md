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

### Project

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
