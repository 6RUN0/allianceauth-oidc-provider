#!/usr/bin/env sh
# Entrypoint for the conformance provider container.
#
# Bootstraps the database, seeds the deterministic test client/user,
# and starts the Django dev server. ``runserver`` is fine here — this
# is a test harness, not production. ``--noreload`` avoids the
# auto-reloader's double-import side effects on AA startup.
set -eu

export DJANGO_SETTINGS_MODULE=tests.conformance.conformance_settings
export PYTHONUNBUFFERED=1

# Migrate first so seed has tables to write into. ``--run-syncdb``
# covers AA models that lack initial migrations on a fresh DB.
uv run python -m django migrate --run-syncdb --noinput

# Seed the conformance client and user. Idempotent.
uv run python tests/conformance/seed.py

# Bind to all interfaces so the suite container can reach us by
# Docker DNS (``provider:8080``).
exec uv run python -m django runserver 0.0.0.0:8080 --noreload --insecure
