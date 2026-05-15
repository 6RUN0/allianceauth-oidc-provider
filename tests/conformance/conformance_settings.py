"""
Conformance-Suite-friendly Django settings.

Extends ``tests.test_settingsAA4`` with the bare minimum a real RP
expects when our provider runs behind the suite's HTTPS termination
(``localhost.emobix.co.uk:8443``):

- ``ALLOWED_HOSTS`` opens the ``provider`` Docker hostname so the
  conformance-suite container can resolve us.
- ``CSRF_TRUSTED_ORIGINS`` allows the suite's HTTPS host to POST.
- ``DEBUG = False`` so traceback HTML doesn't leak into the suite's
  log captures (which would falsely flag PII).
- ``OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"]`` pins the issuer to the
  suite-facing URL — without this DOT would build ``iss`` from the
  internal Docker hostname and the id_token would not validate.

Use via:

    DJANGO_SETTINGS_MODULE=tests.conformance.conformance_settings
"""

from __future__ import annotations

import os

from tests.test_settingsAA4 import *  # noqa: F403
from tests.test_settingsAA4 import OAUTH2_PROVIDER, STORAGES

# Public URL the conformance suite uses to reach the provider. The
# default matches the docker-compose layout: ``provider`` is the
# Docker DNS name for our service, reachable from the suite container
# on the shared bridge network. ``https://`` (not http://) because the
# suite enforces TLS for OIDC discovery — see
# ``CheckDiscEndpointAllEndpointsAreHttps``. The trailing ``/o`` matters:
# OIDC Discovery 1.0 requires ``iss`` to equal ``discoveryUrl`` with the
# ``/.well-known/openid-configuration`` suffix removed. Our discovery
# lives at ``/o/.well-known/...`` (DOT mounts everything under ``/o/``
# in tests/urls.py), so ``iss`` must include ``/o`` to match.
CONFORMANCE_PUBLIC_URL = os.environ.get(
    "CONFORMANCE_PUBLIC_URL",
    "https://provider:8443/o",
)

DEBUG = False
ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = [
    "https://provider:8443",
    "https://localhost:8443",
    # Suite's TLS-terminated ingress; included so an operator iterating
    # via the UI on the host can drive consent / login forms without
    # CSRF rejections.
    "https://localhost.emobix.co.uk:8443",
    # Inherited ``SITE_URL`` from test_settingsAA4. AA's startup check
    # (allianceauth.checks.B007) warns when SITE_URL isn't in this
    # list; quietest path is to keep it.
    "https://example.com",
]

# AA's settings template points ``WSGI_APPLICATION`` at
# ``allianceauth.wsgi.application``, which only exists in a *deployed*
# AA project tree (alongside manage.py) — not in the installed
# package. ``runserver`` resolves this at startup and would crash; set
# to None so Django falls back to ``get_wsgi_application()`` and uses
# its default WSGI handler.
WSGI_APPLICATION = None

# Pin the issuer so id_tokens validate against the URL the suite
# actually used. DOT will derive the rest of the discovery doc URLs
# relative to this when ``OIDC_ISS_ENDPOINT`` is set.
OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"] = CONFORMANCE_PUBLIC_URL
# A longer access token TTL keeps the suite from spinning into refresh
# tests prematurely.
OAUTH2_PROVIDER["ACCESS_TOKEN_EXPIRE_SECONDS"] = 3600
# DOT's default 60-second auth-code TTL is preserved here — current
# step pacing of the conformance suite reliably exchanges the code
# well within that window. Holding the production default keeps the
# suite honest: an unexpected mid-flow ``invalid_grant`` from a
# browser-driven module signals a real regression in code lifetime
# accounting, not a too-tight test fixture knob.
OAUTH2_PROVIDER["AUTHORIZATION_CODE_EXPIRE_SECONDS"] = 60

OAUTH2_PROVIDER["REFRESH_TOKEN_EXPIRE_SECONDS"] = 24 * 3600

# OIDC_RP_INITIATED_LOGOUT_ENABLED is default-on through
# AllianceAuthOIDC.ready (``_apply_default_oauth2_provider_settings``)
# — no explicit opt-in needed here. ALWAYS_PROMPT below stays
# conformance-only because production deployers want the user to
# see a confirm screen by default; only the headless suite needs to
# bypass it.
# DOT's stock ``RPInitiatedLogoutView`` renders an HTML confirm page
# at ``oauth2_provider/logout_confirm.html`` when this is True; the
# suite's headless HtmlUnit cannot follow a confirm-and-submit flow
# (same Bootstrap 5 / ES6+ stall that brakes
# ``oidcc-userinfo-post-header`` upstream). Skip the prompt so the
# logout path completes inline. Operators wanting an interactive
# logout confirm in production keep the default True.
OAUTH2_PROVIDER["OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT"] = False

# The conformance suite POSTs to /account/login/ with a normal Django
# session cookie. Production AA sets Secure on the session cookie; the
# suite-facing httpd terminates TLS and forwards plain HTTP, so we
# leave the Secure flag off here. This is *only* the conformance
# settings module — production AA settings are unaffected.
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# AA's stock ``/account/login/`` template is EVE-SSO-only — a single
# OAuth-redirect link, no username/password form. The conformance
# suite's headless browser expects a fillable login form
# (``id_username`` / ``id_password``), so route the login flow
# through Django admin's login view instead. Admin's template uses
# exactly those field IDs and accepts a ``next=`` parameter, so AA's
# middleware sends unauthenticated users there, and on success the
# browser is redirected back to ``/o/authorize/...`` to complete the
# OIDC flow. The seeded conformance user has ``is_staff=True`` (see
# ``seed.py``) so admin login accepts it.
LOGIN_URL = "/admin/login/"

# Alliance Auth's base settings use ``AaManifestStaticFilesStorage``,
# which expects ``collectstatic`` to have populated a manifest of
# hashed filenames. Templates rendered by the suite's headless Chromium
# (login form, consent page) reference static assets via
# ``{% static ... %}``, and the manifest backend raises ``ValueError``
# at template render time if the file is not in the manifest. We do
# not run ``collectstatic`` in the conformance container — it is a
# CI-style ephemeral harness, not a real deployment — so swap the
# staticfiles backend for the non-manifest variant. Asset URLs still
# resolve at template-render time; the headless browser will 404 on
# the icons themselves, but the form renders and the suite's
# Selenium driver fills/clicks regardless.
STORAGES = {
    **STORAGES,
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}
