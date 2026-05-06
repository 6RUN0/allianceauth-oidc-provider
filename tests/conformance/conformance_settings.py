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
from tests.test_settingsAA4 import OAUTH2_PROVIDER

# Public URL the conformance suite uses to reach the provider. The
# default matches the docker-compose layout: ``provider`` is the
# Docker DNS name for our service, reachable from the suite container
# on the shared bridge network. The trailing ``/o`` matters: OIDC
# Discovery 1.0 requires ``iss`` to equal ``discoveryUrl`` with the
# ``/.well-known/openid-configuration`` suffix removed. Our discovery
# lives at ``/o/.well-known/...`` (DOT mounts everything under ``/o/``
# in tests/urls.py), so ``iss`` must include ``/o`` to match.
CONFORMANCE_PUBLIC_URL = os.environ.get(
    "CONFORMANCE_PUBLIC_URL",
    "http://provider:8080/o",
)

DEBUG = False
ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = [
    "http://provider:8080",
    "http://localhost:8080",
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

# The conformance suite POSTs to /account/login/ with a normal Django
# session cookie. Production AA sets Secure on the session cookie; the
# suite-facing httpd terminates TLS and forwards plain HTTP, so we
# leave the Secure flag off here. This is *only* the conformance
# settings module — production AA settings are unaffected.
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
