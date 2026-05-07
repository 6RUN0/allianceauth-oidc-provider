"""
Build the JSON config the conformance suite stores against a plan.

The suite's plan registry persists this dict and re-uses it for
every module the plan kicks off — so the structure has to match what
the suite expects exactly. The shape is documented inline in
``build_plan_config``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .config import (
    CLIENT2_ID,
    CLIENT2_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    PUBLIC_URL,
    USERNAME,
)


def _host_root(public_url: str) -> str:
    """
    Strip the OIDC path prefix from ``public_url`` to recover the
    Django host root.

    AA's login and consent templates live on the host root (no
    ``/o/`` prefix); the suite's headless browser hits both during
    automation, so we need a clean base URL — not the
    ``rstrip('/o')`` character-set strip, which silently removes
    every trailing ``/`` and ``o`` and breaks on any host whose path
    happens to share those characters.
    """
    parsed = urlparse(public_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_plan_config() -> dict[str, Any]:
    """
    Build the JSON config the suite stores against a plan.

    Mirrors the shape suite plans expect: ``server.discoveryUrl`` plus
    a ``client`` block with our pre-registered credentials. Login
    credentials go under ``resource`` so the suite's browser driver
    can submit AA's standard Django login form.
    """
    host_root = _host_root(PUBLIC_URL)
    return {
        "alias": "conformance",
        "description": "allianceauth-oidc-provider conformance run",
        "server": {
            # OIDC Discovery 1.0 §4: discoveryUrl is the issuer URL
            # plus exactly ``/.well-known/openid-configuration`` — no
            # trailing slash. The suite's CheckDiscEndpointDiscoveryUrl
            # validates this strictly.
            "discoveryUrl": (f"{PUBLIC_URL}/.well-known/openid-configuration"),
        },
        # The basic-cert plan drives two pre-registered clients
        # through some modules. Both must be created on the provider
        # side (see seed.py).
        "client": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        # ``oidcc-server-client-secret-post`` runs
        # ``OIDCCServerTestClientSecretPost.configureClient()`` which
        # copies ``config.client_secret_post`` into ``config.client``
        # before the happy-path starts. The suite assumes "many/most
        # servers restrict each client to using only one auth method"
        # and lets the operator point each variant at a separate
        # pre-registered client; DOT/oauthlib accepts both
        # ``client_secret_basic`` and ``client_secret_post`` on the
        # same client_id, so we mirror the regular block. Without
        # this entry the swap nulls out ``client`` and the module
        # interrupts at GetStaticClientConfiguration.
        "client_secret_post": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        "client2": {
            "client_id": CLIENT2_ID,
            "client_secret": CLIENT2_SECRET,
        },
        "resource": {
            "resourceUrl": f"{PUBLIC_URL}/userinfo/",
        },
        # ``browser`` drives the suite's headless HtmlUnit. The suite
        # selects a TOP-LEVEL entry by matching the ``goToUrl`` URL it
        # tells the browser to visit. Inside the entry, each TASK has
        # its own ``match`` field that fires against the browser's
        # CURRENT URL after navigation.
        #
        # Flow:
        # 1. Suite ``goToUrl(/o/authorize/...)`` — matches the entry
        #    below.
        # 2. AA middleware 302's an unauthenticated user to
        #    ``LOGIN_URL`` (= ``/admin/login/`` in conformance
        #    settings; AA's stock ``/account/login/`` is EVE-SSO-only
        #    with no fillable form).
        # 3. Login task fires against the admin-login URL — fills
        #    ``id_username`` / ``id_password`` and submits. Django
        #    admin's form uses exactly those IDs.
        # 4. On success, admin redirects to the ``next`` URL
        #    (``/o/authorize/...``).
        # 5. If the seeded app has ``skip_authorization=False``, DOT
        #    renders our consent template; the Authorize task clicks
        #    ``name=allow``. Apps seeded with
        #    ``skip_authorization=True`` (the default in
        #    ``seed.py``) skip the consent screen — DOT 302's
        #    directly to the RP callback. Both tasks are
        #    ``optional: true`` so a single configuration handles
        #    both flows.
        # 6. ``[type=submit]`` (CSS selector) matches both
        #    ``<input type="submit">`` (admin login) and
        #    ``<button type="submit">`` (other forms) — the
        #    previous ``button[type=submit]`` selector missed the
        #    admin form's input element.
        "browser": [
            {
                "match": f"{host_root}/o/authorize*",
                "tasks": [
                    {
                        "task": "Login",
                        "match": f"{host_root}/admin/login*",
                        "optional": True,
                        "commands": [
                            ["text", "id", "id_username", USERNAME],
                            ["text", "id", "id_password", PASSWORD],
                            ["click", "css", "[type=submit]"],
                        ],
                    },
                    {
                        "task": "Authorize",
                        "match": f"{host_root}/o/authorize*",
                        "optional": True,
                        "commands": [
                            ["click", "name", "allow"],
                        ],
                    },
                ],
            },
        ],
    }
