"""
Integration tests for the OIDC provider over a real HTTP socket.

These tests complement ``tests/test_conformance.py``: that file drives
the provider through Django's test client, which short-circuits the
WSGI layer. This module boots a ``LiveServerTestCase`` and walks the
OIDC code flow with ``requests`` + ``jwcrypto``, validating the
id_token signature against a JWKS retrieved over the wire.

What the wire-level perspective catches that the test client can't:

- ``iss`` and ``jwks_uri`` are absolute URLs that match the live host,
  so the issuer/JWKS contract used by offline-validating relying
  parties (Grafana, Mosquitto, …) is exercised end-to-end.
- The mock-RP follows the spec the way a real RP does: cookies,
  ``Bearer`` headers, redirects.
- The Bearer-token revocation path travels through real HTTP, not the
  shortcut Django test client.

These tests run sequentially (``LiveServerTestCase`` is incompatible
with ``--parallel=auto``) and are exposed via ``nox -s integration``,
not the default suite.
"""

from __future__ import annotations

import json
from importlib import import_module
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
)
from django.contrib.auth.models import Permission
from django.test import LiveServerTestCase, override_settings
from django.utils import timezone
from jwcrypto import jwk, jwt
from oauth2_provider.settings import oauth2_settings

from allianceauth_oidc.constants import PERM_ACCESS_OIDC_CODENAME

from ._factories import (
    make_alliance,
    make_app,
    make_character,
    make_corp,
    make_user,
)

REDIRECT_URI = "http://localhost/redir/"
HTTP_TIMEOUT = 5
SCOPE_FULL = "openid profile email"


def _oauth2_provider_without_iss() -> dict:
    """
    The default ``test_settingsAA4`` pins ``OIDC_ISS_ENDPOINT`` so that
    Celery-driven back-channel logout dispatches can derive ``iss``
    without a request context. The live-server flow needs the opposite:
    discovery doc URLs MUST be absolute on the dynamically-allocated
    live host, so the ``iss`` override has to be cleared here.
    """
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.pop("OIDC_ISS_ENDPOINT", None)
    return cfg


@override_settings(OAUTH2_PROVIDER=_oauth2_provider_without_iss())
class MockRelyingPartyFlow(LiveServerTestCase):
    """
    End-to-end OIDC code-flow over a real HTTP socket.

    Subclasses ``LiveServerTestCase`` (i.e. ``TransactionTestCase``); the
    DB is flushed between tests, so fixtures are built in ``setUp`` —
    not ``setUpTestData`` — to be reconstructed for each test.

    ``serialized_rollback = True`` makes Django re-load the initial DB
    state (including AA's data-migration ``State`` rows like Member /
    Blue / Guest) after each test. Without it, the state row created by
    AA's RunPython migrations would be flushed and never restored.
    """

    serialized_rollback = True

    def setUp(self) -> None:
        super().setUp()
        # ``oauth2_settings`` caches OAUTH2_PROVIDER at import; the
        # class-level ``override_settings`` only takes effect after a
        # cache reload. Mirror the pattern used by tests in
        # ``tests/test_logout.py``.
        oauth2_settings.reload()
        self.addCleanup(oauth2_settings.reload)
        # Affiliation chain so the EVE claims have something to emit.
        alli = make_alliance("MRP", alliance_id=4001)
        corp = make_corp(
            "MRP", corp_id=4101, name="MockRP-Corp", alliance=alli
        )
        self.character = make_character("MockRP-Char", corp, char_id=4201)
        self.user = make_user(
            "MockRpUser",
            main=self.character,
            email="rp@example.test",
        )
        access_perm = Permission.objects.get_by_natural_key(
            PERM_ACCESS_OIDC_CODENAME,
            "allianceauth_oidc",
            "allianceauthapplication",
        )
        self.user.user_permissions.add(access_perm)
        # ``skip_authorization=True`` lets the authorize GET return the
        # 302 with code directly, sidestepping CSRF on the consent POST
        # — which a real RP exchange does not see anyway.
        self.app, self.client_id, self.client_secret = make_app(
            owner=self.user,
            redirect_uri=REDIRECT_URI,
            skip_authorization=True,
            pkce_required=False,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _logged_in_session(self) -> requests.Session:
        """
        Return a ``requests.Session`` carrying a Django session cookie
        for ``self.user``.

        Bypasses Alliance Auth's login form by writing a Session row
        directly and shipping the cookie. Works because
        ``SESSION_ENGINE = "django.contrib.sessions.backends.db"`` and
        the WSGI server in ``LiveServerTestCase`` reads from the same
        database the test thread wrote to.

        Sets ``user.last_login`` because DOT's id_token builder formats
        it unconditionally — a None value crashes ``dateformat.format``
        and the token endpoint returns 500. ``Client.force_login`` does
        this implicitly via the ``user_logged_in`` signal; cookie-
        injection has to do it explicitly.
        """
        if self.user.last_login is None:
            self.user.last_login = timezone.now()
            self.user.save(update_fields=["last_login"])

        engine = import_module(settings.SESSION_ENGINE)
        store = engine.SessionStore()
        store[SESSION_KEY] = str(self.user.pk)
        store[BACKEND_SESSION_KEY] = (
            "django.contrib.auth.backends.ModelBackend"
        )
        store[HASH_SESSION_KEY] = self.user.get_session_auth_hash()
        store.save()
        rp = requests.Session()
        rp.cookies.set(
            settings.SESSION_COOKIE_NAME,
            store.session_key,
        )
        return rp

    def _discovery(self) -> dict[str, Any]:
        url = urljoin(
            self.live_server_url + "/",
            "o/.well-known/openid-configuration/",
        )
        resp = requests.get(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _fetch_jwks(self, jwks_uri: str) -> jwk.JWKSet:
        resp = requests.get(jwks_uri, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return jwk.JWKSet.from_json(resp.text)

    def _authorize_for_code(
        self,
        rp_session: requests.Session,
        *,
        state: str = "live-state",
        nonce: str = "live-nonce",
        scope: str = SCOPE_FULL,
    ) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "state": state,
            "nonce": nonce,
        }
        doc = self._discovery()
        resp = rp_session.get(
            f"{doc['authorization_endpoint']}?{urlencode(params)}",
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
        )
        self.assertEqual(
            302,
            resp.status_code,
            f"expected redirect with code; got {resp.status_code}",
        )
        location = resp.headers["Location"]
        qs = parse_qs(urlparse(location).query)
        self.assertIn("code", qs, f"no code in {location!r}")
        self.assertEqual([state], qs["state"])
        return qs["code"][0]

    def _exchange_code(
        self,
        code: str,
        *,
        client_secret: str | None = None,
    ) -> requests.Response:
        return requests.post(
            self._discovery()["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": self.client_id,
                "client_secret": client_secret or self.client_secret,
            },
            timeout=HTTP_TIMEOUT,
        )

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_discovery_endpoints_are_absolute_and_on_live_host(
        self,
    ) -> None:
        """
        ``iss`` and every URL in the discovery doc must point at the
        live server's host:port.

        Regression line for hardcoded ``OIDC_ISS_ENDPOINT`` settings or
        URL builders that drop the port — both break offline RPs.
        """
        doc = self._discovery()
        host = self.live_server_url
        self.assertTrue(
            doc["issuer"].startswith(host),
            f"issuer {doc['issuer']!r} not on live host {host!r}",
        )
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ):
            self.assertTrue(
                doc[key].startswith(host),
                f"{key}={doc[key]!r} not absolute on {host!r}",
            )

    def test_full_code_flow_round_trips_id_token_via_real_http(
        self,
    ) -> None:
        """
        End-to-end: login → authorize → token → verify id_token against
        JWKS-over-HTTP → userinfo → revoke → userinfo rejected.

        The id_token signature is verified using the JWKS fetched over
        the wire — proving the ``jwks_uri`` contract is intact.
        """
        rp = self._logged_in_session()
        code = self._authorize_for_code(rp)
        token_resp = self._exchange_code(code)
        self.assertEqual(200, token_resp.status_code, token_resp.text)
        body = token_resp.json()
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)

        doc = self._discovery()
        keyset = self._fetch_jwks(doc["jwks_uri"])
        verified = jwt.JWT(jwt=body["id_token"], key=keyset)
        claims = json.loads(verified.claims)
        self.assertTrue(
            claims["iss"].startswith(self.live_server_url),
            f"iss {claims['iss']!r} must match live host",
        )
        self.assertEqual(self.client_id, claims["aud"])
        self.assertEqual("live-nonce", claims.get("nonce"))

        # Userinfo over real HTTP with Bearer header.
        ui = requests.get(
            doc["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {body['access_token']}"},
            timeout=HTTP_TIMEOUT,
        )
        self.assertEqual(200, ui.status_code, ui.text)
        ui_body = ui.json()
        self.assertEqual(str(self.user.pk), ui_body.get("sub"))
        # Standard OIDC ``name`` carries the main character's name…
        self.assertEqual("MockRP-Char", ui_body.get("name"))
        # …and the EVE-specific id claim is emitted under the default
        # ``eve_`` prefix (regression for the claim-mapping wiring).
        self.assertEqual(
            self.character.character_id,
            ui_body.get("eve_character_id"),
        )

        # Revoke and re-check: userinfo must reject the now-dead token.
        rev = requests.post(
            urljoin(self.live_server_url + "/", "o/revoke_token/"),
            data={
                "token": body["access_token"],
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=HTTP_TIMEOUT,
        )
        self.assertEqual(200, rev.status_code, rev.text)
        post_revoke = requests.get(
            doc["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {body['access_token']}"},
            timeout=HTTP_TIMEOUT,
        )
        self.assertIn(
            post_revoke.status_code,
            (401, 403),
            f"revoked token must not authorize userinfo; "
            f"got {post_revoke.status_code}",
        )

    def test_invalid_client_secret_yields_oauth_error_over_http(
        self,
    ) -> None:
        """
        RFC 6749: a token request with a wrong client_secret must
        return ``invalid_client`` (or ``invalid_grant``) without
        leaking a token.

        The Bearer flow's authentication boundary lives in the WSGI
        layer — the test client cannot tell us whether a real RP would
        be rejected.
        """
        rp = self._logged_in_session()
        code = self._authorize_for_code(rp, state="bad-secret")
        resp = self._exchange_code(
            code,
            client_secret="not-the-secret",  # nosec B106
        )
        self.assertIn(
            resp.status_code,
            (400, 401),
            f"expected 4xx; got {resp.status_code}: {resp.text}",
        )
        body = resp.json()
        self.assertIn(
            body.get("error"),
            {"invalid_client", "invalid_grant"},
        )
        self.assertNotIn("access_token", body)

    def test_anonymous_authorize_redirects_to_login(self) -> None:
        """
        Without a session cookie, ``/o/authorize/`` must NOT issue a
        code — the dispatch-layer policy gate runs over the wire too.

        Catches the regression where the gate is in ``get()``/``post()``
        only; the existing test is for POST bypass via the test client,
        and this is its HTTP-layer mirror.
        """
        anon = requests.Session()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_FULL,
            "state": "anon",
        }
        doc = self._discovery()
        resp = anon.get(
            f"{doc['authorization_endpoint']}?{urlencode(params)}",
            allow_redirects=False,
            timeout=HTTP_TIMEOUT,
        )
        # AA's login_required redirect → 302 to the login page; it
        # must NOT be a redirect back to redirect_uri with a code.
        if resp.status_code == 302:
            location = resp.headers["Location"]
            self.assertNotIn(
                "code=",
                location,
                f"anonymous user got a code in {location!r}",
            )
        else:
            self.assertNotEqual(200, resp.status_code)
