"""
Tests for /o/logout/ — RP-initiated logout and post_logout_redirect_uri
allowlist enforcement.
"""

import hashlib
import hmac

from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings

from ._jwt_helpers import _b64url_encode_nopad, forge_unsigned_jwt
from ._oidc_testcase import REDIRECT_STATUSES, SCOPE_PROFILE, OIDCTestCase


def _forged_hs256_id_token_hint() -> str:
    """
    Build an HS256 JWT signed with an attacker-chosen secret.

    The AS does not know the secret, so signature verification
    must fail. The compact form follows ``header.payload.sig``
    base64url-no-pad encoding; same payload shape as the
    ``alg=none`` companion so the two cases differ only in the
    alg header and the signature segment.
    """
    header_seg = _b64url_encode_nopad(
        b'{"alg":"HS256","typ":"JWT","kid":"forged"}'
    )
    payload_seg = _b64url_encode_nopad(
        b'{"sub":"1","aud":"victim","iss":"https://evil.example/"}'
    )
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = hmac.new(b"attacker-key", signing_input, hashlib.sha256).digest()
    return f"{header_seg}.{payload_seg}.{_b64url_encode_nopad(sig)}"


def _enable_rp_logout():
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.setdefault("OIDC_ENABLED", True)
    cfg["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
    return cfg


class TestRPInitiatedLogout(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Every test in this class flips OIDC_RP_INITIATED_LOGOUT_ENABLED via
        # override_settings + oauth2_settings.reload(); register the cleanup
        # once so individual tests don't repeat try/finally boilerplate.
        self.addCleanup(oauth2_settings.reload)

    def _issue_id_token(self) -> str:
        """
        Run the auth-code flow to get an id_token for use as
        id_token_hint.
        """
        self.grant_oidc_access(self.user1)
        return self.run_code_flow(
            self.user1, scope=SCOPE_PROFILE, state="logout-issue"
        )["id_token"]

    def test_logout_allows_only_configured_post_logout_redirect_uri(self):
        """
        /o/logout/ must respect the per-app post_logout_redirect_uris
        allowlist.

        DOT versions differ on the exact status (302/400), but must never
        redirect to an unlisted URI.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            denied = "http://localhost/post-logout-bad/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            # 1) allowed URI -> redirects there (or at least no 500).
            resp_ok = self.client.get(
                "/o/logout/", data={"post_logout_redirect_uri": allowed}
            )
            self.assertNotEqual(500, resp_ok.status_code)
            if resp_ok.status_code in REDIRECT_STATUSES:
                self.assertTrue(
                    resp_ok.headers.get("Location", "").startswith(allowed)
                )

            # 2) denied URI -> never redirects there.
            resp_bad = self.client.get(
                "/o/logout/", data={"post_logout_redirect_uri": denied}
            )
            self.assertNotEqual(500, resp_bad.status_code)
            if resp_bad.status_code in REDIRECT_STATUSES:
                self.assertFalse(
                    resp_bad.headers.get("Location", "").startswith(denied)
                )
            else:
                # Many DOT versions return 400 on invalid redirect uri.
                self.assertIn(resp_bad.status_code, (200, 400))

    def test_rp_logout_with_valid_id_token_hint_redirects_to_allowed_uri(self):
        """
        With a valid id_token_hint and an allowed post_logout_redirect_uri,
        /o/logout/ redirects to the configured URI (302/303).

        Some DOT
        versions render a confirmation template (200) — the invariant we
        enforce: never error 500 and never redirect anywhere except the
        allowed URI.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            id_token = self._issue_id_token()

            resp = self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": allowed,
                },
            )
            self.assertNotEqual(500, resp.status_code)
            if resp.status_code in REDIRECT_STATUSES:
                loc = resp.headers.get("Location", "")
                self.assertTrue(
                    loc.startswith(allowed),
                    f"Location {loc!r} does not start with {allowed!r}",
                )

    def test_rp_logout_with_id_token_hint_for_unlisted_redirect_uri(self):
        """
        Even with a valid id_token_hint, an unlisted
        post_logout_redirect_uri must not redirect there — the allowlist is the
        security boundary, not the hint.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            allowed = "http://localhost/post-logout-ok/"
            denied = "http://localhost/post-logout-bad/"
            self.oauth_app.post_logout_redirect_uris = allowed
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()

            id_token = self._issue_id_token()

            resp = self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": denied,
                },
            )
            self.assertNotEqual(500, resp.status_code)
            if resp.status_code in REDIRECT_STATUSES:
                loc = resp.headers.get("Location", "")
                self.assertFalse(
                    loc.startswith(denied),
                    f"Location leaked to denied URI {loc!r}",
                )


class TestRPLogoutIdTokenHintValidation(OIDCTestCase):
    """
    /o/logout/ ``id_token_hint`` validation contracts.

    OIDC RP-Initiated Logout 1.0 §3: ``id_token_hint`` is an OPTIONAL
    parameter; if present it identifies the End-User. The spec
    explicitly permits *expired* hints (the user is already logged in;
    the hint just disambiguates ``sub``).

    Three negative paths that MUST NOT bypass the post-logout
    redirect_uri allowlist:

    1. Unsigned hint (``alg=none``) — classic JWT-confusion vector.
    2. Forged signature (HS256 with a key the AS does not know).
    3. Hint issued for a different ``aud`` / different client.

    For each, the contract pinned is "no 5xx, never redirect to a URI
    outside the per-app allowlist". A hint that fails validation may
    be ignored (DOT default — render the confirm template) or rejected
    outright; both are spec-compliant.
    """

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(oauth2_settings.reload)

    def _logout_with_hint(self, hint: str, *, post_logout: str):
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            self.oauth_app.post_logout_redirect_uris = post_logout
            self.oauth_app.save()
            self.oauth_app.refresh_from_db()
            return self.client.get(
                "/o/logout/",
                data={
                    "id_token_hint": hint,
                    "post_logout_redirect_uri": post_logout,
                },
            )

    def test_id_token_hint_forgery_sweep_no_5xx_or_open_redirect(
        self,
    ) -> None:
        """
        Sweep of forged/garbage id_token_hint shapes.

        The AS does not know the attacker's signing key (HS256)
        and does not accept ``alg=none``. Each row's MUST-NOT
        shape is identical: no 5xx, no attacker-controlled
        redirect outside the configured allowlist. The AS may
        ignore (200 confirm page) or surface a controlled
        error (400); both are acceptable.

        * ``alg_none`` — unsigned JWT (``header.payload.``).
        * ``garbage`` — hint that does not look like a JWT at
          all; DOT must surface a controlled error, never 500.
        * ``forged_hs256`` — HS256-signed JWT with an
          attacker-chosen secret; signature verification fails.
        """
        allowed = "http://localhost/post-logout-ok/"
        cases: tuple[tuple[str, str], ...] = (
            (
                "alg_none",
                forge_unsigned_jwt(
                    {
                        "sub": "1",
                        "aud": "victim",
                        "iss": "https://evil.example/",
                    }
                ),
            ),
            ("garbage", "not-a-jwt"),
            ("forged_hs256", _forged_hs256_id_token_hint()),
        )
        for label, hint in cases:
            with self.subTest(hint=label):
                resp = self._logout_with_hint(hint, post_logout=allowed)
                self.assertNotEqual(500, resp.status_code)
                if resp.status_code in REDIRECT_STATUSES:
                    loc = resp.headers.get("Location", "")
                    self.assertTrue(
                        loc.startswith((allowed, "/")),
                        f"{label} hint must not redirect outside "
                        f"allowlist; got {loc!r}",
                    )


class TestLogoutCSRF(OIDCTestCase):
    """
    OIDC RP-Initiated Logout 1.0 §2 — GET on /o/logout/ renders a
    confirmation UI (no CSRF token needed; it's a navigation). POST
    that submits the form MUST be CSRF-protected like any other
    state-changing Django POST.

    Without CSRF protection on POST, an attacker can craft a form
    on their site that auto-submits to ``/o/logout/`` and logs the
    victim out — annoying at minimum, and a phishing pivot
    (post-logout redirect to attacker page that mimics the AS login
    screen and harvests credentials).
    """

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(oauth2_settings.reload)

    def test_post_logout_without_csrf_token_rejected(self) -> None:
        """
        Enforce CSRF: POST to /logout/ without a CSRF token MUST be
        rejected (403). The Django test client defaults to
        ``enforce_csrf_checks=False`` for ergonomics, which silently
        hides CSRF regressions; this test opts in explicitly.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            client = self.client_class(enforce_csrf_checks=True)
            self.grant_oidc_access(self.user1)
            client.force_login(self.user1)
            resp = client.post(
                "/o/logout/",
                data={"allow": True},
            )
            self.assertEqual(
                403,
                resp.status_code,
                "POST /o/logout/ without CSRF token MUST yield 403; "
                f"got {resp.status_code}",
            )

    def test_get_logout_renders_confirmation_without_csrf_token(
        self,
    ) -> None:
        """
        GET is navigation, not a state change — CSRF irrelevant. The
        confirmation template should render without 403.
        """
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            client = self.client_class(enforce_csrf_checks=True)
            self.grant_oidc_access(self.user1)
            client.force_login(self.user1)
            resp = client.get("/o/logout/")
            self.assertNotEqual(403, resp.status_code)


class TestLogoutEndpointDefaultOn(OIDCTestCase):
    """
    AppConfig-integration smoke for /o/logout/.

    Every other test in this module flips
    ``OIDC_RP_INITIATED_LOGOUT_ENABLED=True`` explicitly via
    ``override_settings(OAUTH2_PROVIDER=_enable_rp_logout())`` because
    those cases were written before
    :func:`allianceauth_oidc.apps._apply_default_oauth2_provider_settings`
    made the flag default-on. The override path masks an entire
    class of regression: if the AppConfig helper stops firing on
    app load, DOT's stock ``False`` default would gate ``/o/logout/``
    behind a 404, but every override-using test would still pass
    because they overwrite the flag inside the test body.

    This class deliberately uses NO override. A non-404 response
    means both that the URL pattern is mounted in
    ``allianceauth_oidc/urls.py`` AND that DOT's
    ``RPInitiatedLogoutView`` sees ``OIDC_RP_INITIATED_LOGOUT_ENABLED``
    as truthy — i.e. the AppConfig path is intact end-to-end.
    """

    def test_logout_endpoint_enabled_by_appconfig_default(self) -> None:
        """
        Anonymous GET against ``/o/logout/`` returns a non-404 status.

        Status-code semantics in DOT 3.x:

        * ``302`` to ``LOGIN_URL`` — anonymous user, the
          ``login_required`` decorator on
          ``RPInitiatedLogoutView.dispatch`` redirects. This is the
          expected default branch.
        * ``200`` — would indicate DOT changed the auth-required
          posture; still a "route works" signal, so accepted here.
        * ``404`` — route either unmounted or gated off by an
          ``OIDC_RP_INITIATED_LOGOUT_ENABLED=False`` reading. This is
          the regression mode this test exists to catch.

        ``assertNotEqual(404, ...)`` rather than
        ``assertIn({200, 302, 303}, ...)`` because DOT's exact
        anonymous response shape is operator-affecting but not
        contract-affecting: a future DOT release could legitimately
        return 401 (RFC 6750) without breaking the AppConfig
        contract. The 404 boundary is the one that matters.
        """
        resp = self.client.get("/o/logout/")
        self.assertNotEqual(
            404,
            resp.status_code,
            "/o/logout/ returned 404 without any explicit "
            "OIDC_RP_INITIATED_LOGOUT_ENABLED override. The AppConfig "
            "default-on helper (allianceauth_oidc.apps._apply_default_"
            "oauth2_provider_settings) likely stopped running on app "
            "load — either AllianceAuthOIDC.ready was modified or DOT "
            "changed how OAuth2ProviderSettings caches the value.",
        )
