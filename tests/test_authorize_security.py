"""
Tests for /o/authorize/ — the authorization-code grant entry point.

Covers anonymous redirects to the login page, the global OIDC permission gate,
and per-application state/group access policy as evaluated on the authorize
request itself (i.e. before the user reaches the consent screen). Full code-
exchange flows belong in test_token.py.
"""

from ._factories import make_app
from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_OPENID,
    OIDCTestCase,
)


class TestPkceInteractionWithOtherGates(OIDCTestCase):
    """
    Pin the dispatch order between PKCE and the other authorize-gates.

    PKCE is one of several gates around /o/authorize/. These tests
    confirm:

    1. State / group whitelist denial wins over a PKCE check (the
       authorize view runs the policy gate in ``dispatch`` *before*
       DOT inspects the PKCE challenge).
    2. ``active=False`` denial wins over a successful PKCE challenge
       (``is_usable`` runs first; an inactive app cannot issue codes
       even with a perfect PKCE round-trip).
    3. Toggling ``pkce_required`` mid-flow on the admin form does NOT
       affect an already-issued authorization code (the code carries
       its issuance-time PKCE contract through to token-exchange).
    """

    def test_state_group_denial_wins_over_pkce_check(self):
        # App restricted to "Blue" state; user1 is "Member" → denied at
        # the policy stage, not at the PKCE stage.
        creds = make_app(owner=self.user1, pkce_required=True, states=["Blue"])
        self.grant_oidc_access(self.user1)
        response = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="state-vs-pkce",
            extra={"client_id": creds.client_id},
        )
        # ``assertDeniedApp`` checks the rendered denial page (200 with
        # the app name), not a PKCE-related error.
        self.assertDeniedApp(response, self.user1, creds.app)

    def test_active_false_wins_over_pkce_required(self):
        from oauth2_provider.models import get_grant_model

        creds = make_app(owner=self.user1, pkce_required=True, active=False)
        self.grant_oidc_access(self.user1)
        _, challenge = self.make_pkce_pair()
        # Send a perfectly valid PKCE challenge — the active=False gate
        # must still reject the request.
        response = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="active-vs-pkce",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        # ``is_usable=False`` short-circuits before any code is issued.
        # DOT may render the consent page with an error, redirect with
        # an error, or 400 — assert "no code anywhere" both in the
        # response and in the database. The DB check is the strong
        # invariant: a Grant row would mean a usable code reached the
        # storage layer regardless of how the response was rendered.
        body = response.content.decode("utf-8", errors="ignore") + str(
            response.headers
        )
        self.assertNotIn("code=", body)
        Grant = get_grant_model()
        self.assertFalse(
            Grant.objects.filter(application=creds.app).exists(),
            "no Grant row should be persisted for an inactive app",
        )

    def test_admin_toggle_does_not_affect_in_flight_code(self):
        import json
        from urllib.parse import parse_qs, urlparse

        creds = make_app(
            owner=self.user1,
            pkce_required=True,
            skip_authorization=True,
        )
        self.grant_oidc_access(self.user1)

        verifier, challenge = self.make_pkce_pair()

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="race-issue",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(302, resp.status_code)
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]

        # Operator flips the flag to False mid-flight (e.g. via admin).
        # The previously-issued code retains its strict-PKCE contract.
        creds.app.refresh_from_db()
        creds.app.pkce_required = False
        creds.app.save()

        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn("access_token", body)


class TestStateEchoOnError(OIDCTestCase):
    """
    OIDC Core 1.0 §3.1.2.6 / RFC 6749 §4.1.2.1: when /authorize/
    fails after the AS has decided the redirect_uri is registered,
    the error MUST be returned to the RP via redirect with the
    ``state`` parameter echoed back. Omitting state breaks the RP's
    CSRF defence — a man-in-the-middle can swap the error response
    for an attacker-chosen authorization code if the RP cannot
    distinguish their own state.

    The success-path state echo and the ``prompt=none`` /
    ``login_required`` cases are pinned by the prompt-* tests above;
    this class closes the same contract on the OAuth-protocol error
    branches (consent denial, malformed scope, malformed
    response_type) which the conformance suite covers indirectly via
    HtmlUnit and stalls upstream.
    """

    def _force_login_user1(self) -> None:
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)

    def test_state_echoed_on_user_consent_denial(self) -> None:
        """
        Consent denial: POST /authorize/ with ``allow`` present but
        falsy (Django BooleanField cleans an empty string to False).
        DOT translates that into an ``access_denied`` error redirect.

        NB: the project's :meth:`AuthAuthorizationView._promote_post_body_to_query`
        treats *absence* of ``allow`` as the cross-origin initial POST
        (OIDC §3.1.2.1) and promotes the body to a GET query rather
        than a denial. Denial therefore requires ``allow`` to be
        present with a falsy value.
        """
        self._force_login_user1()
        response = self.client.post(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "deny-state-echo",
                "allow": "",  # present but falsy → user denied
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertEqual(["access_denied"], qs.get("error"))
        self.assertEqual(["deny-state-echo"], qs.get("state"))
        self.assertNotIn("code", qs)

    def test_state_echoed_on_unsupported_response_type(self) -> None:
        """
        ``response_type=unknown`` is a protocol-level error.

        The AS must redirect with ``error=unsupported_response_type``
        and echo state. DOT also accepts ``invalid_request`` here;
        spec-compliance allows either.
        """
        self._force_login_user1()
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "wibble",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "bad-rt-state",
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertIn(
            qs.get("error", [None])[0],
            ("unsupported_response_type", "invalid_request"),
        )
        self.assertEqual(["bad-rt-state"], qs.get("state"))
        self.assertNotIn("code", qs)

    def test_state_echoed_on_invalid_scope(self) -> None:
        """
        Unknown scope name → ``error=invalid_scope`` on the redirect
        (RFC 6749 §4.1.2.1). State must still ride along.
        """
        self._force_login_user1()
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid bogus-scope-x",
                "state": "bad-scope-state",
            },
        )
        loc, _, qs = self.parse_redirect(response, (302,))
        self.assertTrue(loc.startswith(REDIRECT_URI))
        self.assertEqual(["invalid_scope"], qs.get("error"))
        self.assertEqual(["bad-scope-state"], qs.get("state"))
        self.assertNotIn("code", qs)

    def test_state_absent_when_request_omitted_it(self) -> None:
        """
        Symmetric: if the original request had no ``state``, the AS
        must NOT inject an empty ``state=`` into the error redirect
        — that would corrupt RP-side parsing. Omit state entirely
        rather than echo an empty string.
        """
        self._force_login_user1()
        response = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid not-a-scope",
                # Deliberately no ``state``.
            },
        )
        _, _, qs = self.parse_redirect(response, (302,))
        self.assertIn("error", qs)
        self.assertNotIn(
            "state",
            qs,
            "state MUST NOT be injected when the request lacked it",
        )


class TestRequestObjectAndUriHandling(OIDCTestCase):
    """
    OIDC Core 1.0 §6 / RFC 9101 (JAR) — the ``request`` and
    ``request_uri`` parameters carry a signed JWT whose claims
    override the corresponding query-string parameters.

    The project does NOT implement JAR. The discovery document does
    NOT set ``request_parameter_supported=true`` (per §4 the value
    defaults to ``false``), and the provider does NOT fetch the URL
    referenced by ``request_uri``. Both contracts are security-
    critical:

    1. Silent ``request=`` parsing would let a forged JWT override
       ``redirect_uri`` / ``client_id`` from the query — classic
       parameter-confusion attack.
    2. Fetching a URL from ``request_uri`` is SSRF: attacker-supplied
       URL → AS makes an outbound HTTP request, possibly to internal
       services (RFC 6819 §5.4.1).

    Tests pin the safe behaviour: parameters are ignored, the flow
    uses the query-string values, no outbound fetch happens, no 5xx.
    Replaces ``oidcc-ensure-request-object-with-redirect-uri`` and
    ``oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported``
    from the conformance suite (both fail upstream).
    """

    def test_request_param_does_not_override_query_redirect_uri(self) -> None:
        """
        Send a forged unsigned JWT-shaped payload in ``request=`` that
        claims a different ``redirect_uri``. The AS must ignore it and
        either use the query-string values (succeed) or reject with an
        OAuth error redirect to the *query* ``redirect_uri``, not the
        forged one. Either is spec-compliant; a forged-URI redirect or
        5xx would be the regression.
        """
        from base64 import urlsafe_b64encode

        def _b64(s: bytes) -> str:
            return urlsafe_b64encode(s).rstrip(b"=").decode("ascii")

        forged_header = _b64(b'{"alg":"none","typ":"JWT"}')
        forged_payload = _b64(
            b'{"redirect_uri":"http://evil.example/cb","client_id":"forged"}'
        )
        forged_jwt = f"{forged_header}.{forged_payload}."

        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "request-object-ignored",
                "request": forged_jwt,
            },
        )
        self.assertLess(
            resp.status_code,
            500,
            f"request= must NOT 5xx; got {resp.status_code}",
        )
        # If the AS emitted a redirect, it must point at the registered
        # redirect_uri (taken from query) — NOT the forged URI from the
        # JWT.
        location = resp.headers.get("Location", "")
        self.assertNotIn(
            "evil.example",
            location,
            "request= JWT MUST NOT override redirect_uri — query "
            f"redirect_uri wins; got Location={location!r}",
        )

    def test_request_uri_param_does_not_trigger_fetch_or_5xx(self) -> None:
        """
        ``request_uri=http://attacker.invalid/`` — the AS must not
        make an outbound fetch (no test runs DNS so an attempted
        fetch would raise and surface as 5xx) and must not redirect
        to the attacker URL.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "request-uri-ssrf",
                "request_uri": "http://attacker.invalid/forged.jwt",
            },
        )
        self.assertLess(
            resp.status_code,
            500,
            "request_uri= must NOT trigger an outbound fetch / 5xx; "
            f"got {resp.status_code}",
        )
        self.assertNotIn(
            "attacker.invalid",
            resp.headers.get("Location", ""),
            "AS must never redirect to a request_uri-supplied host",
        )

    def test_discovery_does_not_falsely_advertise_request_parameter_support(
        self,
    ) -> None:
        """
        Discovery: if ``request_parameter_supported`` is present it
        must be ``false`` (or absent — defaults to ``false`` per §4).
        Same contract for ``request_uri_parameter_supported``: per §4
        the default is ``true``, so if absent we are technically
        claiming support; the test asserts the field is either absent
        or explicitly ``false`` — preventing an accidental ``true``
        from leaking into the discovery doc.
        """
        import json

        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))
        self.assertIsNot(
            doc.get("request_parameter_supported"),
            True,
            "request_parameter_supported MUST NOT be advertised as "
            "true unless JAR is actually implemented",
        )
        # ``request_uri_parameter_supported`` defaults to ``true`` per
        # §4 if absent. The contract here is "do not flip to true
        # without an actual implementation"; absent is acceptable.
        self.assertIsNot(
            doc.get("request_uri_parameter_supported"),
            True,
            "request_uri_parameter_supported MUST NOT be explicitly "
            "advertised as true unless request_uri fetch is "
            "implemented",
        )


class TestAuthorizeInputBounds(OIDCTestCase):
    """
    DoS-resistance on /o/authorize/.

    Extremely long or pathological inputs MUST NOT 5xx. Django
    enforces ``DATA_UPLOAD_MAX_MEMORY_SIZE`` on the request body
    (default 2.5MB) and ``DATA_UPLOAD_MAX_NUMBER_FIELDS`` on form-
    encoded POSTs, but each endpoint can still parse parameters in
    ways that escalate memory (regex backtracking, JSON parsing of
    attacker-controlled blobs). The contract pinned: the endpoint
    returns a clean 4xx for malformed input, never 5xx.
    """

    _LARGE = 200_000
    # 200KB — enough to surface regex / JSON memory blowups; well
    # under DATA_UPLOAD_MAX_MEMORY_SIZE so Django itself does not
    # pre-empt the test by rejecting the body.

    def _authorize(self, **extras):
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": "dos-bounds-default",
        }
        data.update(extras)
        return self.client.get("/o/authorize/", data=data)

    def test_extremely_long_state_does_not_5xx(self) -> None:
        """``state=<200KB>`` — must be tolerated without 5xx."""
        resp = self._authorize(state="A" * self._LARGE)
        self.assertLess(resp.status_code, 500)

    def test_extremely_long_scope_does_not_5xx(self) -> None:
        """``scope=openid <200KB of space-delimited tokens>``."""
        long_scope = "openid " + ("dosdosdos " * (self._LARGE // 10))
        resp = self._authorize(scope=long_scope[: self._LARGE])
        self.assertLess(resp.status_code, 500)

    def test_extremely_long_client_id_does_not_5xx(self) -> None:
        """``client_id=<200KB>`` — unregistered, must 4xx without 5xx."""
        resp = self._authorize(client_id="X" * self._LARGE)
        self.assertLess(resp.status_code, 500)

    def test_extremely_long_redirect_uri_does_not_5xx(self) -> None:
        """``redirect_uri=https://x/<200KB>`` — must 4xx without 5xx."""
        long_uri = "https://rp.example/" + ("a" * self._LARGE)
        resp = self._authorize(redirect_uri=long_uri)
        self.assertLess(resp.status_code, 500)

    def test_extremely_long_claims_json_does_not_5xx(self) -> None:
        """
        ``claims=<200KB of wide JSON>``.

        The selector path in ``TestRequestedIdTokenClaimsSelector``
        defends itself with ``try/except``; this test confirms the
        HTTP layer survives the same pathological input.
        """
        keys = ",".join(f'"k{i}":null' for i in range(20_000))
        claims_blob = '{"id_token":{' + keys + "}}"
        resp = self._authorize(claims=claims_blob)
        self.assertLess(resp.status_code, 500)

    def test_repeated_response_type_param_does_not_5xx(self) -> None:
        """
        HTTP parameter pollution: ``response_type=code&response_type=token``.

        Django's ``QueryDict`` keeps the LAST value by default for
        ``request.GET[k]`` and exposes the full list via ``getlist``.
        The AS must use one consistently and MUST NOT 5xx on the
        duplicate.
        """
        from urllib.parse import urlencode

        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        qs = urlencode(
            [
                ("response_type", "code"),
                ("response_type", "token"),
                ("client_id", self.oauth_id),
                ("redirect_uri", REDIRECT_URI),
                ("scope", SCOPE_OPENID),
                ("state", "dup-rt"),
            ]
        )
        resp = self.client.get(f"/o/authorize/?{qs}")
        self.assertLess(resp.status_code, 500)
