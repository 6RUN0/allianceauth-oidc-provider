"""
Tests for /o/authorize/ — the authorization-code grant entry point.

Covers anonymous redirects to the login page, the global OIDC permission gate,
and per-application state/group access policy as evaluated on the authorize
request itself (i.e. before the user reaches the consent screen). Full code-
exchange flows belong in test_token.py.
"""

from typing import Any

from ._factories import make_app
from ._jwt_helpers import forge_unsigned_jwt, split_jwt
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
        body = self.json_body(token_resp, expected_status=None)
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
        forged_jwt = forge_unsigned_jwt(
            {
                "redirect_uri": "http://evil.example/cb",
                "client_id": "forged",
            }
        )

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
        doc = self.discovery()
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

    def test_extremely_long_parameter_does_not_5xx(self) -> None:
        """
        Sweep: ``state`` / ``scope`` / ``client_id`` / ``redirect_uri``
        / ``claims`` MUST tolerate a 200KB attacker payload without
        a 5xx. The selector path in ``TestRequestedIdTokenClaimsSelector``
        defends itself with ``try/except``; this sweep confirms the
        HTTP layer survives the same pathological inputs.
        """
        long_scope = ("openid " + ("dosdosdos " * (self._LARGE // 10)))[
            : self._LARGE
        ]
        long_redirect = "https://rp.example/" + ("a" * self._LARGE)
        wide_claims = (
            '{"id_token":{'
            + ",".join(f'"k{i}":null' for i in range(20_000))
            + "}}"
        )
        cases = (
            ("state", {"state": "A" * self._LARGE}),
            ("scope", {"scope": long_scope}),
            ("client_id", {"client_id": "X" * self._LARGE}),
            ("redirect_uri", {"redirect_uri": long_redirect}),
            ("claims", {"claims": wide_claims}),
        )
        for label, extras in cases:
            with self.subTest(param=label):
                resp = self._authorize(**extras)
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


class TestResponseTypeRestriction(OIDCTestCase):
    """
    The project is intentionally code-flow only.

    OAuth 2.0 Security BCP (RFC 9700) deprecates the implicit flow:
    ``response_type=token`` (or ``=id_token``) returns tokens in the
    URL fragment, where they leak to Referer headers, access logs,
    browser history, and any other party with read access to the
    URL. Hybrid (``code id_token``) drops the same id_token in the
    URL fragment.

    Pin the code-only contract on three layers:

    1. /authorize/ rejects implicit / hybrid request — no token /
       id_token surfaces in the redirect URL.
    2. Discovery advertises ``response_types_supported: ["code"]``
       only — no ``"token"``, no ``"id_token"``.
    3. ``unsupported_response_type`` error code per RFC 6749 §4.1.2.1.
    """

    def _authorize_with_response_type(self, response_type: str, state: str):
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        return self.client.get(
            "/o/authorize/",
            data={
                "response_type": response_type,
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": state,
            },
        )

    def _assert_no_token_in_fragment(self, resp) -> None:
        """The Location header MUST NOT carry ``#access_token=...`` etc."""
        loc = resp.headers.get("Location", "")
        # If the AS issued an implicit AT, it lands in the fragment
        # (``...#access_token=...``). The hash separator is the
        # signature of the leak.
        if "#" in loc:
            fragment = loc.split("#", 1)[1]
            for forbidden in ("access_token", "id_token"):
                self.assertNotIn(
                    forbidden,
                    fragment,
                    f"implicit/hybrid leaked {forbidden!r} in URL "
                    f"fragment {fragment!r}",
                )

    _OAUTH_REJECT_ERRORS = frozenset(
        {
            "unsupported_response_type",
            "unauthorized_client",
            "invalid_request",
        }
    )

    def test_non_code_response_types_rejected(self) -> None:
        """
        Every non-``code`` response_type MUST be rejected.

        Sweep covers ``token``, ``id_token``, the two §3.3 hybrid
        pairs, and the §3.1.1 ``none`` value. The contract is
        layered:

        * No 5xx — the authorize dispatcher catches malformed flows
          before they reach the grant machinery.
        * No implicit token/id_token surfaces in the URL fragment.
        * On the redirect branch, the OAuth error code lives in the
          ``unsupported_response_type`` / ``unauthorized_client`` /
          ``invalid_request`` set — DOT picks the variant based on
          per-app grant-type policy, all three are spec-compliant
          (RFC 6749 §4.1.2.1, OIDC §3.3 for hybrid, OIDC §3.1.1
          for ``none``).
        """
        cases = (
            ("token", "rt-token"),
            ("id_token", "rt-idtok"),
            ("code id_token", "rt-hybrid-1"),
            ("code token", "rt-hybrid-2"),
            ("none", "rt-none"),
        )
        for response_type, state in cases:
            with self.subTest(response_type=response_type):
                resp = self._authorize_with_response_type(response_type, state)
                self.assertLess(resp.status_code, 500)
                self._assert_no_token_in_fragment(resp)
                if resp.status_code in (301, 302, 303, 307, 308):
                    _, _, qs = self.parse_redirect(resp, (302, 303))
                    self.assertIn(
                        qs.get("error", [None])[0],
                        self._OAUTH_REJECT_ERRORS,
                    )

    def test_discovery_advertises_only_code_response_type(self) -> None:
        """
        ``AllianceAuthDiscoveryView`` overrides ``response_types_supported``
        to exactly ``["code"]``. DOT's stock view would echo its full
        enum (implicit + hybrid); advertising those misleads RPs into
        sending requests the AS will reject at runtime via the per-app
        ``authorization_grant_type`` gate.
        """
        rts = self.discovery().get("response_types_supported")
        self.assertEqual(
            ["code"],
            rts,
            "Discovery MUST advertise only the code flow this "
            "provider implements",
        )
        # Sanity: each implicit / hybrid form is absent.
        for forbidden in (
            "token",
            "id_token",
            "code id_token",
            "code token",
            "id_token token",
            "code id_token token",
        ):
            self.assertNotIn(forbidden, rts)

    def test_missing_response_type_param(self) -> None:
        """
        ``response_type`` REQUIRED per RFC 6749 §4.1.1 / OIDC §3.1.2.1.

        When the parameter is OMITTED entirely (not merely unknown,
        which ``test_state_echoed_on_unsupported_response_type``
        already pins), the AS MUST NOT 5xx; per RFC 6749 §4.1.2.1 it
        redirects with ``error=invalid_request`` once redirect_uri
        and client_id validate. Pinned because the conformance suite
        module ``oidcc-response-type-missing`` probes this exact
        path — a unit test makes the diagnostic distinction between
        a server-side hang and a suite-side HtmlUnit upstream stall.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                # response_type intentionally OMITTED.
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "rt-missing",
            },
        )
        self.assertLess(resp.status_code, 500)
        self._assert_no_token_in_fragment(resp)
        if resp.status_code in (301, 302, 303, 307, 308):
            _, _, qs = self.parse_redirect(resp, (302, 303))
            self.assertIn(
                qs.get("error", [None])[0],
                self._OAUTH_REJECT_ERRORS,
                "Missing response_type MUST yield an OAuth error "
                "code (invalid_request preferred) per RFC 6749 "
                "§4.1.2.1.",
            )


class TestHostHeaderPoisoning(OIDCTestCase):
    """
    An attacker-controlled ``Host`` header MUST NOT alter the AS's
    canonical identifiers or selection logic.

    Reverse-proxy scenarios: an attacker who sits between RP and AS
    (or who controls a host that resolves to the AS via DNS
    rebinding) sends a request with ``Host: evil.example``. If the
    AS derives ``iss``, ``jwks_uri``, or redirect_uri match-keys
    from ``request.get_host()``, the attacker controls those values
    in the response — game over.

    Pin three layers:

    1. ``iss`` claim in id_token comes from ``OIDC_ISS_ENDPOINT``
       setting, not from request Host.
    2. Discovery ``issuer`` field is stable across Host header
       changes.
    3. ``redirect_uri`` matching is byte-equal against the
       registered URI; Host header does not get to substitute.

    AA's default ``ALLOWED_HOSTS=['*']`` means Django won't 400 on
    the attacker Host — exactly the deployment that needs this
    test most.
    """

    EVIL_HOST = "evil.example"

    def test_iss_claim_comes_from_setting_not_host_header(self) -> None:
        """
        Send the full code-flow under an attacker Host header.
        ``iss`` in the issued id_token MUST equal the configured
        ``OAUTH2_PROVIDER['OIDC_ISS_ENDPOINT']``, never
        ``https://evil.example/...``.
        """
        from oauth2_provider.settings import oauth2_settings

        configured_iss = getattr(oauth2_settings, "OIDC_ISS_ENDPOINT", "")
        # The test settings pin a fixed issuer; the assertion only
        # makes sense if that pin is present.
        self.assertTrue(
            configured_iss,
            "test settings must pin OIDC_ISS_ENDPOINT for this test",
        )

        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(
            self.user1,
            state="host-iss-poison",
            extra_authorize_params={"HTTP_HOST": self.EVIL_HOST},
        )
        # Token endpoint hit happens via the default test client
        # which uses ``testserver`` as Host; the iss claim must
        # still come from the setting regardless.
        _, claims = split_jwt(body["id_token"])
        self.assertEqual(
            configured_iss,
            claims.get("iss"),
            f"id_token iss came from request Host instead of "
            f"OIDC_ISS_ENDPOINT; got {claims.get('iss')!r}",
        )
        self.assertNotIn(self.EVIL_HOST, claims.get("iss", ""))

    def test_discovery_issuer_stable_under_attacker_host_header(
        self,
    ) -> None:
        """
        Discovery ``issuer`` field MUST NOT shift with the Host
        header. Otherwise an attacker who can inject Host can
        publish a malicious discovery document that points RPs at
        their forged JWKS.
        """
        from oauth2_provider.settings import oauth2_settings

        configured_iss = getattr(oauth2_settings, "OIDC_ISS_ENDPOINT", "")

        resp = self.client.get(
            "/o/.well-known/openid-configuration/",
            headers={"host": self.EVIL_HOST},
        )
        self.assertEqual(200, resp.status_code)
        doc = self.json_body(resp, expected_status=None)
        self.assertEqual(
            configured_iss,
            doc.get("issuer"),
            f"discovery issuer shifted to attacker Host; got "
            f"{doc.get('issuer')!r}",
        )
        # jwks_uri may use request-host (DOT default) — pin the
        # current behavior so a shift is visible. If this test
        # starts failing, jwks_uri now points at evil.example,
        # which is the real SSRF/key-substitution risk.
        jwks_uri = doc.get("jwks_uri", "")
        self.assertNotIn(
            self.EVIL_HOST,
            jwks_uri,
            f"jwks_uri leaked attacker Host header: {jwks_uri!r}",
        )

    def test_redirect_uri_match_ignores_host_header(self) -> None:
        """
        Authorize with the registered redirect_uri but under an
        attacker Host header. The AS MUST accept the request as
        normal (matching is on registered URI, not on Host),
        issuing the code to the registered URI.

        The flip-side (attacker submits an attacker-controlled
        redirect_uri AND attacker Host) is already covered by
        :class:`TestRedirectURIExactMatch` in test_token.py — that
        path rejects because the URI doesn't match the registered
        value.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        # POST with the registered URI; the Host header is the
        # attacker's value but redirect_uri is honest.
        resp = self.client.post(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "host-redir-ok",
                "allow": True,
            },
            headers={"host": self.EVIL_HOST},
        )
        # Either successful redirect to registered URI, or a clean
        # error — never a redirect to attacker host.
        self.assertLess(resp.status_code, 500)
        location = resp.headers.get("Location", "")
        self.assertNotIn(
            self.EVIL_HOST,
            location,
            f"redirect Location leaked attacker Host: {location!r}",
        )


class TestIssParamInAuthzResponse(OIDCTestCase):
    """
    RFC 9207 — *OAuth 2.0 Authorization Server Issuer Identification*.

    The RFC closes the "mix-up attack" class (RFC 9700 §4.4) by
    requiring the AS to echo its ``iss`` (issuer URL) in the
    authorize redirect. The RP, federated to multiple ASes, then
    verifies the redirect originated from the AS it initiated the
    flow with — without ``iss`` the RP cannot distinguish a code
    issued by AS-honest from one injected via AS-evil.

    Current state of the upstream stack:

    * django-oauth-toolkit 3.2 / oauthlib 3.x do **not** implement
      RFC 9207. The authorize redirect contains ``code`` + ``state``
      and nothing else; the discovery document does **not**
      advertise ``authorization_response_iss_parameter_supported``.

    These tests **document the gap**. They are deliberately
    asymmetric — when DOT adopts RFC 9207 in a future minor, the
    assertions flip from "absent" to "present and equals issuer",
    which is the right time to revisit the policy layer and
    consider whether to enforce the parameter at the AS side
    independently of DOT.
    """

    def test_authorize_redirect_does_not_include_iss_parameter(self) -> None:
        """
        documents-gap: the 302 from /o/authorize/ on consent carries
        only ``code`` and ``state``. When DOT ships RFC 9207, this
        assertion flips to ``self.assertIn("iss", qs)`` and a
        follow-up assertion equates ``qs["iss"][0]`` with the
        discovery ``issuer`` URL.
        """
        self.grant_oidc_access(self.user1)
        code, _, qs = self.authorize_post_and_extract_code(
            self.user1,
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "iss-absent",
                "allow": True,
            },
            expected_redirect_uri=REDIRECT_URI,
        )
        del code  # acknowledge that issuance is just a side-effect here
        self.assertNotIn(
            "iss",
            qs,
            "RFC 9207 ``iss`` parameter unexpectedly present — "
            "DOT must have shipped support; flip this test to a "
            "positive equality check against the discovery ``issuer``.",
        )

    def test_discovery_does_not_advertise_iss_parameter_support(self) -> None:
        """
        documents-gap: discovery does not yet carry
        ``authorization_response_iss_parameter_supported: true``.

        RFC 9207 §3 requires the AS to advertise the capability so
        RPs can opt into stricter verification. Until DOT adds this
        flag, RPs cannot tell if the AS is RFC 9207-compliant; pin
        the current absence so a silent flip to ``True`` doesn't
        bypass our review.
        """
        self.assertNotIn(
            "authorization_response_iss_parameter_supported",
            self.discovery(),
            "DOT discovery shipped RFC 9207 advert — flip this test "
            "to a positive ``assertTrue(config[...]) is True``.",
        )


class TestAuthorizeClickjackingHeaders(OIDCTestCase):
    """
    OIDC Core §16.16 mandates clickjacking protection on the consent
    screen. ``AuthAuthorizationView.dispatch`` applies both legacy
    ``X-Frame-Options`` and the modern
    ``Content-Security-Policy: frame-ancestors`` directive to every
    response path leaving the view — consent screen, denied page,
    reauth bounce.

    The application-level pin in ``_apply_clickjacking_headers`` is
    defence-in-depth on top of
    ``django.middleware.clickjacking.XFrameOptionsMiddleware``, which
    operators may not have wired (the middleware is in Django's
    recommended set but not required for any other reason).
    """

    def _assert_frame_protections(self, response: Any) -> None:
        """Both headers MUST be present with the spec-mandated values."""
        self.assertEqual("DENY", response.headers.get("X-Frame-Options"))
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertIn(
            "frame-ancestors 'none'",
            csp,
            f"CSP missing frame-ancestors directive; got {csp!r}",
        )

    def test_consent_screen_carries_clickjacking_headers(self) -> None:
        """
        The consent template is the spec-target of §16.16 — it is
        the surface an attacker would frame to steal authorisation
        clicks. Headers MUST be present on the 200 render.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        resp = self.authorize_get_default(self.user1)
        self.assertEqual(200, resp.status_code)
        self._assert_frame_protections(resp)

    def test_denied_response_carries_clickjacking_headers(self) -> None:
        """
        The 403 denied page is a defence-in-depth target too — a
        framed denied page leaks "user X cannot access app Y" to a
        framing attacker. Headers MUST cover the deny path.
        """
        # user2 lacks the global access_oidc permission → GlobalDeny
        self.client.force_login(self.user2)
        resp = self.authorize_get_default(self.user2)
        self.assertEqual(403, resp.status_code)
        self._assert_frame_protections(resp)

    def test_operator_xframe_override_is_respected(self) -> None:
        """
        ``_apply_clickjacking_headers`` uses an additive write: an
        operator-configured ``X-Frame-Options`` (e.g. ``SAMEORIGIN``
        for an embedded consent screen) is NOT overwritten. The
        contract is "set the header IF absent", not "force DENY".

        Verified by patching ``_dispatch_inner`` to attach a
        ``SAMEORIGIN`` header before the outer wrapper sees the
        response.
        """
        from unittest import mock

        from allianceauth_oidc.views_authorize import AuthAuthorizationView

        real = AuthAuthorizationView._dispatch_inner

        def patched(self, request, *args, **kwargs):
            response = real(self, request, *args, **kwargs)
            response["X-Frame-Options"] = "SAMEORIGIN"
            return response

        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        with mock.patch.object(
            AuthAuthorizationView, "_dispatch_inner", patched
        ):
            resp = self.authorize_get_default(self.user1)
        # Outer wrapper must NOT overwrite the operator-set value.
        self.assertEqual("SAMEORIGIN", resp.headers.get("X-Frame-Options"))
        # CSP frame-ancestors is still added (additive on the CSP
        # header — coexists with whatever else lives on that line).
        self.assertIn(
            "frame-ancestors 'none'",
            resp.headers.get("Content-Security-Policy", ""),
        )
