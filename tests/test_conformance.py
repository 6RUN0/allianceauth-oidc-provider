"""
OIDC conformance tests: claims selector, PKCE smoke, locales, public client.

Endpoint-specific suites moved out of this file:

- discovery + JWKS              → ``test_discovery.py``
- id_token claim contracts      → ``test_id_token.py``
- ``/o/revoke_token/`` + ``/o/introspect/`` → ``test_revoke_introspect.py``

What remains here covers cross-cutting conformance contracts that do not
fit any of the endpoint-specific homes above: the OIDC §5.5 ``claims``
request-parameter selector, the ``oidcc-codereuse``-style PKCE smoke
matrix, locale negotiation, and public-client policy.
"""

import base64
import html
import os
import re
from typing import Any

from ._factories import make_app
from ._jwt_helpers import split_jwt
from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    GrantedOIDCTestCase,
    OIDCTestCase,
)


def _b64url(raw: bytes) -> str:
    # base64url-encode without padding, per RFC 7636 / RFC 7515.
    # Duplicated here and in test_discovery.py — the helper is one
    # line and copying avoids a shared ``tests/_helpers.py`` for a
    # single function.
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TestRequestedIdTokenClaimsSelector(OIDCTestCase):
    """
    OIDC Core 1.0 §5.5 — the ``claims`` request parameter selects
    optional id_token claims. The selector must (a) reject malformed
    inputs without raising (M5: a string or list survives JSON parse
    when the client sends a quoted string instead of a dict) and
    (b) treat an essential ``acr`` request as triggering the same
    ``acr=0`` fallback that ``acr_values`` does (M11, §5.5.1.1).
    """

    def _stub(self, **overrides):
        from types import SimpleNamespace

        defaults: dict[str, Any] = {"claims": None, "acr_values": None}
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_selector_returns_empty_when_claims_is_a_string(self) -> None:
        """A malformed string survives JSON parse as a str — must not crash."""
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        selector = (
            AllianceAuthOAuth2Validator._select_requested_id_token_claims
        )
        request = self._stub(claims="garbage")
        self.assertEqual(selector(request), {})

    def test_selector_returns_empty_when_id_token_member_is_a_list(
        self,
    ) -> None:
        """Defensive: non-dict ``id_token`` member is ignored."""
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        selector = (
            AllianceAuthOAuth2Validator._select_requested_id_token_claims
        )
        request = self._stub(claims={"id_token": ["unexpected"]})
        self.assertEqual(selector(request), {})

    def test_selector_returns_id_token_member_when_well_formed(
        self,
    ) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        selector = (
            AllianceAuthOAuth2Validator._select_requested_id_token_claims
        )
        request = self._stub(claims={"id_token": {"acr": {"essential": True}}})
        self.assertEqual(selector(request), {"acr": {"essential": True}})

    def test_acr_zero_emitted_for_essential_acr_in_claims_param(
        self,
    ) -> None:
        """
        OIDC §5.5.1.1 — when the client requests ``acr`` via
        ``claims.id_token.acr`` (especially with ``essential=True``)
        but the provider cannot meet a concrete level, ``acr=0``
        must still appear. The previous override only fired this
        fallback for the ``acr_values`` request parameter.
        """
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        request = self._stub(
            claims={"id_token": {"acr": {"essential": True}}},
            acr_values=None,
        )
        narrowed = AllianceAuthOAuth2Validator._inject_acr_fallback(
            narrowed={"sub": "1"}, request=request
        )
        self.assertEqual(narrowed["acr"], "0")

    def test_acr_zero_still_emitted_for_acr_values_only(self) -> None:
        """Regression: legacy ``acr_values`` path keeps emitting ``acr=0``."""
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        request = self._stub(
            claims=None, acr_values="urn:mace:incommon:iap:silver"
        )
        narrowed = AllianceAuthOAuth2Validator._inject_acr_fallback(
            narrowed={"sub": "1"}, request=request
        )
        self.assertEqual(narrowed["acr"], "0")

    def test_acr_not_emitted_when_neither_acr_values_nor_claim(
        self,
    ) -> None:
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        request = self._stub(claims=None, acr_values=None)
        narrowed = AllianceAuthOAuth2Validator._inject_acr_fallback(
            narrowed={"sub": "1"}, request=request
        )
        self.assertNotIn("acr", narrowed)


class TestPKCEFlow(GrantedOIDCTestCase):
    def _authorize_with_pkce(self, *, challenge: str, state: str) -> str:
        """Issue an authorization code with a code_challenge attached."""
        return self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state=state,
            extra_authorize_params={
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    def _exchange(
        self, *, code: str, verifier: str | None
    ) -> tuple[int, dict]:
        """Wrap :meth:`exchange_code_with_verifier` for legacy tuple shape."""
        resp = self.exchange_code_with_verifier(code=code, verifier=verifier)
        return resp.status_code, self.json_body(resp, expected_status=None)

    def test_pkce_s256_round_trip(self):
        """
        Happy path: a client opting into S256 PKCE still gets a working
        code + verifier exchange.

        With per-app PKCE the shared fixture has ``pkce_required=False``
        (so non-PKCE flows in other modules keep working), but a client
        sending ``code_challenge`` regardless still drives the full
        verifier round-trip — DOT enforces PKCE whenever the
        authorize-time challenge is present.
        """
        verifier, challenge = self.make_pkce_pair()
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-happy"
        )
        status, body = self._exchange(code=code, verifier=verifier)
        self.assertEqual(200, status)
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)

    def test_pkce_with_wrong_verifier_is_rejected(self):
        """
        RFC 7636: presenting a verifier that does NOT hash to the previously-
        supplied challenge must be rejected with invalid_grant.

        Otherwise PKCE provides no protection.
        """
        _, challenge = self.make_pkce_pair()
        wrong_verifier = _b64url(os.urandom(32))  # unrelated random bytes
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-wrong-verifier"
        )
        status, body = self._exchange(code=code, verifier=wrong_verifier)
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )

    def test_pkce_missing_verifier_when_challenge_provided_is_rejected(
        self,
    ):
        """
        RFC 7636 §4.6: if the authorize request used PKCE, the token request
        MUST include code_verifier.

        Omitting it must fail.
        """
        _, challenge = self.make_pkce_pair()
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-missing-verifier"
        )
        status, body = self._exchange(code=code, verifier=None)
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )

    def test_pkce_empty_verifier_is_rejected(self):
        """
        Empty ``code_verifier`` cannot match any non-empty challenge
        hash — DOT must reject the exchange. Pinned because an
        empty-string fast-path that bypassed the hash compare would
        defeat PKCE entirely.
        """
        _, challenge = self.make_pkce_pair()
        code = self._authorize_with_pkce(
            challenge=challenge, state="pkce-empty-verifier"
        )
        status, body = self._exchange(code=code, verifier="")
        self.assertEqual(400, status)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )


class TestPerAppPkceRequired(GrantedOIDCTestCase):
    """
    Per-app ``pkce_required`` override exercised over the HTTP authorize
    surface.

    These tests build dedicated ``make_app(pkce_required=...)`` fixtures
    so the shared OIDCTestCase fixture (``pkce_required=False``) stays
    isolated and other modules' assumptions are not affected.
    """

    def _authorize_no_challenge(self, *, client_id: str, state: str):
        return self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state=state,
            extra={"client_id": client_id},
        )

    def test_pkce_required_per_app_strict_no_challenge(self):
        """
        Fixture ``pkce_required=True``; authorize without ``code_challenge``
        must fail (DOT redirects with ``error=invalid_request``).
        """
        creds = make_app(owner=self.user1, pkce_required=True)
        resp = self._authorize_no_challenge(
            client_id=creds.client_id, state="pkce-strict"
        )
        # DOT for missing PKCE returns either a 302 with the error
        # encoded in the redirect, or a 400 with the error in the body.
        # Accept both shapes.
        self.assertIn(resp.status_code, (302, 400))
        body = resp.content.decode("utf-8") + str(resp.headers)
        self.assertIn("invalid_request", body)

    def test_pkce_required_per_app_lenient_no_challenge(self):
        """
        Fixture ``pkce_required=False``; authorize without
        ``code_challenge`` must succeed (302 redirect carrying ``code=``).
        """
        creds = make_app(
            owner=self.user1, pkce_required=False, skip_authorization=True
        )
        resp = self._authorize_no_challenge(
            client_id=creds.client_id, state="pkce-lenient"
        )
        self.assertEqual(302, resp.status_code)
        location = resp.headers["Location"]
        self.assertIn("code=", location)
        self.assertNotIn("error=", location)

    def test_pkce_required_with_method_plain_round_trip(self):
        """
        RFC 7636 §4.2 ``code_challenge_method=plain``: the verifier is
        the challenge verbatim. With ``pkce_required=True`` this still
        round-trips because the challenge is supplied.
        """
        from urllib.parse import parse_qs, urlparse

        verifier = _b64url(os.urandom(32))
        challenge = verifier  # plain method: challenge == verifier
        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="pkce-plain",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "plain",
            },
        )
        self.assertEqual(302, resp.status_code)
        location = resp.headers["Location"]
        self.assertIn("code=", location)
        code = parse_qs(urlparse(location).query)["code"][0]
        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = self.json_body(token_resp, expected_status=None)
        self.assertIn("access_token", body)

    def test_strict_app_empty_verifier_at_exchange_is_rejected(self):
        """
        Empty verifier at exchange must fail under strict mode — same
        contract as the global fixture's
        ``test_pkce_empty_verifier_is_rejected`` but cross-checked
        against per-app override to guard against a regression that
        bypasses verifier validation when ``pkce_required=True``
        forces the authorize-time check.
        """
        from urllib.parse import parse_qs, urlparse

        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        _, challenge = self.make_pkce_pair()
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="strict-empty",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(302, resp.status_code)
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]
        token_resp = self.exchange_code_with_verifier(
            code=code,
            verifier="",
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(400, token_resp.status_code)
        body = self.json_body(token_resp, expected_status=None)
        self.assertIn(
            body.get("error"),
            {"invalid_grant", "invalid_request"},
        )


class TestClaimsRequestParameterHTTP(GrantedOIDCTestCase):
    """
    OIDC Core 1.0 §5.5 — the ``claims`` request parameter is JSON
    embedded in a query parameter. Mis-shaped input is an attractive
    DoS / parser-confusion target.

    The filter-level coverage lives in
    :class:`TestRequestedIdTokenClaimsSelector`; this class closes
    the HTTP-side contract behind the conformance suite's
    ``oidcc-claims-essential`` module. Each case asserts the AS does
    NOT 500 / does NOT block the flow on bad input — graceful
    handling is the security property.
    """

    def test_authorize_accepts_well_formed_claims_param(self) -> None:
        """
        ``claims={"id_token":{"acr":{"essential":true}}}`` — the
        spec-canonical example. Flow must complete and a code is
        issued.
        """
        claims_json = '{"id_token":{"acr":{"essential":true}}}'
        code = self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state="claims-well-formed",
            extra_authorize_params={"claims": claims_json},
        )
        self.assertIsInstance(code, str)
        self.assertTrue(code)

    def test_authorize_with_malformed_claims_param_does_not_500(self) -> None:
        """
        Malformed JSON in ``claims=`` must not crash. The selector
        defends with a try/except (M5 in TestRequestedIdTokenClaimsSelector);
        the HTTP path must surface that defence — either accept the
        request and ignore the bad claim (the project's choice) or
        reject with an OAuth error redirect. A 5xx is forbidden.
        """
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "claims-malformed",
                "claims": "{not-valid-json",
            },
        )
        self.assertLess(
            resp.status_code,
            500,
            f"malformed claims= MUST NOT 5xx; got {resp.status_code}",
        )

    def test_authorize_with_empty_claims_param_does_not_500(self) -> None:
        """An empty ``claims=`` query parameter must be tolerated."""
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "claims-empty",
                "claims": "",
            },
        )
        self.assertLess(resp.status_code, 500)


class TestAcrValuesCodeFlow(GrantedOIDCTestCase):
    """
    OIDC Core 1.0 §15.1 — a client that requested ACR via
    ``acr_values`` SHOULD get an ``acr`` claim back; the provider
    answers ``acr=0`` (RFC 6711 "no specific level") because AA has
    no concept of authentication levels.

    These are full HTTP flows on purpose: the stub-level tests in
    :class:`TestRequestedIdTokenClaimsSelector` exercised
    ``_inject_acr_fallback`` with a hand-built request and stayed
    green while the real code flow silently dropped ``acr_values``
    at the token endpoint (oauthlib does not carry it across the
    exchange; DOT persists only ``nonce`` and ``claims`` on the
    Grant, and its consent form round-trips only those). The
    conformance module
    ``oidcc-ensure-request-with-acr-values-succeeds`` caught the
    gap as a WARNING. The fix rewrites the authorize query,
    folding ``acr_values`` into a ``claims.id_token.acr`` member —
    see ``_fold_acr_values_into_claims_query`` in
    ``views_authorize.py``.

    The fold lives on the *rendered* flow (GET query / promoted
    POST body), so these tests drive the endpoints the way a
    browser does — ``skip_authorization`` fast path and the real
    consent-form round trip — rather than fabricating a consent
    POST like ``authorize_to_code`` does (a fabricated POST never
    passes through the fold).
    """

    def _authorize_params(self, state: str, extra: dict | None) -> dict:
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_OPENID,
            "state": state,
        }
        params.update(extra or {})
        return params

    def _id_token_claims_via_skip_authorization(
        self, extra: dict | None, state: str
    ) -> dict:
        """GET /o/authorize/ with skip_authorization -> code -> token."""
        self.oauth_app.skip_authorization = True
        self.oauth_app.save()
        resp = self.authorize_get(
            self.user1, params=self._authorize_params(state, extra)
        )
        _, _, qs = self.parse_redirect(resp, (302,))
        body = self.json_body(
            self.exchange_code_for_token(
                code=qs["code"][0], redirect_uri=REDIRECT_URI
            )
        )
        return split_jwt(body["id_token"])[1]

    def test_acr_values_only_yields_acr_zero_in_id_token(self) -> None:
        claims = self._id_token_claims_via_skip_authorization(
            {"acr_values": "0"}, state="acr-values-only"
        )
        self.assertEqual("0", claims.get("acr"))

    def test_claims_essential_acr_yields_acr_zero_in_id_token(
        self,
    ) -> None:
        claims = self._id_token_claims_via_skip_authorization(
            {"claims": '{"id_token":{"acr":{"essential":true}}}'},
            state="acr-claims-essential",
        )
        self.assertEqual("0", claims.get("acr"))

    def test_acr_values_alongside_claims_param_yields_acr_zero(
        self,
    ) -> None:
        # Both spec-equivalent request forms at once — the fold must
        # not clobber the client's own claims.id_token member.
        claims = self._id_token_claims_via_skip_authorization(
            {
                "acr_values": "urn:mace:incommon:iap:silver",
                "claims": '{"id_token":{"auth_time":{"essential":true}}}',
            },
            state="acr-values-plus-claims",
        )
        self.assertEqual("0", claims.get("acr"))
        # The client-requested auth_time member survived the fold.
        self.assertIn("auth_time", claims)

    def test_no_acr_claim_without_any_acr_request(self) -> None:
        claims = self._id_token_claims_via_skip_authorization(
            None, state="acr-not-requested"
        )
        self.assertNotIn("acr", claims)

    def test_acr_survives_consent_form_round_trip(self) -> None:
        """
        The deployment-default path (``skip_authorization=False``):
        GET renders the consent form, the folded claims ride DOT's
        hidden ``claims`` field, the user's POST carries them to the
        grant. Submits the ACTUAL rendered form fields — no
        fabricated values.
        """
        resp = self.authorize_get(
            self.user1,
            params=self._authorize_params(
                "acr-consent-form", {"acr_values": "0"}
            ),
        )
        self.assertEqual(200, resp.status_code)
        content = resp.content.decode("utf-8")
        # Attribute values arrive HTML-escaped (the claims JSON's
        # quotes render as ``&quot;``) — unescape before re-POSTing.
        hidden = {
            name: html.unescape(value)
            for name, value in re.findall(
                r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', content
            )
        }
        self.assertIn("acr", hidden.get("claims", ""))
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data={**hidden, "allow": "true"},
            expected_redirect_uri=REDIRECT_URI,
        )
        body = self.json_body(
            self.exchange_code_for_token(code=code, redirect_uri=REDIRECT_URI)
        )
        claims = split_jwt(body["id_token"])[1]
        self.assertEqual("0", claims.get("acr"))

    def test_acr_values_with_malformed_claims_param_is_rejected(
        self,
    ) -> None:
        # The fold must leave malformed claims JSON untouched (never
        # replace client input); oauthlib then rejects the request
        # ("Malformed claims parameter") instead of the fold masking
        # the client's error. DOT renders the rejection as an error
        # page (no redirect — same shape as any authorize-request
        # validation failure).
        resp = self.authorize_get(
            self.user1,
            params=self._authorize_params(
                "acr-malformed-claims",
                {"acr_values": "0", "claims": "this is not json"},
            ),
        )
        self.assertEqual(400, resp.status_code)
        self.assertIn(
            "invalid_request", resp.content.decode("utf-8", "replace")
        )


class TestLocaleNegotiation(GrantedOIDCTestCase):
    """
    OIDC Core 1.0 §5.2 + §3.1.2.1 — ``ui_locales`` and
    ``claims_locales`` are OPTIONAL request parameters. The
    provider is permitted to ignore them, but it MUST NOT 5xx and
    MUST NOT alter the OAuth flow on their presence.

    The project ignores both (no locale negotiation; ``locale`` claim
    derives from ``user.profile.language``). This class pins that
    contract — replaces conformance modules ``oidcc-ui-locales`` and
    ``oidcc-claims-locales`` which TIMEOUT upstream.
    """

    def test_ui_locales_does_not_break_authorize_flow(self) -> None:
        """``ui_locales=fr,en`` must be accepted and a code issued."""
        code = self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state="ui-locales",
            extra_authorize_params={"ui_locales": "fr en"},
        )
        self.assertIsInstance(code, str)
        self.assertTrue(code)

    def test_claims_locales_does_not_break_authorize_flow(self) -> None:
        """``claims_locales=de,en`` must be accepted and a code issued."""
        code = self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state="claims-locales",
            extra_authorize_params={"claims_locales": "de en"},
        )
        self.assertIsInstance(code, str)
        self.assertTrue(code)

    def test_locale_claim_follows_user_profile_not_request_locale(
        self,
    ) -> None:
        """
        The ``locale`` claim on /userinfo/ must reflect
        ``user.profile.language`` — passing ``ui_locales=fr`` MUST
        NOT change it to ``fr``. Pins the design choice to ignore
        request-side locale negotiation.
        """
        self.user1.profile.language = "ru"
        self.user1.profile.save()
        self.user1.refresh_from_db()

        tokens = self.run_code_flow(
            self.user1,
            scope=SCOPE_FULL,
            state="locale-vs-request",
            extra_authorize_params={"ui_locales": "fr en"},
        )
        info = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(200, info.status_code)
        body = self.json_body(info, expected_status=None)
        self.assertEqual(
            "ru",
            body.get("locale"),
            "locale claim must come from user.profile.language, not "
            "the ui_locales request parameter",
        )


class TestPublicClientPolicy(GrantedOIDCTestCase):
    """
    Public-client (``client_type=public``) contracts.

    RFC 6749 §2.1 / §10.4: public clients cannot keep a confidential
    secret. The token endpoint MUST authenticate them by client_id
    alone (no secret required), and PKCE is the recommended
    alternative — RFC 7636 was designed exactly for this case.

    Pinned: public-client + PKCE code flow completes; presenting a
    bogus client_secret on a public client does not cause a
    spurious 500.
    """

    def _public_app(self, *, pkce_required: bool = True):
        from oauth2_provider.models import AbstractApplication

        from ._factories import make_app

        return make_app(
            owner=self.user1,
            pkce_required=pkce_required,
            skip_authorization=True,
            client_type=AbstractApplication.CLIENT_PUBLIC,
        )

    def test_public_client_pkce_code_flow_succeeds_without_secret(
        self,
    ) -> None:
        """
        Public client + PKCE + no client_secret on /o/token/ — the
        canonical mobile/native-app flow. MUST succeed.
        """
        from urllib.parse import parse_qs, urlparse

        creds = self._public_app(pkce_required=True)

        verifier, challenge = self.make_pkce_pair()

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="public-pkce",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(302, resp.status_code)
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]

        # Public-client token exchange: client_id + code_verifier,
        # no client_secret.
        token_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": creds.client_id,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
        self.assertEqual(200, token_resp.status_code)
        body = self.json_body(token_resp, expected_status=None)
        self.assertIn("access_token", body)

    def test_public_client_with_garbage_secret_does_not_500(self) -> None:
        """
        Public client presented with a (bogus) secret — either DOT
        silently ignores it (RFC 6749: secret is meaningless for
        public clients) or rejects with invalid_client. Either is
        spec-compliant; a 5xx would be the regression.
        """
        from urllib.parse import parse_qs, urlparse

        creds = self._public_app(pkce_required=True)
        verifier, challenge = self.make_pkce_pair()
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="public-with-garbage-secret",
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        code = parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]

        token_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": creds.client_id,
                "client_secret": "WRONG_SECRET",  # nosec B106 pragma: allowlist secret
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
        self.assertLess(
            token_resp.status_code,
            500,
            "public client + bogus secret MUST NOT 5xx; got "
            f"{token_resp.status_code}",
        )
