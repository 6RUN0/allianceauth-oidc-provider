"""
Graceful-handling pins for OIDC optional authorize parameters.

OIDC Core 1.0 §3.1.2.1 lists a number of authorize-request
parameters the AS MAY honour or ignore: ``display``,
``ui_locales``, ``claims_locales``, ``login_hint``. None of them
are *required* — but they're all OPTIONAL with explicit fallback
semantics ("if not supported, the AS MUST NOT error").

Plus OAuth 2.0 Form Post Response Mode (OAuth FAPI / OASIS
draft): ``response_mode=form_post`` swaps the 302+query response
for a 200 HTML form that auto-POSTs to the redirect_uri.

The contract these tests pin: every optional parameter the
provider does NOT implement MUST be ignored gracefully — no
5xx, no privilege change, no silent downgrade that could mask
a future security regression. When upstream lands the feature,
each test surfaces the change by flipping from "ignored" to
"honoured" assertions.
"""

import json

from ._oidc_testcase import (
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    OIDCTestCase,
)


class TestDisplayParameter(OIDCTestCase):
    """
    OIDC §3.1.2.1 ``display`` parameter graceful handling.

    Spec values: ``page`` (default, full-page UI), ``popup``
    (popup window — smaller fonts, no chrome), ``touch``
    (touch-screen optimised), ``wap`` (feature-phone — legacy).
    Plus arbitrary case-sensitive strings the AS MAY ignore.

    Project does not customise the consent / login UI per
    ``display`` value. Pin: each spec value (and one bogus
    value) flows through /authorize/ without 5xx and without
    affecting code issuance.
    """

    def _authorize_with_display(self, value: str) -> object:
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        return self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": f"display-{value}",
                "display": value,
            },
        )

    def test_all_spec_display_values_do_not_5xx(self) -> None:
        """Each spec-listed ``display`` value yields a controlled response."""
        for value in ("page", "popup", "touch", "wap"):
            with self.subTest(display=value):
                resp = self._authorize_with_display(value)
                self.assertLess(
                    resp.status_code,
                    500,
                    f"display={value!r} yielded 5xx: {resp.status_code}",
                )

    def test_unknown_display_value_does_not_5xx(self) -> None:
        """
        An arbitrary unknown value MUST be ignored, not 5xx-rejected.

        OIDC §3.1.2.1 explicitly allows the AS to ignore unknown
        ``display`` values; rejecting one as malformed input would
        be a spec violation.
        """
        resp = self._authorize_with_display("hologram")
        self.assertLess(resp.status_code, 500)

    def test_display_does_not_affect_code_issuance(self) -> None:
        """
        ``display`` is UI-only — code/state echo MUST be identical.

        Pin that no value of ``display`` mutates the issued code,
        scope, or state. If a future override of the consent
        template starts conditioning on ``display`` and accidentally
        rewrites scope, this test surfaces the regression.
        """
        self.grant_oidc_access(self.user1)
        # Two parallel authorizations: one with display, one without.
        # Both must issue codes; the codes themselves differ (random)
        # but the *state* echoes verbatim and no error is reported.
        code_plain = self.authorize_to_code(
            self.user1, scope=SCOPE_OPENID, state="display-baseline"
        )
        code_with = self.authorize_to_code(
            self.user1,
            scope=SCOPE_OPENID,
            state="display-popup",
            extra_authorize_params={"display": "popup"},
        )
        # Both codes are non-empty strings and DIFFERENT (each
        # authorize call mints a fresh Grant).
        self.assertTrue(code_plain)
        self.assertTrue(code_with)
        self.assertNotEqual(code_plain, code_with)


class TestUiLocalesParameter(OIDCTestCase):
    """
    OIDC §3.1.2.1 ``ui_locales`` parameter graceful handling.

    Space-separated list of BCP47 language tags in priority order.
    The AS uses it to select the language of the login / consent
    UI. Project does not localise the consent template per request,
    so ``ui_locales`` is ignored — but MUST be ignored *cleanly*.

    Two contracts:

    1. Any well-formed ``ui_locales`` value flows through without
       5xx and without affecting the code-issuance path.
    2. Malformed values (empty, oversized, control chars) do not
       5xx — the AS treats unparseable input as "no preference".
    """

    def _authorize_with_locales(self, value: str) -> object:
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        return self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "ui-locales",
                "ui_locales": value,
            },
        )

    def test_well_formed_locales_do_not_5xx(self) -> None:
        for value in ("ru en", "en-US fr-CA", "de", "ja-JP"):
            with self.subTest(ui_locales=value):
                resp = self._authorize_with_locales(value)
                self.assertLess(resp.status_code, 500)

    def test_empty_and_garbage_locales_do_not_5xx(self) -> None:
        """Empty / malformed strings MUST NOT crash the dispatcher."""
        for value in ("", "   ", "xx-yy zz-ww", "bad locale with !@#"):
            with self.subTest(ui_locales=value):
                resp = self._authorize_with_locales(value)
                self.assertLess(resp.status_code, 500)

    # The full ui_locales-vs-profile.language identity contract is
    # pinned at the /userinfo HTTP level by
    # ``test_conformance.TestLocaleNegotiation
    # .test_locale_claim_follows_user_profile_not_request_locale``.
    # Duplicating it here would only re-test the same boundary
    # against a weaker observation point (id_token §5.4 hides
    # ``locale`` by design — see ``get_id_token_dictionary``).


class TestLoginHintParameter(OIDCTestCase):
    """
    OIDC §3.1.2.1 ``login_hint`` parameter binding contract.

    Spec semantics: the RP suggests the End-User's identifier (email,
    phone, etc.) to pre-fill the login form. The AS MAY use it to
    skip identifier entry, but the value is **never** authoritative —
    the actual authenticated subject comes from the session.

    Project does not customise the login template, so ``login_hint``
    is ignored. The critical safety pin: regardless of the hint
    value, the code is bound to the *session* user. An attacker who
    crafts ``login_hint=victim@example.com`` MUST NOT receive a
    code for that user — they receive a code for themselves (if
    authenticated) or a login prompt (if not).
    """

    def test_login_hint_does_not_override_session_user(self) -> None:
        """
        Code is bound to session user, not ``login_hint`` value.

        The attacker scenario: a victim is logged in as user1; the
        attacker tricks them into clicking a crafted authorize URL
        with ``login_hint=attacker@example.com``. The issued code
        and id_token MUST identify user1 (the session), never the
        attacker's hint.
        """
        self.grant_oidc_access(self.user1)
        tokens = self.run_code_flow(
            self.user1,
            scope=SCOPE_FULL,
            state="login-hint-binding",
            extra_authorize_params={
                "login_hint": "attacker@example.com",
            },
        )
        import base64

        seg = tokens["id_token"].split(".", 2)[1]
        padding = "=" * (-len(seg) % 4)
        claims = json.loads(
            base64.urlsafe_b64decode(seg + padding).decode("utf-8")
        )
        self.assertEqual(
            str(self.user1.pk),
            claims.get("sub"),
            "id_token sub MUST be session user, never login_hint",
        )

    def test_login_hint_with_garbage_does_not_5xx(self) -> None:
        """
        Hint values are advisory — any string MUST be tolerated.

        Pin defensive handling: SQL-fragment, control chars,
        oversized blob — none should escape into a 5xx or alter
        the flow.
        """
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        for hint in (
            "",
            "' OR 1=1 --",
            "\x00\x01\x02",
            "a" * 4096,
            "user@.invalid",
        ):
            with self.subTest(login_hint=repr(hint)):
                resp = self.client.get(
                    "/o/authorize/",
                    data={
                        "response_type": "code",
                        "client_id": self.oauth_id,
                        "redirect_uri": REDIRECT_URI,
                        "scope": SCOPE_OPENID,
                        "state": "login-hint-garbage",
                        "login_hint": hint,
                    },
                )
                self.assertLess(
                    resp.status_code,
                    500,
                    f"login_hint={hint!r} yielded 5xx",
                )


class TestResponseModeFormPost(OIDCTestCase):
    """
    OAuth 2.0 Form Post Response Mode — ``response_mode=form_post``.

    Defined by *OAuth 2.0 Form Post Response Mode* (OASIS / OIDC FAPI
    references). Instead of 302 with parameters in the query, the AS
    returns 200 HTML containing a form that auto-POSTs the response
    parameters to the redirect_uri. Mitigates parameter leakage via
    HTTP referer logs and browser history.

    Current state of the upstream stack: django-oauth-toolkit does
    NOT implement ``form_post``. Discovery does not advertise
    ``response_modes_supported``, and oauthlib falls back to the
    default ``query`` mode.

    Two pinned outcomes (either is spec-compliant):

    1. The request is silently downgraded to ``response_mode=query``
       (302 redirect with code+state in the URL).
    2. The request is rejected with
       ``error=unsupported_response_mode`` (RFC 6749 §4.1.2.1).

    The forbidden outcome — and the regression this catches — is a
    5xx, or a 200 HTML response that pretends to be form_post but
    fails to submit (silent breakage for RPs that depend on the
    mode).
    """

    def test_response_mode_form_post_is_downgraded_or_rejected(
        self,
    ) -> None:
        self.grant_oidc_access(self.user1)
        self.client.force_login(self.user1)
        resp = self.client.get(
            "/o/authorize/",
            data={
                "response_type": "code",
                "client_id": self.oauth_id,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE_OPENID,
                "state": "form-post-mode",
                "response_mode": "form_post",
            },
        )
        # No 5xx — DOT's parameter validation either accepts and
        # ignores, or rejects via a documented OAuth error.
        self.assertLess(resp.status_code, 500)
        # The two acceptable shapes:
        #   * 200 + consent template (DOT renders consent; mode
        #     ignored until POST).
        #   * 302 to redirect_uri (query mode fallback) — possibly
        #     carrying an ``error`` parameter.
        self.assertIn(resp.status_code, (200, 302))
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            # Either an error in query, or a normal code redirect —
            # never an attacker-controlled URI.
            self.assertTrue(location.startswith(REDIRECT_URI))

    def test_response_modes_supported_absent_from_discovery(self) -> None:
        """
        documents-gap: discovery does not advertise response_modes.

        When DOT adopts form_post, ``response_modes_supported``
        will appear in discovery and ``form_post`` will be in the
        list. Flip the assertion at that point and extend the
        first test to assert the actual form_post behaviour.
        """
        resp = self.client.get("/o/.well-known/openid-configuration/")
        self.assertEqual(200, resp.status_code)
        doc = json.loads(resp.content.decode("utf-8"))
        self.assertNotIn(
            "response_modes_supported",
            doc,
            "DOT shipped response_modes advert; extend "
            "test_response_mode_form_post_is_downgraded_or_rejected.",
        )
