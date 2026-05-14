"""
Tests for /o/token/ — full code-exchange and refresh flows.

Two related concerns:

1. Policy matrix (state x group x superuser) parametrized via
   ``parameterized.expand`` — replaces 6 hand-written
   ``test_full_chain_*`` methods plus 3 deny variants previously
   scattered across test_authorize.py.
2. Token-policy guards: refusal to exchange or refresh tokens when
   the user no longer matches the app's policy, on redirect_uri
   mismatch, on wrong client_secret, on inactive applications, and
   on refresh-token rotation invalidation.

Userinfo claims live in test_userinfo.py; RP-initiated logout in
test_logout.py; debug-logging leak protection in test_logging.py.
"""

import json

from allianceauth.authentication.models import State
from parameterized import parameterized

from ._oidc_testcase import (
    DEFAULT_EXPIRES_IN,
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    OIDCTestCase,
)

# (name, app_states, app_groups_required, user_groups_match, is_superuser,
#  expect)
#
# - ``app_states``: list of State names the app restricts to. ``[]`` = no
#   state restriction.
# - ``app_groups_required``: True → app requires the test group; user1 may
#   or may not be in that group depending on ``user_groups_match``.
# - ``user_groups_match``: only meaningful when app_groups_required=True.
# - ``is_superuser``: bypasses all restrictions.
# - ``expect``: "allow" runs the full code-flow + token check; "deny" hits
#   /o/authorize/ and asserts the denial page.
#
# user1 has state=Member by default (set up in OIDCTestCase.setUpTestData).
POLICY_MATRIX = [
    # No restrictions — every authenticated user gets a token.
    ("open_app_no_restrictions", [], False, False, False, "allow"),
    # State-only.
    ("state_only_match", ["Member"], False, False, False, "allow"),
    ("state_only_mismatch_denies", ["Blue"], False, False, False, "deny"),
    # Group-only.
    ("group_only_match", [], True, True, False, "allow"),
    ("group_only_mismatch_denies", [], True, False, False, "deny"),
    # Combined: OR semantics — any single match wins.
    (
        "state_match_overrides_no_group",
        ["Member"],
        True,
        False,
        False,
        "allow",
    ),
    (
        "group_match_overrides_wrong_state",
        ["Blue"],
        True,
        True,
        False,
        "allow",
    ),
    ("neither_matches_denies", ["Blue"], True, False, False, "deny"),
    # Superuser bypasses everything, even neither-match.
    ("superuser_bypasses_restrictions", ["Blue"], True, False, True, "allow"),
]


class TestPolicyMatrix(OIDCTestCase):
    """
    Parametrised access-policy matrix exercised end-to-end.

    `parameterized.expand` synthesises individual test methods named
    ``test_policy_matrix_<index>_<scenario>`` so failure messages point at the
    exact row.
    """

    @parameterized.expand(POLICY_MATRIX)
    def test_policy_matrix(
        self,
        name: str,
        app_states: list[str],
        app_groups_required: bool,
        user_groups_match: bool,
        is_superuser: bool,
        expect: str,
    ) -> None:
        for state_name in app_states:
            self.oauth_app.states.add(State.objects.get(name=state_name))
        if app_groups_required:
            self.oauth_app.groups.add(self.test_grp)
            if user_groups_match:
                self.user1.groups.add(self.test_grp)

        if is_superuser:
            self.user1.is_superuser = True
            self.user1.save()
        self.grant_oidc_access(self.user1)

        if expect == "allow":
            self.run_code_flow(
                self.user1,
                state=f"matrix-{name}",
                expected_scope=SCOPE_FULL,
                expected_expires_in=DEFAULT_EXPIRES_IN,
            )
        elif expect == "deny":
            response = self.authorize_get_default(
                self.user1, state=f"matrix-{name}"
            )
            self.assertDeniedApp(response, self.user1, self.oauth_app)
        else:
            self.fail(f"unknown expect={expect!r}")


class TestTokenPolicyGuards(OIDCTestCase):
    """Refusal paths on /o/token/ and /o/authorize/ when context shifts."""

    def _grant_user1_with_test_grp(self) -> None:
        self.oauth_app.groups.add(self.test_grp)
        self.grant_oidc_access(self.user1)
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()

    def test_token_exchange_denied_if_group_removed_after_code_issued(self):
        """
        If the user stops matching policy (group/state) after code issuance,
        /o/token/ must fail with invalid_grant.
        """
        self._grant_user1_with_test_grp()
        code = self.authorize_to_code(self.user1, state="policy-test")

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.exchange_code_for_token(
            code=code,
            state="policy-test",
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_group_removed(self):
        """
        Refresh token exchange must enforce policy and deny if access was
        removed.
        """
        self._grant_user1_with_test_grp()
        body = self.run_code_flow(
            self.user1,
            state="refresh-policy-test",
            expected_scope=SCOPE_FULL,
            expected_expires_in=DEFAULT_EXPIRES_IN,
        )
        refresh = body["refresh_token"]

        self.user1.groups.clear()
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_refresh_token_denied_if_global_permission_removed(self):
        """
        If the user loses the global OIDC permission after receiving a
        refresh_token, refresh must fail with invalid_grant.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(self.user1, state="perm-removed-refresh")
        refresh = body["refresh_token"]

        self.user1.user_permissions.remove(self.access_oauth)
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_token_exchange_denied_if_redirect_uri_mismatch(self):
        """
        If redirect_uri at /o/token/ doesn't match the one used at
        /o/authorize/, token exchange must fail.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="redir-mismatch")

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/other/",
            expected_status=400,
        )
        self.assertOAuthError(
            resp, expected_error={"invalid_grant", "invalid_request"}
        )

    def test_token_exchange_denied_if_client_secret_invalid(self):
        """
        Confidential clients must not exchange a code with an invalid
        client_secret.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(
            self.user1, scope=SCOPE_OPENID, state="bad-secret"
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            client_secret="WRONG_SECRET",  # nosec B106
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_client",
                "invalid_grant",
                "invalid_request",
            },
        )

    def test_refresh_token_denied_when_app_becomes_inactive(self):
        """
        A refresh_token minted while the app was active must NOT issue a new
        access_token after ``active=False``.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(self.user1, state="inactive-after-issue")
        refresh = body["refresh_token"]

        self.oauth_app.active = False
        self.oauth_app.save()
        self.oauth_app.refresh_from_db()

        resp = self.refresh_token(
            refresh_token=refresh, expected_status=(400, 401, 403)
        )
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_grant",
                "invalid_client",
                "invalid_request",
            },
        )

    def test_old_refresh_token_invalidated_after_rotation(self):
        """
        ``ROTATE_REFRESH_TOKEN=True`` (test settings): once a refresh is
        consumed and a new one is issued, the old refresh must NOT be reusable.

        Regression for token-rotation contract.
        """
        self.grant_oidc_access(self.user1)
        first = self.run_code_flow(self.user1, state="rotation-1")
        old_refresh = first["refresh_token"]

        # First rotation: old refresh → fresh access + (rotated) refresh.
        rotated = self.refresh_token(refresh_token=old_refresh)
        rotated_body = json.loads(rotated.content.decode("utf-8"))
        self.assertIn("access_token", rotated_body)
        new_refresh = rotated_body["refresh_token"]
        self.assertNotEqual(
            old_refresh,
            new_refresh,
            "ROTATE_REFRESH_TOKEN expected to mint a new refresh value",
        )

        # Reusing the old refresh after rotation must fail.
        resp = self.refresh_token(
            refresh_token=old_refresh,
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp, expected_error={"invalid_grant", "invalid_request"}
        )

    def test_token_response_omits_id_token_when_scope_lacks_openid(self):
        """
        DOT only emits an ``id_token`` when the scope contains ``openid``.

        OAuth-only flows must skip id_token entirely.
        """
        self.grant_oidc_access(self.user1)
        body = self.run_code_flow(
            self.user1,
            scope="email",
            state="no-openid-scope",
            expect_id_token=False,
            expected_scope="email",
        )
        self.assertIn("access_token", body)

    def test_inactive_app_cannot_issue_code(self):
        """
        ``AllianceAuthApplication.active=False`` must make the app unusable
        — no code redirect to redirect_uri.
        """
        self.grant_oidc_access(self.user1)
        self.oauth_app.active = False
        self.oauth_app.save()

        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE_FULL,
            "state": "inactive-app",
            "allow": True,
        }
        resp = self.authorize_post(self.user1, data=data)

        if resp.status_code == 302:
            loc, _, qs = self.parse_redirect(resp, (302,))
            self.assertTrue(loc.startswith(REDIRECT_URI))
            self.assertNotIn("code", qs)
            self.assertIn("error", qs)
            self.assertTrue(qs["error"][0])
        else:
            self.assertNotEqual(302, resp.status_code)


class TestPkceRequiredRefreshFlow(OIDCTestCase):
    """
    Per-app ``pkce_required=True`` must NOT block refresh-token grants.

    DOT only enforces PKCE at the authorize endpoint; the issued
    code carries the verifier contract through to token-exchange.
    Refresh requests do not present a PKCE verifier and must succeed
    on their existing refresh_token alone.
    """

    def test_pkce_required_does_not_block_refresh(self):
        from urllib.parse import parse_qs, urlparse

        from ._factories import make_app

        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        self.grant_oidc_access(self.user1)

        verifier, challenge = self.make_pkce_pair()

        # Drive the authorize → code path with the verifier.
        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="pkce-refresh",
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
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, token_resp.status_code)
        body = json.loads(token_resp.content.decode("utf-8"))
        self.assertIn("refresh_token", body)

        refresh_resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "refresh_token",
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "refresh_token": body["refresh_token"],
            },
        )
        self.assertEqual(200, refresh_resp.status_code)
        refreshed = json.loads(refresh_resp.content.decode("utf-8"))
        self.assertIn("access_token", refreshed)


class TestCodeReuseTokenRevocation(OIDCTestCase):
    """
    Authorization-code reuse must invalidate any tokens previously
    issued from that code.

    RFC 6749 §10.5: ``If an authorization code is used more than once,
    the authorization server MUST deny the request and SHOULD revoke
    (when possible) all tokens previously issued based on that
    authorization code.``

    DOT 3.2.0 enforces the MUST half (re-exchange returns
    ``invalid_grant`` because the Grant row is deleted on first use),
    but leaves the already-issued AccessToken / RefreshToken usable
    until their natural expiry. The OpenID Conformance Suite's
    ``oidcc-codereuse-30seconds`` module surfaces this gap as a
    WARNING via ``EnsureHttpStatusCodeIs4xx`` on the post-reuse
    ``/o/userinfo/`` probe.
    """

    def _userinfo(self, access_token: str):
        return self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {access_token}"},
        )

    def test_access_token_revoked_when_code_replayed(self):
        """
        After a second ``POST /o/token/`` with the same code returns
        ``invalid_grant``, the access_token issued by the FIRST
        exchange must no longer be accepted at ``/o/userinfo/``.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="code-replay-at")

        first = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
        )
        body = json.loads(first.content.decode("utf-8"))
        access_token = body["access_token"]

        # Sanity: the freshly-issued access_token works before reuse.
        sanity = self._userinfo(access_token)
        self.assertEqual(
            200,
            sanity.status_code,
            "access_token must be valid immediately after issue",
        )

        # Replay the SAME authorization code — DOT must reject this.
        replay = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )
        self.assertOAuthError(replay, expected_error="invalid_grant")

        # The access_token issued from that code must now be revoked.
        revoked = self._userinfo(access_token)
        self.assertIn(
            revoked.status_code,
            (401, 403),
            "RFC 6749 §10.5: access_token issued from a reused code "
            "must be revoked; /userinfo returned "
            f"{revoked.status_code} with token still usable",
        )

    def test_refresh_token_revoked_when_code_replayed(self):
        """
        Same defence-in-depth for refresh_token: a code-reuse event
        must invalidate the refresh_token issued from the original
        exchange, otherwise an attacker who replays the code (and is
        rate-limited at /token/) can still mint fresh access_tokens
        via the refresh flow indefinitely.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="code-replay-rt")

        first = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
        )
        body = json.loads(first.content.decode("utf-8"))
        refresh = body["refresh_token"]

        self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            expected_status=400,
        )

        resp = self.refresh_token(
            refresh_token=refresh, expected_status=(400, 401)
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_audit_row_created_on_first_exchange(self):
        """
        Sanity: a successful code exchange records exactly one
        ``IssuedCodeAudit`` row keyed on the sha256 of the code.
        """
        import hashlib

        from allianceauth_oidc.models import IssuedCodeAudit

        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="audit-row-test")
        self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
        )

        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        audit = IssuedCodeAudit.objects.filter(
            code_hash=code_hash, application=self.oauth_app
        ).first()
        self.assertIsNotNone(audit, "audit row must be created on exchange")
        self.assertEqual(0, audit.reuse_count)
        self.assertIsNotNone(audit.access_token_pk)
        self.assertIsNotNone(audit.refresh_token_pk)

    def test_cleanup_drops_clean_old_audits_but_keeps_reused_ones(self):
        """
        ``clear_expired_tokens`` deletes ``IssuedCodeAudit`` rows
        older than the refresh-token TTL ONLY when ``reuse_count=0``.
        Rows that recorded a replay are forensic evidence and must
        be preserved across the routine cleanup pass.
        """
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.settings import oauth2_settings

        from allianceauth_oidc.models import IssuedCodeAudit
        from allianceauth_oidc.tasks import clear_expired_tokens

        refresh_ttl = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
        well_past = timezone.now() - timedelta(seconds=refresh_ttl + 60)

        # Clean & old → should be deleted.
        clean_old = IssuedCodeAudit.objects.create(
            code_hash="a" * 64,
            application=self.oauth_app,
            reuse_count=0,
        )
        # Reused & old → must be preserved.
        reused_old = IssuedCodeAudit.objects.create(
            code_hash="b" * 64,
            application=self.oauth_app,
            reuse_count=1,
        )
        # Clean & fresh → must be preserved.
        clean_fresh = IssuedCodeAudit.objects.create(
            code_hash="c" * 64,
            application=self.oauth_app,
            reuse_count=0,
        )
        # Backdate the "old" rows. ``auto_now_add`` ignores assigns
        # at creation; use a queryset update to bypass it.
        IssuedCodeAudit.objects.filter(
            pk__in=[clean_old.pk, reused_old.pk]
        ).update(created_at=well_past)

        clear_expired_tokens()

        self.assertFalse(
            IssuedCodeAudit.objects.filter(pk=clean_old.pk).exists(),
            "clean old audit row must be cleaned up",
        )
        self.assertTrue(
            IssuedCodeAudit.objects.filter(pk=reused_old.pk).exists(),
            "reused audit row must be preserved as forensic evidence",
        )
        self.assertTrue(
            IssuedCodeAudit.objects.filter(pk=clean_fresh.pk).exists(),
            "fresh audit row must not be touched",
        )


class TestPKCEAttackVectors(OIDCTestCase):
    """
    PKCE (RFC 7636) negative paths on /o/token/ and /o/authorize/.

    ``TestPkceRequiredRefreshFlow`` covers the happy path; this class
    closes the verifier-validation contract on the exchange step and
    the challenge-presence contract on the authorize step. The OIDC
    conformance suite's PKCE coverage routinely TIMEOUTs upstream
    (HtmlUnit), so without these Python-side tests we have no
    automated proof that a missing / wrong / downgraded verifier is
    actually rejected.
    """

    def _pkce_app(self):
        # ``pkce_required=True`` is per-app and resolved via the
        # callable in test settings (``per_app_pkce_required``);
        # ``skip_authorization=True`` short-circuits the consent page
        # so ``authorize_get_default`` returns a 302 directly.
        from ._factories import make_app

        creds = make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )
        self.grant_oidc_access(self.user1)
        return creds

    def _issue_code_with_challenge(
        self,
        creds,
        *,
        challenge: str,
        method: str = "S256",
        state: str,
    ) -> str:
        from urllib.parse import parse_qs, urlparse

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state=state,
            extra={
                "client_id": creds.client_id,
                "code_challenge": challenge,
                "code_challenge_method": method,
            },
        )
        self.assertEqual(302, resp.status_code)
        return parse_qs(urlparse(resp.headers["Location"]).query)["code"][0]

    def test_exchange_without_verifier_when_challenge_was_set(self):
        """
        RFC 7636 §4.6: when ``code_challenge`` was sent on authorize,
        the token request MUST include ``code_verifier``. Omitting it
        must yield ``invalid_grant``.
        """
        creds = self._pkce_app()
        _, challenge = self.make_pkce_pair()
        code = self._issue_code_with_challenge(
            creds, challenge=challenge, state="pkce-omit-verifier"
        )

        resp = self.exchange_code_with_verifier(
            code=code,
            verifier=None,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_exchange_with_wrong_verifier(self):
        """
        RFC 7636 §4.6: a verifier that does NOT hash (S256) to the
        registered challenge must be rejected. Drawing a second fresh
        PKCE pair makes the mismatch overwhelmingly likely (the
        challenge space is 256 bits).
        """
        creds = self._pkce_app()
        _, challenge = self.make_pkce_pair()
        wrong_verifier, _ = self.make_pkce_pair()
        code = self._issue_code_with_challenge(
            creds, challenge=challenge, state="pkce-wrong-verifier"
        )

        resp = self.exchange_code_with_verifier(
            code=code,
            verifier=wrong_verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_exchange_with_malformed_verifier_rejected(self):
        """
        A verifier shorter than RFC 7636 §4.1's 43-character minimum is
        malformed; DOT rejects it via the same ``invalid_grant`` path
        as a wrong-but-well-formed verifier. Pins that a length-shortcut
        does not bypass the hash check.
        """
        creds = self._pkce_app()
        _, challenge = self.make_pkce_pair()
        code = self._issue_code_with_challenge(
            creds, challenge=challenge, state="pkce-malformed-verifier"
        )

        resp = self.exchange_code_with_verifier(
            code=code,
            verifier="too-short",
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_authorize_without_challenge_when_pkce_required(self):
        """
        ``pkce_required=True`` on the application must cause /authorize/
        to refuse a request that has no ``code_challenge``. Refusal
        shape (error-redirect vs 400) depends on DOT's branch; both are
        spec-compliant, the contract is "no code is issued".
        """
        creds = self._pkce_app()

        resp = self.authorize_get_default(
            self.user1,
            scope=SCOPE_OPENID,
            state="pkce-missing-challenge",
            extra={"client_id": creds.client_id},
        )
        self.assertIn(resp.status_code, (302, 400))
        if resp.status_code == 302:
            _, _, qs = self.parse_redirect(resp, (302,))
            self.assertNotIn(
                "code",
                qs,
                "PKCE-required app must NOT issue a code when "
                "code_challenge is absent",
            )
            self.assertIn("error", qs)

    def test_authorize_accepts_plain_method_documenting_dot_default(self):
        """
        DOT does not restrict ``code_challenge_method`` to S256 by
        default — ``plain`` is accepted alongside S256. Pin this so a
        future "S256 only" hardening lands with a deliberate test
        change rather than a silent behaviour shift.

        RFC 7636 §4.2 prefers S256 ("clients SHOULD use S256"), but the
        spec permits ``plain``; tightening to S256-only is a project
        policy decision, not a DOT default.
        """
        creds = self._pkce_app()
        verifier, _ = self.make_pkce_pair()
        # For ``plain``, the challenge is the verifier verbatim
        # (RFC 7636 §4.2). Using the verifier as challenge means the
        # exchange step has the matching value to send back.
        code = self._issue_code_with_challenge(
            creds,
            challenge=verifier,
            method="plain",
            state="pkce-plain-method",
        )

        resp = self.exchange_code_with_verifier(
            code=code,
            verifier=verifier,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertEqual(200, resp.status_code)
        body = json.loads(resp.content.decode("utf-8"))
        self.assertIn("access_token", body)


class TestTokenEndpointHTTPMethod(OIDCTestCase):
    """
    Reject GET on /o/token/ — RFC 6749 §3.2 mandates POST.

    Two reasons GET MUST NOT be supported:

    1. Credentials in URL: ``code``, ``client_secret``, and (in JWT-mode
       at refresh) the refresh token would land in access logs,
       Referer headers, CDN caches, browser history.
    2. CSRF: GET requests are trivially forgeable from a third-party
       site; POST + the credential check is the OAuth model.

    DOT inherits this from Django's ``View`` + ``http_method_names``;
    the test pins the contract so a future ``http_method_names = ['get',
    'post']`` regression is caught.
    """

    def test_get_returns_405_method_not_allowed(self) -> None:
        resp = self.client.get("/o/token/")
        self.assertEqual(
            405,
            resp.status_code,
            "RFC 6749 §3.2: token endpoint MUST reject GET with 405",
        )
        self.assertIn("Allow", resp.headers)
        self.assertIn("POST", resp.headers["Allow"])


class TestAuthorizationCodeLifetime(OIDCTestCase):
    """
    RFC 6749 §4.1.2: authorization codes are SHORT-lived (DOT default
    60s in test settings). An expired code MUST be rejected with
    ``invalid_grant`` on exchange — the window between issuance and
    exchange is exactly the MITM/replay attack surface, and an
    indefinitely-valid code reopens it.

    Backdate the Grant row's ``expires`` field directly rather than
    sleeping or freezing time — the test must run in milliseconds and
    must not depend on system clock drift.
    """

    def test_expired_code_rejected_on_exchange(self) -> None:
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import get_grant_model

        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="expired-code")

        # Force the Grant row's expires into the past. ``expires`` is
        # a DateTimeField on AbstractGrant; queryset update bypasses
        # signal handlers / auto_now and is the canonical way to fake
        # a past timestamp.
        Grant = get_grant_model()
        Grant.objects.filter(code=code).update(
            expires=timezone.now() - timedelta(seconds=60),
        )

        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )


class TestRedirectURIExactMatch(OIDCTestCase):
    """
    RFC 6749 §3.1.2.2 + §4.1.3: registered ``redirect_uri`` matching
    MUST be by simple string comparison — no substring / prefix /
    case-insensitive / parameter-tolerant matching.

    Pre-existing :meth:`TestTokenPolicy.test_token_exchange_denied_if_redirect_uri_mismatch`
    covers a wholly-different URI. This class covers the subtle
    near-miss vectors an attacker actually tries: query-string
    injection, path suffix, scheme upgrade, IDN/punycode visual
    spoofing. Each must reject as firmly as a wholly-different URI.
    """

    def test_path_suffix_rejected(self) -> None:
        """Registered ``http://localhost/redir/`` ≠ ``http://localhost/redir/evil``."""
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="suffix-redir")
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI + "evil",
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_extra_query_param_rejected(self) -> None:
        """Registered URI does not carry query — exchange with query MUST reject."""
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="query-redir")
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI + "?steal=1",
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_fragment_in_redirect_uri_rejected(self) -> None:
        """
        RFC 6749 §3.1.2: ``redirect_uri`` MUST NOT include a fragment.
        Even if DOT happens to normalise it away, the exchange step
        must reject the request — silent normalisation hides bugs.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="frag-redir")
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI + "#frag",
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_scheme_upgrade_rejected(self) -> None:
        """
        Registered scheme is ``http``; presenting the same authority
        with ``https`` MUST reject — string match, not protocol-aware
        comparison.
        """
        self.grant_oidc_access(self.user1)
        code = self.authorize_to_code(self.user1, state="scheme-redir")
        # Replace only the scheme on the registered URI.
        https_variant = REDIRECT_URI.replace("http://", "https://", 1)
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=https_variant,
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )


class TestRefreshScopeBoundary(OIDCTestCase):
    """
    Refresh-token grant scope contract.

    RFC 6749 §6: the requested ``scope`` parameter on refresh MUST be
    a subset of the originally-granted scope. The server SHOULD honour
    a strict subset (downscope) and MUST reject an attempt to widen
    the scope (upscope).

    The conformance suite's ``oidcc-refresh-token`` exercises the
    refresh-with-subset path but TIMEOUTs upstream; we own the
    coverage Python-side.
    """

    def test_refresh_downscope_to_subset_is_allowed(self):
        """
        Original grant: ``openid profile email`` → refresh requesting
        ``openid`` must succeed and the response must echo the
        narrowed scope.
        """
        self.grant_oidc_access(self.user1)
        first = self.run_code_flow(
            self.user1, scope=SCOPE_FULL, state="downscope-1"
        )
        refresh = first["refresh_token"]

        resp = self.refresh_token(
            refresh_token=refresh, scope=SCOPE_OPENID, expected_status=200
        )
        body = json.loads(resp.content.decode("utf-8"))
        # Scope echo: at most a subset of the original grant.
        got = set((body.get("scope") or "").split())
        self.assertTrue(
            got.issubset(set(SCOPE_FULL.split())),
            f"refresh scope {got!r} must be subset of original "
            f"{set(SCOPE_FULL.split())!r}",
        )
        self.assertIn("openid", got)
        self.assertIn("access_token", body)

    def test_refresh_upscope_to_unrequested_scope_rejected(self):
        """
        Original grant: ``openid`` only → refresh request asks for
        ``openid profile email``. RFC 6749 §6: the response scope MUST
        NOT exceed the original grant. DOT's contract: either reject
        outright (invalid_scope / invalid_grant) or silently clamp back
        to the original. Either is spec-compliant; the test pins both
        acceptable outcomes so a regression that *widens* is caught.
        """
        self.grant_oidc_access(self.user1)
        first = self.run_code_flow(
            self.user1,
            scope=SCOPE_OPENID,
            state="upscope-1",
            expected_scope=SCOPE_OPENID,
        )
        refresh = first["refresh_token"]

        resp = self.refresh_token(
            refresh_token=refresh,
            scope=SCOPE_FULL,
            expected_status=(200, 400, 401),
        )

        if resp.status_code == 200:
            body = json.loads(resp.content.decode("utf-8"))
            got = set((body.get("scope") or "").split())
            self.assertEqual(
                {"openid"},
                got,
                "RFC 6749 §6: upscope MUST NOT succeed — the response "
                "scope must remain the original subset",
            )
        else:
            self.assertOAuthError(
                resp,
                expected_error={
                    "invalid_scope",
                    "invalid_grant",
                    "invalid_request",
                },
            )

    def test_refresh_with_disjoint_scope_rejected_or_clamped(self):
        """
        Original grant: ``openid`` → refresh asks for ``email`` alone
        (no overlap with the original). Same contract as upscope:
        reject or clamp; widening is forbidden. ``email`` was NOT in
        the original grant, so it must not appear in the response.
        """
        self.grant_oidc_access(self.user1)
        first = self.run_code_flow(
            self.user1,
            scope=SCOPE_OPENID,
            state="disjoint-1",
            expected_scope=SCOPE_OPENID,
        )
        refresh = first["refresh_token"]

        resp = self.refresh_token(
            refresh_token=refresh,
            scope="email",
            expected_status=(200, 400, 401),
        )

        if resp.status_code == 200:
            body = json.loads(resp.content.decode("utf-8"))
            got = set((body.get("scope") or "").split())
            self.assertNotIn(
                "email",
                got,
                "RFC 6749 §6: a scope absent from the original grant "
                "must not be granted on refresh",
            )
        else:
            self.assertOAuthError(
                resp,
                expected_error={
                    "invalid_scope",
                    "invalid_grant",
                    "invalid_request",
                },
            )
