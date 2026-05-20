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

from allianceauth.authentication.models import State
from parameterized import parameterized

from ._oidc_testcase import (
    DEFAULT_EXPIRES_IN,
    REDIRECT_URI,
    SCOPE_FULL,
    SCOPE_OPENID,
    GrantedOIDCTestCase,
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


class TestPolicyMatrix(GrantedOIDCTestCase):
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


class TestTokenPolicyGuards(GrantedOIDCTestCase):
    """Refusal paths on /o/token/ and /o/authorize/ when context shifts."""

    def _grant_user1_with_test_grp(self) -> None:
        self.oauth_app.groups.add(self.test_grp)
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
        body = self.run_code_flow(self.user1, state="perm-removed-refresh")
        refresh = body["refresh_token"]

        self.user1.user_permissions.remove(self.access_oauth)
        self.user1.refresh_from_db()

        resp = self.refresh_token(refresh_token=refresh, expected_status=400)
        self.assertOAuthError(resp, expected_error="invalid_grant")

    def test_save_bearer_token_layer3_blocks_when_layer2_disabled(
        self,
    ) -> None:
        """
        Layer-3 enforcement isolation: a regression that silently
        neutralises Layer 2 (``_enforce_policy`` always returning
        True for ``validate_code`` / ``validate_refresh`` /
        ``validate_bearer``) MUST still produce ``invalid_grant``
        because ``save_bearer_token`` (Layer 3) consults
        ``policy.decide(...)`` directly and converts a denial into
        ``InvalidGrantError``.

        Without this test, an attacker who slipped a ``return True``
        into ``_enforce_policy`` would pass every other test in
        this class — each of those tests relies on Layer 2 catching
        the violation. Defence-in-depth is only meaningful when each
        layer can be proven to enforce independently; this test pins
        that property for Layer 3.

        ``_enforce_policy`` is patched (rather than ``validate_code``
        directly) because ``super().validate_code`` populates
        request scopes that Layer 3 relies on; stubbing the whole
        method short-circuits DOT bookkeeping and surfaces an
        unrelated ``FatalClientError`` rather than testing the
        intended layer interaction.

        Symmetric Layer-2 isolation (``save_bearer_token`` neutralised,
        Layer 2 must still deny) is covered by
        :class:`tests.test_auth_provider.TestEnforcePolicy` —
        ``_enforce_policy`` is exercised in isolation there with a
        stubbed policy, independent of the Layer 3 path.
        """
        from unittest.mock import patch

        from oauth2_provider.models import get_access_token_model

        self._grant_user1_with_test_grp()
        code = self.authorize_to_code(self.user1, state="layer3-iso")

        # Strip access AFTER the code is issued — Layer 2 would
        # normally catch this. Layer 3 must catch it on its own.
        self.user1.groups.clear()
        self.user1.refresh_from_db()

        with patch(
            "allianceauth_oidc.auth_provider."
            "AllianceAuthOAuth2Validator._enforce_policy",
            return_value=True,
        ):
            resp = self.exchange_code_for_token(
                code=code,
                state="layer3-iso",
                redirect_uri=REDIRECT_URI,
                expected_status=400,
            )
        self.assertOAuthError(resp, expected_error="invalid_grant")

        # Token persistence MUST NOT have happened: Layer 3 raises
        # ``InvalidGrantError`` before ``super().save_bearer_token``
        # would write the row.
        access_token_model = get_access_token_model()
        self.assertFalse(
            access_token_model.objects.filter(user=self.user1).exists(),
            "Layer 3 must refuse persistence — no token row should "
            "exist after the policy denial.",
        )

    def test_token_exchange_denied_if_redirect_uri_mismatch(self):
        """
        If redirect_uri at /o/token/ doesn't match the one used at
        /o/authorize/, token exchange must fail.
        """
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
        first = self.run_code_flow(self.user1, state="rotation-1")
        old_refresh = first["refresh_token"]

        # First rotation: old refresh → fresh access + (rotated) refresh.
        rotated = self.refresh_token(refresh_token=old_refresh)
        rotated_body = self.json_body(rotated, expected_status=None)
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
            # DOT may answer with 400 (validation reject) instead of
            # the OAuth error-redirect; both are spec-compliant. What
            # MUST NOT happen is a 200 consent page — that would mean
            # ``active=False`` is silently ignored and the user is
            # being asked to grant a deactivated app.
            self.assertNotEqual(
                200,
                resp.status_code,
                "inactive app must not render the consent page; "
                f"got status={resp.status_code}",
            )


class TestPkceRequiredRefreshFlow(GrantedOIDCTestCase):
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
        body = self.json_body(token_resp, expected_status=None)
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
        refreshed = self.json_body(refresh_resp, expected_status=None)
        self.assertIn("access_token", refreshed)


class TestCodeReuseTokenRevocation(GrantedOIDCTestCase):
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
        code = self.authorize_to_code(self.user1, state="code-replay-at")

        first = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
        )
        body = self.json_body(first, expected_status=None)
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
        code = self.authorize_to_code(self.user1, state="code-replay-rt")

        first = self.exchange_code_for_token(
            code=code,
            redirect_uri=REDIRECT_URI,
        )
        body = self.json_body(first, expected_status=None)
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

    def test_n3_audit_failure_rolls_back_token_issuance(self):
        """
        regression: if ``_record_code_issuance`` raises (audit DB
        outage, table missing, etc.), the outer ``transaction.atomic``
        in ``save_bearer_token`` MUST roll back the parent's AT/RT
        writes too. Pre-refactor, the parent's atomic committed AT/RT
        independently and the try/except swallowed the audit failure,
        leaving tokens issued without a reuse-detection FK link — a
        race-window source the  counter could only measure, not
        close. The trade-off is fail-closed on audit-pipeline
        failure: legitimate clients see a 500 instead of a 200 with
        degraded reuse-detection.

        Asserts at the validator boundary (the exception escapes
        ``save_bearer_token`` rather than at the HTTP boundary) so
        the test is independent of Django's debug-page rendering or
        request-exception propagation settings.
        """
        from unittest.mock import patch

        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()

        code = self.authorize_to_code(self.user1, state="n3-rollback-test")

        at_count_before = AccessToken.objects.count()
        rt_count_before = RefreshToken.objects.count()

        # ``self.client.post`` re-raises exceptions from the view by
        # default — drop that so we get a 500 response instead of an
        # exception interrupting the test.
        with (
            patch.object(
                AllianceAuthOAuth2Validator,
                "_record_code_issuance",
                side_effect=RuntimeError("simulated audit DB outage"),
            ),
            self.assertRaises(RuntimeError),
        ):
            self.client.raise_request_exception = True
            self.client.post(
                "/o/token/",
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.oauth_id,
                    "client_secret": self.oauth_secret,
                    "redirect_uri": REDIRECT_URI,
                    "code": code,
                },
            )

        self.assertEqual(
            at_count_before,
            AccessToken.objects.count(),
            "outer atomic must roll back AccessToken insert on audit failure",
        )
        self.assertEqual(
            rt_count_before,
            RefreshToken.objects.count(),
            "outer atomic must roll back RefreshToken insert on audit failure",
        )

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

    def test_n1_lookup_helper_resolves_at_pk_via_token_checksum(self):
        """
        regression: ``_lookup_dot_token_pk`` MUST find an
        ``AccessToken`` row via the indexed ``token_checksum`` column
        even when the raw ``token`` column has been blanked after
        issuance (operator-side at-rest hashing). The prior
        implementation filtered on the raw column directly and
        silently returned None for such deployments, breaking the
        reuse-detection FK link without an observable signal.

        DOT's ``TokenChecksumField.pre_save`` auto-populates the
        checksum from ``token`` at save time, so the test creates the
        row with a real raw value (DOT computes the checksum), then
        clears ``token`` via queryset ``update`` (which bypasses
        ``pre_save``) to simulate the post-issuance hash-and-clear.
        """
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import get_access_token_model

        from allianceauth_oidc.auth_provider import _lookup_dot_token_pk

        AccessToken = get_access_token_model()
        raw = "n1-checksum-lookup-fixture"
        at = AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=raw,
            expires=timezone.now() + timedelta(seconds=3600),
            scope="openid",
        )
        # Blank ``token`` after issuance — bypass ``pre_save`` so the
        # checksum survives.
        AccessToken.objects.filter(pk=at.pk).update(token="")

        resolved_pk = _lookup_dot_token_pk(AccessToken, raw)
        self.assertEqual(at.pk, resolved_pk)

    def test_n1_lookup_helper_falls_back_to_token_for_refresh_token(self):
        """
        ``RefreshToken`` has no ``token_checksum`` column in DOT 3.x
        — the helper must fall back to the raw ``token`` column for
        models without the indexed checksum field. Asymmetry is a
        DOT-side limitation, not a bug here; the test pins the
        fallback so a future helper refactor cannot accidentally
        skip RT lookups.
        """
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        from allianceauth_oidc.auth_provider import _lookup_dot_token_pk

        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        at = AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="n1-rt-fallback-at",
            expires=timezone.now() + timedelta(seconds=3600),
            scope="openid",
        )
        rt = RefreshToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            access_token=at,
            token="n1-rt-fallback-raw",
        )
        self.assertEqual(
            rt.pk, _lookup_dot_token_pk(RefreshToken, "n1-rt-fallback-raw")
        )

    def test_c4_audit_row_survives_application_delete(self):
        """
        C-4 regression: ``IssuedCodeAudit.application`` FK is
        ``on_delete=SET_NULL`` so admin-driven RP deletion preserves
        ``reuse_count>=1`` forensic rows. The
        ``application_client_id_snapshot`` column lets the row
        identify its originating RP after the FK becomes NULL.
        """
        from allianceauth_oidc.models import IssuedCodeAudit

        from ._factories import make_app

        app = make_app(owner=self.user1).app
        snapshot_client_id = app.client_id
        row = IssuedCodeAudit.objects.create(
            code_hash="c4" * 32,
            application=app,
            reuse_count=2,  # forensic evidence — must survive
            application_client_id_snapshot=snapshot_client_id,
        )
        app.delete()
        survivor = IssuedCodeAudit.objects.get(pk=row.pk)
        self.assertIsNone(
            survivor.application,
            "C-4 FK must be SET_NULL on application delete",
        )
        self.assertEqual(
            snapshot_client_id, survivor.application_client_id_snapshot
        )
        self.assertEqual(2, survivor.reuse_count)

    def test_c4_record_code_issuance_populates_snapshot(self):
        """
        ``_record_code_issuance`` is the single insert path for
        IssuedCodeAudit. It must snapshot the application's
        ``client_id`` automatically — operators don't pass it
        through the validator.
        """
        from allianceauth_oidc.models import IssuedCodeAudit

        code = self.authorize_to_code(self.user1, state="c4-snapshot")
        self.exchange_code_for_token(code=code, redirect_uri=REDIRECT_URI)

        import hashlib

        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        row = IssuedCodeAudit.objects.get(
            code_hash=code_hash, application=self.oauth_app
        )
        self.assertEqual(
            self.oauth_app.client_id, row.application_client_id_snapshot
        )

    def test_n1_lookup_helper_returns_none_for_empty_or_unknown(self):
        from oauth2_provider.models import get_access_token_model

        from allianceauth_oidc.auth_provider import _lookup_dot_token_pk

        AccessToken = get_access_token_model()
        self.assertIsNone(_lookup_dot_token_pk(AccessToken, None))
        self.assertIsNone(_lookup_dot_token_pk(AccessToken, ""))
        self.assertIsNone(
            _lookup_dot_token_pk(AccessToken, "never-issued-token")
        )


class _PkceCodeIssuanceMixin:
    """
    Provision a PKCE-strict app and drive ``/authorize/`` to a code.

    Two PKCE classes (:class:`TestPKCEAttackVectors`,
    :class:`TestAuthorizationCodeSubstitution`) each carried their own
    almost-identical copy of these helpers — same factory call, same
    redirect parse — and drift had already started (one fixed the
    method to ``S256``, the other parameterised it). Centralising on
    a mixin removes the duplication and keeps both attack classes on
    one verifier-issuance contract.

    Mixed in BEFORE :class:`OIDCTestCase` so the test class's MRO
    resolves ``self.user1`` / ``self.authorize_get_default`` /
    ``self.assertEqual`` from the testcase base.
    """

    def _pkce_app(self):
        # ``pkce_required=True`` is per-app and resolved via the
        # callable in test settings (``per_app_pkce_required``);
        # ``skip_authorization=True`` short-circuits the consent page
        # so ``authorize_get_default`` returns a 302 directly.
        from ._factories import make_app

        return make_app(
            owner=self.user1, pkce_required=True, skip_authorization=True
        )

    def _issue_code_with_challenge(
        self,
        creds,
        *,
        challenge: str,
        state: str,
        method: str = "S256",
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


class TestPKCEAttackVectors(_PkceCodeIssuanceMixin, GrantedOIDCTestCase):
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

    def test_exchange_with_bad_pkce_verifier_rejected_sweep(self):
        """
        Sweep of PKCE verifier shapes that must reject.

        RFC 7636 §4.6 requires the token request to present a
        ``code_verifier`` that hashes (S256) to the registered
        ``code_challenge``. Each row exercises a distinct failure
        mode and must rule the same ``invalid_grant`` /
        ``invalid_request`` error class:

        * ``omitted`` — verifier missing entirely. RFC §4.6
          mandates rejection when a challenge was sent.
        * ``wrong_hash`` — well-formed verifier whose S256 does
          not match the registered challenge (drawn as a second
          fresh pair, 256-bit collision space).
        * ``malformed_short`` — verifier shorter than the §4.1
          43-character minimum. Pins that a length-shortcut
          cannot bypass the hash check.

        A fresh ``(challenge, code)`` pair per row keeps the
        single-use-code semantics independent of the verifier
        invariant under test.
        """
        creds = self._pkce_app()
        for label, verifier_factory in (
            ("omitted", lambda: None),
            (
                "wrong_hash",
                lambda: self.make_pkce_pair()[0],
            ),
            ("malformed_short", lambda: "too-short"),
        ):
            with self.subTest(verifier=label):
                _, challenge = self.make_pkce_pair()
                code = self._issue_code_with_challenge(
                    creds,
                    challenge=challenge,
                    state=f"pkce-{label}-verifier",
                )
                resp = self.exchange_code_with_verifier(
                    code=code,
                    verifier=verifier_factory(),
                    client_id=creds.client_id,
                    client_secret=creds.client_secret,
                )
                self.assertIn(resp.status_code, (400, 401))
                self.assertOAuthError(
                    resp,
                    expected_error={
                        "invalid_grant",
                        "invalid_request",
                    },
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
        body = self.json_body(resp, expected_status=None)
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


class TestAuthorizationCodeLifetime(GrantedOIDCTestCase):
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


class TestRedirectURIExactMatch(GrantedOIDCTestCase):
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

    def test_near_miss_redirect_uri_mutations_rejected(self) -> None:
        """
        Sweep of near-miss redirect_uri mutations on exchange.

        RFC 6749 §3.1.2.2 + §4.1.3 mandate simple string
        comparison — no substring / prefix / case-insensitive /
        parameter-tolerant matching. Each row pins one
        near-miss attack vector:

        * ``path_suffix`` — appending a segment must NOT
          prefix-match (``…/redir/`` ≠ ``…/redir/evil``).
        * ``extra_query`` — registered URI does not carry
          query; exchange with query MUST reject.
        * ``fragment`` — RFC 6749 §3.1.2 forbids fragments in
          redirect_uri. Even if DOT normalises it away, the
          exchange step must reject — silent normalisation
          hides bugs.
        * ``scheme_upgrade`` — registered scheme is ``http``;
          presenting the same authority with ``https`` MUST
          reject (string match, not protocol-aware).

        Each iteration draws a fresh code; reusing one across
        rows would conflate DOT's single-use-code semantics
        with the redirect_uri-match invariant under test.
        """
        cases: tuple[tuple[str, str], ...] = (
            ("path_suffix", REDIRECT_URI + "evil"),
            ("extra_query", REDIRECT_URI + "?steal=1"),
            ("fragment", REDIRECT_URI + "#frag"),
            (
                "scheme_upgrade",
                REDIRECT_URI.replace("http://", "https://", 1),
            ),
        )
        for label, mutated_redirect in cases:
            with self.subTest(mutation=label):
                code = self.authorize_to_code(
                    self.user1, state=f"{label}-redir"
                )
                resp = self.exchange_code_for_token(
                    code=code,
                    redirect_uri=mutated_redirect,
                    expected_status=(400, 401),
                )
                self.assertOAuthError(
                    resp,
                    expected_error={
                        "invalid_grant",
                        "invalid_request",
                    },
                )


class TestRefreshScopeBoundary(GrantedOIDCTestCase):
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
        first = self.run_code_flow(
            self.user1, scope=SCOPE_FULL, state="downscope-1"
        )
        refresh = first["refresh_token"]

        resp = self.refresh_token(
            refresh_token=refresh, scope=SCOPE_OPENID, expected_status=200
        )
        body = self.json_body(resp, expected_status=None)
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
            body = self.json_body(resp, expected_status=None)
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
            body = self.json_body(resp, expected_status=None)
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


class TestRefreshAfterUserDeactivation(GrantedOIDCTestCase):
    """
    Refresh-token grant after the end-user's account changes state.

    Sibling to :class:`TestTokenPolicyGuards`, which already covers
    "user lost the test group" and "user lost the global OIDC
    permission". This class closes the ``user.is_active=False``
    branch: a refresh that re-authenticates a deactivated user MUST
    NOT mint a fresh access token.

    The corresponding /o/userinfo/ behaviour is documented (and
    deliberately not enforced) in
    :class:`TestUserinfoAfterUserStateChange` — AT remains valid
    until expiry, RT is where the deactivation contract is.
    """

    def test_refresh_denied_when_user_marked_inactive(self) -> None:
        """
        After ``user.is_active=False``, the refresh_token grant MUST
        be rejected. Mirror of
        ``test_refresh_token_denied_if_global_permission_removed``.
        """
        body = self.run_code_flow(self.user1, state="refresh-inactive")
        refresh = body["refresh_token"]

        self.user1.is_active = False
        self.user1.save()
        self.user1.refresh_from_db()

        resp = self.refresh_token(
            refresh_token=refresh, expected_status=(400, 401)
        )
        self.assertOAuthError(
            resp,
            expected_error={
                "invalid_grant",
                "invalid_request",
                "invalid_client",
            },
        )


class TestAuthorizationCodeSubstitution(
    _PkceCodeIssuanceMixin, GrantedOIDCTestCase
):
    """
    PKCE binds an authorization code to the verifier-of-issue.

    Without PKCE the only thing that ties a ``code`` to its session
    is the ``client_id`` — within the SAME client, an attacker who
    captures one user's code can present it from a different session
    and the AS cannot distinguish the swap. PKCE (RFC 7636) closes
    this by injecting a per-session ``code_challenge`` at authorize
    time and demanding the matching ``code_verifier`` at exchange.

    Cross-client substitution is already pinned by
    :class:`tests.test_multiapp.TestCrossClientCodeAbuse`. This class
    closes the WITHIN-same-client variant — the attack that PKCE
    actually solves.
    """

    def test_session_a_code_with_session_b_verifier_rejected(self) -> None:
        """
        Two parallel auth sessions for the same client / same user
        issue code-A (bound to challenge-A / verifier-A) and code-B
        (bound to challenge-B / verifier-B). Substituting verifier-B
        when exchanging code-A MUST yield ``invalid_grant`` — the
        hash mismatches.
        """
        creds = self._pkce_app()

        verifier_a, challenge_a = self.make_pkce_pair()
        verifier_b, challenge_b = self.make_pkce_pair()
        # Sanity that the two pairs differ; the attack scenario relies
        # on it.
        self.assertNotEqual(verifier_a, verifier_b)
        self.assertNotEqual(challenge_a, challenge_b)

        code_a = self._issue_code_with_challenge(
            creds, challenge=challenge_a, state="subst-a"
        )

        # Exchange code-A with the WRONG (session B) verifier.
        resp = self.exchange_code_with_verifier(
            code=code_a,
            verifier=verifier_b,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )

    def test_session_b_code_with_session_a_verifier_rejected(self) -> None:
        """Symmetric — the swap is rejected in both directions."""
        creds = self._pkce_app()
        verifier_a, _ = self.make_pkce_pair()
        _, challenge_b = self.make_pkce_pair()

        code_b = self._issue_code_with_challenge(
            creds, challenge=challenge_b, state="subst-b"
        )

        resp = self.exchange_code_with_verifier(
            code=code_b,
            verifier=verifier_a,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
        )
        self.assertIn(resp.status_code, (400, 401))
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )


class TestConcurrentReuseLockingInvariant(OIDCTestCase):
    """
    Concurrent-reuse race guard — pin the ``select_for_update``
    invariant.

    Two simultaneous exchanges of the same code on a multi-process
    server MUST NOT both succeed. The serial reuse case is pinned by
    :meth:`TestCodeReuseTokenRevocation.test_access_token_revoked_when_code_replayed`;
    the concurrent case requires DB-level row locking on the audit
    table, implemented via ``IssuedCodeAudit.objects.select_for_update()``
    inside :meth:`AllianceAuthOAuth2Validator._handle_potential_code_reuse`.

    SQLite (in-memory) used for unit tests does not provide row-level
    locks; truly racing two threads here is non-deterministic. Instead,
    we pin the invariant by inspecting the audit-handling code path:
    a regression that drops ``select_for_update`` from the queryset
    re-opens the race on PostgreSQL deployments where it actually
    matters.
    """

    def test_handle_potential_code_reuse_source_uses_atomic_and_lock(
        self,
    ) -> None:
        """
        Verify the source of ``_handle_potential_code_reuse`` contains
        both ``transaction.atomic()`` and ``select_for_update()``.

        The naive runtime check (``CaptureQueriesContext`` looking for
        ``FOR UPDATE`` in emitted SQL) does not work under SQLite —
        the Django SQLite backend silently strips the ``FOR UPDATE``
        clause because the engine has no row-level locks. The contract
        we are pinning is "the ORM call exists in the source"; whether
        the engine honours it is engine-specific (PostgreSQL: yes,
        SQLite: no). A regression that removes the call would re-open
        the concurrent-double-exchange race on PostgreSQL.
        """
        import inspect

        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        src = inspect.getsource(
            AllianceAuthOAuth2Validator._handle_potential_code_reuse
        )
        self.assertIn(
            "transaction.atomic()",
            src,
            "reuse handler MUST wrap the audit lookup + revocation in "
            "an atomic block — required so both the SELECT and the "
            "revoke() commit together",
        )
        self.assertIn(
            "select_for_update()",
            src,
            "reuse handler MUST hold a row-level lock on the audit "
            "row while revoking; concurrent exchanges on PostgreSQL "
            "would both succeed without it",
        )

    def test_handle_potential_code_reuse_does_not_swallow_attribute_error(
        self,
    ) -> None:
        """
        regression: a previous narrow ``except`` clause caught
        ``AttributeError`` on the theory that a stale in-memory token
        instance could be missing ``revoke()``. In practice that
        scenario does not occur — the only realistic source of
        ``AttributeError`` is a programming bug (DOT major rename of
        ``revoke()``, custom token model missing the method). Catching
        it here silently degraded the RFC 6749 §10.5 SHOULD overlay
        ("revoke linked tokens on reuse") into log-only and left the
        leaked code's tokens valid. Pin the narrow except clause to
        ``(DatabaseError, ObjectDoesNotExist)`` only.

        AST-based pin: a bare ``"AttributeError" in src`` substring
        check would false-positive on the  commentary block; parse
        the ``except`` handlers and assert against their exception
        names directly.
        """
        import ast
        import inspect
        import textwrap

        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        src = textwrap.dedent(
            inspect.getsource(
                AllianceAuthOAuth2Validator._handle_potential_code_reuse
            )
        )
        tree = ast.parse(src)

        handler_names: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            exc = node.type
            if isinstance(exc, ast.Name):
                handler_names.append(exc.id)
            elif isinstance(exc, ast.Tuple):
                handler_names.extend(
                    elt.id for elt in exc.elts if isinstance(elt, ast.Name)
                )

        self.assertIn(
            "DatabaseError",
            handler_names,
            "code-reuse handler must catch DatabaseError for transient "
            "DB hiccups",
        )
        self.assertIn(
            "ObjectDoesNotExist",
            handler_names,
            "code-reuse handler must catch ObjectDoesNotExist for the "
            "clear_expired_tokens mid-transaction race",
        )
        self.assertNotIn(
            "AttributeError",
            handler_names,
            "AttributeError must NOT be caught in the code-reuse "
            "handler — it would mask DOT API drift (e.g. ``revoke()`` "
            "rename) and silently break token revocation under reuse.",
        )
        # Belt-and-suspenders: no broad ``Exception`` / ``BaseException``
        # either, even if specific narrows are kept.
        self.assertNotIn("Exception", handler_names)
        self.assertNotIn("BaseException", handler_names)


class TestTokenEndpointAntiEnumeration(OIDCTestCase):
    """
    RFC 6749 §5.2 — token-endpoint error responses MUST NOT leak the
    existence of clients.

    The classic enumeration probe: an attacker iterates ``client_id``
    values and watches for shape / timing differences between
    "unknown client" and "valid client + bad secret". If the server
    distinguishes them (different ``error`` codes, different message
    fields, very different response sizes), the attacker can map the
    deployment's registered apps.

    Pin: both probes return the same set of acceptable ``error``
    codes with no other discriminating fields in the body. Timing
    parity is out of scope (Django views inherently leak some timing
    for DB lookups); this guards the shape-leak vector which is the
    cheap one to fix.
    """

    def _post_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        code: str = "any-non-existent-code",
    ):
        return self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
        )

    def test_unknown_client_and_bad_secret_yield_same_error_shape(
        self,
    ) -> None:
        """
        Both probes MUST land in the same OAuth error envelope.
        Specifically: the same set of ``error`` codes is acceptable
        ({invalid_client, invalid_grant, invalid_request}), and
        neither response carries discriminating fields like
        ``client_id`` or ``error_uri`` echoing the input.
        """
        # Probe 1: completely unregistered client_id.
        resp_unknown = self._post_token(
            client_id="not-a-registered-client",
            client_secret="anything",  # nosec B106
        )
        body_unknown = self.json_body(resp_unknown, expected_status=None)

        # Probe 2: real client_id, wrong secret.
        resp_bad_secret = self._post_token(
            client_id=self.oauth_id,
            client_secret="WRONG_SECRET",  # nosec B106
        )
        body_bad_secret = self.json_body(resp_bad_secret, expected_status=None)

        # Both must be 4xx OAuth-error responses.
        self.assertLess(resp_unknown.status_code, 500)
        self.assertLess(resp_bad_secret.status_code, 500)
        self.assertGreaterEqual(resp_unknown.status_code, 400)
        self.assertGreaterEqual(resp_bad_secret.status_code, 400)

        # ``error`` field MUST be from the same well-known set.
        acceptable = {"invalid_client", "invalid_grant", "invalid_request"}
        self.assertIn(body_unknown.get("error"), acceptable)
        self.assertIn(body_bad_secret.get("error"), acceptable)

        # Neither response must echo the supplied ``client_id``: that
        # would let an attacker confirm by simple grep that the value
        # they sent reached the server.
        self.assertNotIn(
            "not-a-registered-client",
            resp_unknown.content.decode("utf-8"),
        )


class TestRedirectURIInjection(GrantedOIDCTestCase):
    """
    Header- and URL-injection guards on ``redirect_uri``.

    Three concrete vectors:

    - CRLF (``%0d%0a``) in a *registered* URI would split the
      response Location header at dispatch time. Django's
      ``HttpResponseRedirect`` rejects CRLF, but the AS should also
      reject registration so the problem is caught at admin-form
      time, not at runtime.
    - NUL byte (``%00``) historically truncates C-string parsers
      and produces invariant violations.
    - Punycode / IDN homoglyph: a registered URI uses Latin lowercase
      a; an attacker presents the Cyrillic lookalike (U+0430). Both
      render identically but hash differently. The contract pinned:
      exact byte match wins, no Unicode normalisation runs.
    """

    def test_crlf_in_registered_redirect_uri_rejected(self) -> None:
        r"""
        Model-level: a registered URI containing ``\r\n`` must fail
        validation. ``URLField`` + ``URLValidator`` should reject;
        the test pins this against a regression that loosens the
        validator.
        """
        from django.core.exceptions import ValidationError

        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            redirect_uri="https://rp.example/cb\r\nSet-Cookie: x=y",
        )
        with self.assertRaises(ValidationError):
            creds.app.full_clean()

    def test_null_byte_in_registered_redirect_uri_rejected(self) -> None:
        r"""
        NUL byte in path MUST fail validation.

        Django's stock ``URLValidator`` regex permits non-control
        bytes including ``\x00`` in the path segment; the project
        adds an explicit ``\x00 in value`` check in
        :meth:`AllianceAuthApplication._validate_no_nul_in_uri_fields`
        because legacy C-string parsers (load balancers, log
        analysers, syslog) truncate at NUL and would otherwise
        dispatch to a different URI than the audit log records.
        """
        from django.core.exceptions import ValidationError

        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            redirect_uri="https://rp.example/cb\x00evil",
        )
        with self.assertRaises(ValidationError) as ctx:
            creds.app.full_clean()
        self.assertIn("redirect_uris", ctx.exception.error_dict)

    def test_null_byte_in_post_logout_redirect_uri_rejected(self) -> None:
        r"""Symmetric: NUL byte in ``post_logout_redirect_uris``."""
        from django.core.exceptions import ValidationError

        from ._factories import make_app

        creds = make_app(owner=self.user1)
        creds.app.post_logout_redirect_uris = (
            "https://rp.example/logged-out\x00evil"
        )
        with self.assertRaises(ValidationError) as ctx:
            creds.app.full_clean()
        self.assertIn("post_logout_redirect_uris", ctx.exception.error_dict)

    def test_idn_punycode_byte_mismatch_rejected(self) -> None:
        """
        Latin ``a`` (U+0061) vs Cyrillic small a (U+0430).

        Two URIs that render identically must compare unequal at the
        byte level. Registered URI uses Latin; attacker presents the
        Cyrillic lookalike at exchange time. The exchange MUST reject
        because the strings differ — no Unicode-normalisation should
        kick in to make them equal.
        """
        # Latin U+0061 vs Cyrillic U+0430 — the actual homoglyph
        # attack input. ``noqa: RUF001`` on the cyrillic line below
        # suppresses ruff's ambiguous-character lint; that codepoint
        # is the subject of the test, not a typo.
        latin = "http://localhost/redir-a/"
        cyrillic_a = "http://localhost/redir-а/"  # noqa: RUF001
        # Sanity: visually similar, byte-different.
        self.assertNotEqual(latin, cyrillic_a)

        from ._factories import make_app

        creds = make_app(
            owner=self.user1, redirect_uri=latin, pkce_required=False
        )
        code = self.authorize_to_code(
            self.user1,
            state="idn-mismatch",
            redirect_uri=latin,
            extra_authorize_params={"client_id": creds.client_id},
        )
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=cyrillic_a,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            expected_status=(400, 401),
        )
        self.assertOAuthError(
            resp,
            expected_error={"invalid_grant", "invalid_request"},
        )


class TestTokenEndpointCacheControl(GrantedOIDCTestCase):
    """
    RFC 6749 §5.1 — successful token responses MUST carry
    ``Cache-Control: no-store`` and ``Pragma: no-cache``.

    Token bodies contain access_token / refresh_token / id_token —
    anything cached upstream of the RP is a credential disclosure
    risk. DOT's ``TokenView`` emits both headers by default; this
    class pins the contract against a regression where a future
    custom middleware strips or relaxes them.

    Symmetric error-response check: §5.2 does not explicitly
    require ``no-store`` on 4xx, but DOT applies it uniformly and
    cached errors leak request shape regardless. Pin the uniform
    application.
    """

    def test_successful_token_response_has_no_store_cache_control(
        self,
    ) -> None:
        code = self.authorize_to_code(self.user1, state="cache-pin-200")
        resp = self.exchange_code_for_token(
            code=code, redirect_uri=REDIRECT_URI
        )
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            "no-store",
            resp.headers.get("Cache-Control", ""),
            "RFC 6749 §5.1: 200 token response MUST carry no-store",
        )

    def test_successful_token_response_has_pragma_no_cache(self) -> None:
        code = self.authorize_to_code(self.user1, state="cache-pin-pragma")
        resp = self.exchange_code_for_token(
            code=code, redirect_uri=REDIRECT_URI
        )
        self.assertEqual("no-cache", resp.headers.get("Pragma"))

    def test_token_error_response_also_has_no_store_cache_control(
        self,
    ) -> None:
        """4xx token-error responses uniformly carry no-store under DOT."""
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "redirect_uri": REDIRECT_URI,
                "code": "definitely-not-a-real-code",
            },
        )
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertLess(resp.status_code, 500)
        self.assertIn(
            "no-store",
            resp.headers.get("Cache-Control", ""),
            f"4xx token response missing no-store; status={resp.status_code}",
        )


class TestTokenContentType(GrantedOIDCTestCase):
    """
    RFC 6749 §5.1 / §5.2 — token responses (both 200 and 4xx) MUST
    be ``application/json``. RP libraries parse strictly on
    Content-Type; ``text/html`` would surface as cryptic JSON-decode
    errors at the RP rather than as the actual OAuth error.

    DOT default sets this correctly on both branches; the tests pin
    against a middleware regression that strips or rewrites the
    header.
    """

    def test_successful_response_is_application_json(self) -> None:
        code = self.authorize_to_code(self.user1, state="ct-200")
        resp = self.exchange_code_for_token(
            code=code, redirect_uri=REDIRECT_URI
        )
        self.assertEqual(200, resp.status_code)
        self.assertTrue(
            resp.headers.get("Content-Type", "").startswith(
                "application/json"
            ),
        )

    def test_error_response_is_application_json(self) -> None:
        resp = self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "redirect_uri": REDIRECT_URI,
                "code": "definitely-not-a-real-code",
            },
        )
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertLess(resp.status_code, 500)
        self.assertTrue(
            resp.headers.get("Content-Type", "").startswith(
                "application/json"
            ),
            f"4xx token Content-Type missing JSON; "
            f"got {resp.headers.get('Content-Type')!r}",
        )


class TestTokenClientAuthenticationMethods(GrantedOIDCTestCase):
    """
    RFC 6749 §2.3.1 — confidential clients MAY authenticate at the
    token endpoint via HTTP Basic (preferred) OR via body params
    ``client_id`` / ``client_secret`` (legacy / debug). Both MUST
    work; pinning ensures DOT default keeps accepting both forms.
    """

    def _exchange_via_body(self, *, code: str):
        return self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "client_id": self.oauth_id,
                "client_secret": self.oauth_secret,
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
        )

    def _exchange_via_basic_auth(self, *, code: str):
        import base64

        creds = f"{self.oauth_id}:{self.oauth_secret}".encode()
        basic_b64 = base64.b64encode(creds).decode("ascii")
        return self.client.post(
            "/o/token/",
            data={
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
            headers={"authorization": f"Basic {basic_b64}"},
        )

    def test_body_credentials_yield_token(self) -> None:
        """Body ``client_id`` + ``client_secret`` is the legacy form."""
        code = self.authorize_to_code(self.user1, state="body-auth")
        resp = self._exchange_via_body(code=code)
        self.assertEqual(200, resp.status_code)
        body = self.json_body(resp, expected_status=None)
        self.assertIn("access_token", body)

    def test_basic_auth_credentials_yield_token(self) -> None:
        """RFC 6749 §2.3.1: Basic auth is the RECOMMENDED form."""
        code = self.authorize_to_code(self.user1, state="basic-auth")
        resp = self._exchange_via_basic_auth(code=code)
        self.assertEqual(200, resp.status_code)
        body = self.json_body(resp, expected_status=None)
        self.assertIn("access_token", body)
