import hashlib
import json
import os
import uuid
from base64 import b64encode, urlsafe_b64encode
from collections.abc import Callable
from http import HTTPStatus
from typing import Any, ClassVar, Final
from urllib.parse import parse_qs, urlparse

from allianceauth.authentication.models import (
    EveAllianceInfo,
    EveCharacter,
    EveCorporationInfo,
)
from django.contrib.auth.models import Group, Permission, User
from django.dispatch import Signal
from django.test import RequestFactory, TestCase
from oauth2_provider.settings import oauth2_settings

from allianceauth_oidc.constants import PERM_ACCESS_OIDC_CODENAME

from ._factories import (
    DEFAULT_REDIRECT_URI,
    make_alliance,
    make_app,
    make_character,
    make_corp,
    make_user,
)

# Default test fixtures — keep aligned with make_app() / make_user().
# ``REDIRECT_URI`` re-exports the factory's source-of-truth so
# legacy ``from ._oidc_testcase import REDIRECT_URI`` imports keep
# working without a circular import on the factory side.
REDIRECT_URI = DEFAULT_REDIRECT_URI
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "openid profile"
SCOPE_FULL = "openid profile email"

# Mounted provider endpoints — re-export the DOT URL conf overrides
# in ``allianceauth_oidc/urls.py``. Centralised so test files do
# not sprinkle literal paths that future remounts would have to
# chase across the suite.
DISCOVERY_URL: Final[str] = "/o/.well-known/openid-configuration/"
JWKS_URL: Final[str] = "/o/.well-known/jwks.json"
AUTHORIZE_URL: Final[str] = "/o/authorize/"
TOKEN_URL: Final[str] = "/o/token/"
INTROSPECT_URL: Final[str] = "/o/introspect/"
REVOKE_URL: Final[str] = "/o/revoke_token/"
USERINFO_URL: Final[str] = "/o/userinfo/"
# Read from DOT's resolved settings so a future change to
# ``OAUTH2_PROVIDER["ACCESS_TOKEN_EXPIRE_SECONDS"]`` in
# ``test_settingsAA4.py`` propagates here without a manual edit.
DEFAULT_EXPIRES_IN = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS

# All HTTP redirect statuses: 301 Moved Permanently, 302 Found,
# 303 See Other, 307 Temporary Redirect, 308 Permanent Redirect.
# Frozen so a typo like ``REDIRECT_STATUSES.add(...)`` fails fast.
REDIRECT_STATUSES: Final[frozenset[int]] = frozenset(
    {
        HTTPStatus.MOVED_PERMANENTLY,
        HTTPStatus.FOUND,
        HTTPStatus.SEE_OTHER,
        HTTPStatus.TEMPORARY_REDIRECT,
        HTTPStatus.PERMANENT_REDIRECT,
    }
)


class OIDCTestCase(TestCase):
    """Shared test helpers and test data for OIDC provider tests."""

    alliances: ClassVar[list[EveAllianceInfo]]
    corps: ClassVar[list[EveCorporationInfo]]
    characters: ClassVar[list[EveCharacter]]
    users: ClassVar[list[User]]

    def grant_oidc_access(self, user: User) -> None:
        """Grant the global OIDC permission to a user."""
        user.user_permissions.add(self.access_oauth)
        user.refresh_from_db()

    def assertDenied(self, response: Any, user: User) -> None:
        """
        Assert that response is the standard denied page for the given
        user.
        """
        self.assertEqual(403, response.status_code)
        self.assertTemplateUsed(response, "allianceauth_oidc/denied.html")
        self.assertEqual(str(user), response.context["username"])

    def assertDeniedGlobal(self, response: Any, user: User) -> None:
        """Assert that the denial reason is the global permission gate."""
        self.assertDenied(response, user)
        self.assertIsNone(response.context["app_name"])
        self.assertIn(
            "User not allowed global OIDC access",
            response.context["error_code"],
        )
        # Rendered message must mention the per-user / global wording so
        # downstream support tooling can grep for it.
        self.assertIn(
            b"has no permission to use OIDC applications",
            response.content,
        )

    def assertDeniedApp(self, response: Any, user: User, app: Any) -> None:
        """
        Assert that the denial reason is application policy
        (state/groups).
        """
        self.assertDenied(response, user)
        self.assertEqual(str(app), response.context["app_name"])
        self.assertIn(
            "User not allowed for this application",
            response.context["error_code"],
        )
        self.assertIn(
            b"has no permission to use application",
            response.content,
        )

    def assertAuthorizePage(
        self, response: Any, app: Any, scopes: list[str] | None = None
    ) -> None:
        """
        Assert that the authorization consent page rendered for the given
        app.
        """
        self.assertEqual(200, response.status_code)
        self.assertTemplateUsed(response, "allianceauth_oidc/authorize.html")
        self.assertIn("application", response.context)
        self.assertEqual(app, response.context["application"])
        if scopes is not None:
            got = response.context.get("scopes")
            self.assertIsInstance(got, (list, tuple))
            self.assertEqual(sorted(scopes), sorted(got))

    def parse_redirect(
        self,
        response: Any,
        status_codes: frozenset[int] | tuple[int, ...] = REDIRECT_STATUSES,
    ) -> tuple[str, str, dict[str, list[str]]]:
        """
        Parses a redirect response from the authorize endpoint.

        Returns (location, path, parsed_qs_dict).
        """
        self.assertIn(response.status_code, status_codes)
        self.assertIn("Location", response.headers)
        loc = response.headers["Location"]
        parsed = urlparse(loc)
        path = parsed.path
        qs = parse_qs(parsed.query)
        return (loc, path, qs)

    def signal_capture(
        self,
        signal: Signal,
        sink: Callable[..., Any],
        *,
        dispatch_uid: str | None = None,
    ) -> str:
        """
        Connect ``sink`` to ``signal`` with an addCleanup-guarded disconnect.

        Closes two issues at once:

        * The cascade-failure window where an exception raised between
          ``signal.connect(...)`` and the corresponding ``try:`` block
          leaves ``sink`` permanently bound to a production signal
          (``oidc_token_issued``, ``oidc_logout_required``, …) for the
          rest of the test session.
        * The ``dispatch_uid="test.sink"`` collision risk: when two tests
          register against the same Signal with the same UID, Django's
          ``Signal.connect`` is append-only on UID and the second
          registration silently replaces the first.

        ``dispatch_uid`` is auto-generated from ``uuid4().hex`` if not
        provided, so concurrent parallel test workers (``--parallel=auto``)
        cannot collide. Pass an explicit value only when a test
        specifically targets dispatch-uid semantics.

        Returns the resolved ``dispatch_uid`` so a caller can introspect
        it (e.g. to assert it appears in a log line). Callers retain
        full control over the sink's shape — no opinion is imposed on
        what the recording payload looks like.
        """
        uid = dispatch_uid or f"test.capture.{uuid.uuid4().hex}"
        signal.connect(sink, dispatch_uid=uid)
        self.addCleanup(signal.disconnect, dispatch_uid=uid)
        return uid

    def json_body(
        self, response: Any, *, expected_status: int | None = 200
    ) -> Any:
        """
        Decode a Django test-client response body as JSON.

        Default asserts HTTP 200 — pass ``expected_status=None`` to
        skip the status check (e.g. for error-path responses where
        the caller verifies the status separately) or an explicit
        integer to pin a non-200 expectation.
        """
        if expected_status is not None:
            self.assertEqual(
                expected_status,
                response.status_code,
                getattr(response, "content", b"").decode(
                    "utf-8", errors="replace"
                ),
            )
        return json.loads(response.content.decode("utf-8"))

    def discovery(
        self, *, headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """
        Fetch and parse the OIDC discovery document.

        Optional ``headers`` forwarded to the test client — used by
        host-poisoning regression tests that need to drive the
        endpoint under a crafted ``Host`` header.
        """
        resp = self.client.get(DISCOVERY_URL, headers=headers or {})
        return self.json_body(resp)

    def jwks(self) -> dict[str, Any]:
        """Fetch and parse the public JWKS document."""
        return self.json_body(self.client.get(JWKS_URL))

    @staticmethod
    def make_pkce_pair() -> tuple[str, str]:
        """
        Build a fresh PKCE ``(verifier, challenge)`` pair for S256.

        ``verifier``: 256 bits of randomness, base64url-encoded without
        padding (RFC 7636 §4.1, 43-character ASCII output).
        ``challenge``: SHA-256 of the verifier, base64url-encoded
        without padding (RFC 7636 §4.2).

        Lives on the test case rather than the factory module because
        every call site is test-only and the helper has no model
        dependency.
        """
        verifier = (
            urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        )
        challenge = (
            urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        return verifier, challenge

    def exchange_code_with_verifier(
        self,
        *,
        code: str,
        verifier: str | None,
        client_id: str | None = None,
        client_secret: str | None = None,
        redirect_uri: str = REDIRECT_URI,
    ) -> Any:
        """
        POST /o/token/ with the given code and (optional) verifier.

        Mirror of :meth:`exchange_code_for_token` for PKCE-aware tests:
        passes ``code_verifier`` only when a non-``None`` value is
        supplied so callers can drive the omitted-verifier negative
        path with the same helper.
        """
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id or self.oauth_id,
            "client_secret": client_secret or self.oauth_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }
        if verifier is not None:
            payload["code_verifier"] = verifier
        return self.client.post("/o/token/", data=payload)

    def authorize_get(self, user: User, params: dict | None = None) -> Any:
        self.client.force_login(user)
        return self.client.get("/o/authorize/", data=(params or {}))

    def authorize_post(self, user: User, data: dict | None = None) -> Any:
        self.client.force_login(user)
        return self.client.post("/o/authorize/", data=(data or {}))

    def authorize_post_and_extract_code(
        self, user: User, data: dict, expected_redirect_uri: str | None = None
    ) -> tuple[str, str, dict]:
        """
        POST /o/authorize/ (allow=True) -> redirect to redirect_uri with
        code+state.
        """
        resp = self.authorize_post(user, data=data)
        loc, _, qs = self.parse_redirect(resp, (302,))

        if expected_redirect_uri is not None:
            got = urlparse(loc)
            exp = urlparse(expected_redirect_uri)
            self.assertEqual(
                (exp.scheme, exp.netloc), (got.scheme, got.netloc)
            )
            self.assertTrue(got.path.startswith(exp.path))

        self.assertIn("code", qs)
        self.assertIn("state", qs)

        resp_code = qs["code"][0]
        resp_state = qs["state"][0]

        self.assertIsInstance(resp_code, str)
        self.assertIsInstance(resp_state, str)

        if "state" in data:
            self.assertEqual(data["state"], resp_state)

        return resp_code, loc, qs

    def exchange_code_for_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        state: str | None = None,
        scope: str | None = None,
        expected_status: int | tuple[int, ...] = 200,
    ) -> Any:
        """Exchange authorization code for a token response."""
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id or self.oauth_id,
            "redirect_uri": redirect_uri,
            "client_secret": client_secret or self.oauth_secret,
            "code": code,
        }
        if state is not None:
            payload["state"] = state
        if scope is not None:
            payload["scope"] = scope
        resp = self.client.post("/o/token/", data=payload)
        if isinstance(expected_status, tuple):
            self.assertIn(resp.status_code, expected_status)
        else:
            self.assertEqual(expected_status, resp.status_code)
        return resp

    def introspect_token(
        self,
        token: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        """
        POST /o/introspect/ for ``token`` using Basic auth.

        Defaults to the fixture confidential client. RFC 7662 requires
        a confidential authenticated requester — pass ``client_id`` /
        ``client_secret`` to drive the endpoint with a different
        principal.
        """
        cid = client_id or self.oauth_id
        secret = client_secret or self.oauth_secret
        # RFC 7617 Basic auth uses standard base64 (``+/``), not URL-safe.
        creds = b64encode(f"{cid}:{secret}".encode("ascii")).decode("ascii")
        resp = self.client.post(
            INTROSPECT_URL,
            data={"token": token},
            headers={"authorization": f"Basic {creds}"},
        )
        return self.json_body(resp)

    def refresh_token(
        self,
        *,
        refresh_token: str,
        client_id: str | None = None,
        client_secret: str | None = None,
        scope: str | None = None,
        expected_status: int | tuple[int, ...] = 200,
    ) -> Any:
        """Exchange refresh_token for a new token response."""
        payload = {
            "grant_type": "refresh_token",
            "client_id": client_id or self.oauth_id,
            "client_secret": client_secret or self.oauth_secret,
            "refresh_token": refresh_token,
        }
        if scope is not None:
            payload["scope"] = scope

        resp = self.client.post("/o/token/", data=payload)
        if isinstance(expected_status, tuple):
            self.assertIn(resp.status_code, expected_status)
        else:
            self.assertEqual(expected_status, resp.status_code)
        return resp

    def assertOAuthError(
        self,
        response: Any,
        *,
        expected_error: str | set[str],
    ) -> Any:
        """
        Assert that the response body is an OAuth2 error payload.

        ``expected_error`` accepts either a single error code or a set of
        acceptable codes (DOT versions sometimes return invalid_grant where the
        spec allows invalid_request, etc.).
        """
        body = json.loads(response.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        if isinstance(expected_error, set):
            self.assertIn(body.get("error"), expected_error)
        else:
            self.assertEqual(expected_error, body.get("error"))
        return body

    def authorize_get_default(
        self,
        user: User,
        *,
        scope: str = SCOPE_FULL,
        state: str = "test",
        redirect_uri: str = REDIRECT_URI,
        extra: dict | None = None,
    ) -> Any:
        """
        GET /o/authorize/ with the standard OIDC params.

        ``extra`` overrides individual keys (e.g. nonce, code_challenge, custom
        client_id). Mirrors ``authorize_to_code`` for tests that only need the
        consent page or denial response.
        """
        params = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        }
        if extra:
            params.update(extra)
        return self.authorize_get(user, params=params)

    def authorize_to_code(
        self,
        user: User,
        *,
        scope: str = SCOPE_FULL,
        state: str = "test",
        redirect_uri: str = REDIRECT_URI,
        extra_authorize_params: dict | None = None,
    ) -> str:
        """
        Issue an authorization code without performing the token exchange.

        Use this when a test needs to mutate state (groups, permissions,
        debug_mode, app.active) between authorize and token endpoints. For end-
        to-end happy paths, prefer ``run_code_flow``.
        """
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "allow": True,
        }
        if extra_authorize_params:
            data.update(extra_authorize_params)
        code, _, _ = self.authorize_post_and_extract_code(
            user, data=data, expected_redirect_uri=redirect_uri
        )
        return code

    def run_code_flow(
        self,
        user: User,
        *,
        scope: str = SCOPE_FULL,
        state: str = "test",
        redirect_uri: str = REDIRECT_URI,
        extra_authorize_params: dict | None = None,
        expect_status: int | tuple[int, ...] = 200,
        expect_id_token: bool = True,
        expected_scope: str | None = None,
        expected_expires_in: int | None = None,
    ) -> dict:
        """
        Run the full authorization-code flow and return the parsed token
        body.

        Combines authorize_post_and_extract_code + exchange_code_for_token into
        one call. Default scope/state match the most common test setup; pass
        overrides for edge cases.

        Pass ``expect_id_token=False`` for OAuth-only flows (scope without
        ``openid``); ``assertTokenResponse`` will then assert the id_token is
        *absent*. ``expected_scope``/``expected_expires_in`` are forwarded to
        ``assertTokenResponse`` for happy-path checks.
        """
        code = self.authorize_to_code(
            user,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            extra_authorize_params=extra_authorize_params,
        )
        resp = self.exchange_code_for_token(
            code=code,
            redirect_uri=redirect_uri,
            expected_status=expect_status,
        )
        if expect_status == 200:
            return self.assertTokenResponse(
                resp,
                expect_id_token=expect_id_token,
                expected_scope=expected_scope,
                expected_expires_in=expected_expires_in,
            )
        return json.loads(resp.content.decode("utf-8"))

    def assertTokenResponse(
        self,
        response: Any,
        *,
        expected_scope: str | None = None,
        expected_expires_in: int | None = None,
        expect_id_token: bool = True,
    ) -> Any:
        """
        Assert that a successful token response contains required fields.

        Pass ``expect_id_token=False`` for OAuth-only flows whose scope does
        not include ``openid`` — DOT correctly omits the id_token in that case,
        and the default ``True`` would produce a misleading failure.
        """
        body = json.loads(response.content.decode("utf-8"))
        self.assertIsInstance(body, dict)
        self.assertIn("access_token", body)
        self.assertIn("refresh_token", body)
        if expect_id_token:
            self.assertIn("id_token", body)
        else:
            self.assertNotIn("id_token", body)

        if expected_scope is not None:
            got = body.get("scope") or ""
            self.assertEqual(set(expected_scope.split()), set(got.split()))

        if expected_expires_in is not None:
            self.assertEqual(expected_expires_in, body.get("expires_in"))

        return body

    @classmethod
    def setUpTestData(cls) -> None:
        """
        Build the shared fixture: 2 alliances, 4 corps, 10 characters, 4 users
        with varied affiliations, a confidential OIDC app, and two test groups.

        Django wraps `setUpTestData` in a class-level transaction that rolls
        back between tests, so M2M mutations made by individual tests
        (oauth_app.states.add, user.groups.add) don't leak — provided the suite
        stays on TestCase. Switching one of these tests to TransactionTestCase
        or running under pytest-xdist with a shared DB will break that
        guarantee.
        """
        # Alliances. Explicit IDs match assertions in legacy tests.
        cls.alli1 = make_alliance(
            "TEST",
            alliance_id=3,
            name="alliance.names1",
            executor_corp_id=123,
        )
        cls.alli2 = make_alliance(
            "TEST4",
            alliance_id=4,
            name="alliance.names4",
            executor_corp_id=3,
        )
        cls.alliances = [cls.alli1, cls.alli2]

        # Corps: corp1 is intentionally alliance-less (NPC corp case).
        cls.corp1 = make_corp("ABC", corp_id=123, name="corporation.name1")
        cls.corp2 = make_corp(
            "DEF", corp_id=2, name="corporation.name2", alliance=cls.alli1
        )
        cls.corp3 = make_corp(
            "GHI", corp_id=3, name="corporation.name3", alliance=cls.alli2
        )
        cls.corp4 = make_corp(
            "JKL", corp_id=4, name="corporation.name4", alliance=cls.alli2
        )
        cls.corps = [cls.corp1, cls.corp2, cls.corp3, cls.corp4]

        # Characters: 2 in corp1, 4 in corp2, 2 in corp3, 2 in corp4.
        cls.char1 = make_character("character.name1", cls.corp1, char_id=1)
        cls.char2 = make_character("character.name2", cls.corp1, char_id=2)
        cls.char3 = make_character("character.name3", cls.corp2, char_id=3)
        cls.char4 = make_character("character.name4", cls.corp2, char_id=4)
        cls.char5 = make_character("character.name5", cls.corp3, char_id=5)
        cls.char6 = make_character("character.name6", cls.corp3, char_id=6)
        cls.char7 = make_character("character.name7", cls.corp4, char_id=7)
        cls.char8 = make_character("character.name8", cls.corp4, char_id=8)
        cls.char9 = make_character("character.name9", cls.corp2, char_id=9)
        cls.char10 = make_character("character.name10", cls.corp2, char_id=10)
        cls.characters = [
            cls.char1, cls.char2, cls.char3, cls.char4, cls.char5,
            cls.char6, cls.char7, cls.char8, cls.char9, cls.char10,
        ]  # fmt: skip

        # Users:
        # - user1 (Member): main char1 in corp1 (no alliance) + alt char2.
        # - user2 (Blue):   main char3 in corp2/alli1.
        # - user3 (no state): main char5 in corp3/alli2 + alt char7 in
        #   corp4/alli2 — cross-corp same-alliance alts.
        # - user4 (no main, no state): two alts in corp2/alli1; exercises
        #   the "user without main_character" claim-mapping branch.
        cls.user1 = make_user(
            "User1", main=cls.char1, alts=[cls.char2], state="Member"
        )
        cls.user2 = make_user("User2", main=cls.char3, state="Blue")
        cls.user3 = make_user("User3", main=cls.char5, alts=[cls.char7])
        cls.user4 = make_user("User4", alts=[cls.char9, cls.char10])
        cls.users = [cls.user1, cls.user2, cls.user3, cls.user4]

        cls.access_oauth = Permission.objects.get_by_natural_key(
            PERM_ACCESS_OIDC_CODENAME,
            "allianceauth_oidc",
            "allianceauthapplication",
        )

        # Shared fixture defaults to pkce_required=False so the broad
        # cross-feature suites (userinfo, token, audit, logging, …) keep
        # exercising their actual subject without manufacturing a PKCE
        # verifier on every authorize. Tests that target PKCE behaviour
        # build their own ``make_app(pkce_required=True)`` fixture (see
        # ``test_conformance.py``).
        cls.oauth_app, cls.oauth_id, cls.oauth_secret = make_app(
            owner=cls.user1, pkce_required=False
        )

        cls.factory = RequestFactory()
        cls.test_grp = Group.objects.create(name="TestGroup")
        cls.test_grp_2 = Group.objects.create(name="TestGroup2")

    def setUp(self) -> None:
        # refresh_from_db() resets _prefetched_objects_cache for us, plus
        # the per-instance permissions cache that survives the test
        # transaction otherwise.
        for u in self.users:
            u.refresh_from_db()
        self.oauth_app.refresh_from_db()
        self.client.logout()
