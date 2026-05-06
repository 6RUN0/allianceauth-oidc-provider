import json
from http import HTTPStatus
from typing import Any, ClassVar, Final
from urllib.parse import parse_qs, urlparse

from allianceauth.authentication.models import (
    EveAllianceInfo,
    EveCharacter,
    EveCorporationInfo,
)
from django.contrib.auth.models import Group, Permission, User
from django.test import RequestFactory, TestCase

from allianceauth_oidc.constants import PERM_ACCESS_OIDC_CODENAME

from ._factories import (
    make_alliance,
    make_app,
    make_character,
    make_corp,
    make_user,
)

# Default test fixtures — keep aligned with make_app() / make_user().
REDIRECT_URI = "http://localhost/redir/"
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "openid profile"
SCOPE_FULL = "openid profile email"
DEFAULT_EXPIRES_IN = 60

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

        cls.oauth_app, cls.oauth_id, cls.oauth_secret = make_app(
            owner=cls.user1
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
