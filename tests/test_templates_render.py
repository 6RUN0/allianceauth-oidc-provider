"""
Render smoke + Bootstrap-5 regression guards for the provider templates.

Every operator-facing template the provider ships
(``authorize.html`` / ``denied.html`` / ``oauth2_provider/
logout_confirm.html``) is driven through its real view path on the
supported Alliance Auth stack and must:

* render without a 5xx;
* not regress to the Bootstrap 3/2 classes (``label``, ``btn-large``,
  ``btn-default``, ``panel-body``, ``control-group``) that render as
  unstyled markup on Alliance Auth's Bootstrap-5 base — the same defect
  on both AA 4.x and AA 5.x;
* carry the corrected Bootstrap-5 classes.

These guards lock in the template fixes raised by the AA4/AA5
template-compatibility review.
"""

from http import HTTPStatus
from typing import Any

from django.conf import settings
from django.test import override_settings
from oauth2_provider.settings import oauth2_settings

from ._oidc_testcase import GrantedOIDCTestCase, OIDCTestCase

# Bootstrap 3/2 classes that must never reappear in a shipped template —
# each renders as unstyled markup on AA's Bootstrap-5 base. Matched as
# raw bytes against the rendered response body.
LEGACY_BOOTSTRAP_CLASSES: tuple[bytes, ...] = (
    b"label-warning",
    b"label-default",
    b"btn-large",
    b"btn-default",
    b"panel-body",
    b"control-group",
)


def _enable_rp_logout() -> dict[str, Any]:
    """Return an OAUTH2_PROVIDER override with RP-initiated logout on."""
    cfg = dict(getattr(settings, "OAUTH2_PROVIDER", {}) or {})
    cfg.setdefault("OIDC_ENABLED", True)
    cfg["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
    return cfg


class TemplateRenderMixin:
    """Shared assertions for the render smoke tests."""

    def assertNo5xx(self, response: Any) -> None:
        self.assertLess(
            response.status_code,
            500,
            f"template rendered a {response.status_code}: "
            f"{response.content[:500]!r}",
        )

    def assertNoLegacyBootstrap(self, response: Any) -> None:
        for token in LEGACY_BOOTSTRAP_CLASSES:
            self.assertNotIn(
                token,
                response.content,
                f"legacy Bootstrap class {token!r} leaked into the render",
            )


class TestAuthorizeTemplateRenders(TemplateRenderMixin, GrantedOIDCTestCase):
    """``allianceauth_oidc/authorize.html`` consent page."""

    def test_consent_page_renders_without_5xx(self) -> None:
        resp = self.authorize_get_default(self.user1)
        self.assertNo5xx(resp)
        self.assertEqual(HTTPStatus.OK, resp.status_code)
        self.assertTemplateUsed(resp, "allianceauth_oidc/authorize.html")

    def test_consent_page_uses_bootstrap5_classes(self) -> None:
        resp = self.authorize_get_default(self.user1)
        self.assertEqual(HTTPStatus.OK, resp.status_code)
        self.assertNoLegacyBootstrap(resp)
        # Corrected button + character-label classes.
        self.assertIn(b"btn-lg", resp.content)
        self.assertIn(b"text-bg-secondary", resp.content)


class TestDeniedTemplateRenders(TemplateRenderMixin, GrantedOIDCTestCase):
    """``allianceauth_oidc/denied.html`` — global and per-app deny paths."""

    def test_global_deny_page_renders_without_5xx(self) -> None:
        # user2 never receives the global ``access_oidc`` permission.
        resp = self.authorize_get_default(self.user2)
        self.assertNo5xx(resp)
        self.assertEqual(HTTPStatus.FORBIDDEN, resp.status_code)
        self.assertTemplateUsed(resp, "allianceauth_oidc/denied.html")

    def test_app_deny_page_renders_without_5xx(self) -> None:
        # user1 holds the global perm but the app whitelists a group
        # user1 is not a member of -> per-app deny.
        self.oauth_app.groups.add(self.test_grp_2)
        self.addCleanup(self.oauth_app.groups.clear)
        resp = self.authorize_get_default(self.user1)
        self.assertNo5xx(resp)
        self.assertEqual(HTTPStatus.FORBIDDEN, resp.status_code)
        self.assertTemplateUsed(resp, "allianceauth_oidc/denied.html")

    def test_denied_page_uses_bootstrap5_classes(self) -> None:
        resp = self.authorize_get_default(self.user2)
        self.assertEqual(HTTPStatus.FORBIDDEN, resp.status_code)
        self.assertNoLegacyBootstrap(resp)
        self.assertIn(b"text-bg-warning", resp.content)


class TestLogoutConfirmTemplateRenders(TemplateRenderMixin, OIDCTestCase):
    """
    ``oauth2_provider/logout_confirm.html`` override.

    DOT's ``RPInitiatedLogoutView`` resolves ``template_name =
    "oauth2_provider/logout_confirm.html"``; because ``allianceauth_oidc``
    precedes ``oauth2_provider`` in INSTALLED_APPS, our copy under
    ``templates/oauth2_provider/`` shadows DOT's bare Bootstrap-2 page.
    The marker comment proves the override won the template lookup.
    """

    # Rendered HTML comment unique to our override (survives template
    # rendering, unlike a ``{# #}`` Django comment).
    OVERRIDE_MARKER = b"allianceauth-oidc-logout-confirm-override"

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(oauth2_settings.reload)

    def _get_logout_confirm(self) -> Any:
        with override_settings(OAUTH2_PROVIDER=_enable_rp_logout()):
            oauth2_settings.reload()
            self.client.force_login(self.user1)
            return self.client.get("/o/logout/")

    def test_logout_confirm_renders_without_5xx(self) -> None:
        resp = self._get_logout_confirm()
        self.assertNo5xx(resp)
        self.assertEqual(HTTPStatus.OK, resp.status_code)
        self.assertTemplateUsed(resp, "oauth2_provider/logout_confirm.html")

    def test_override_shadows_dot_default(self) -> None:
        resp = self._get_logout_confirm()
        self.assertEqual(HTTPStatus.OK, resp.status_code)
        self.assertIn(self.OVERRIDE_MARKER, resp.content)

    def test_logout_confirm_uses_bootstrap5_classes(self) -> None:
        resp = self._get_logout_confirm()
        self.assertEqual(HTTPStatus.OK, resp.status_code)
        self.assertNoLegacyBootstrap(resp)
        self.assertIn(b"btn-lg", resp.content)
