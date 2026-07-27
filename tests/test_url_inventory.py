"""
Route-inventory guard for ``allianceauth_oidc.urls``.

The app's DCR/CIMD safety rests on ``urls.py`` hand-composing its
``urlpatterns`` instead of including ``oauth2_provider.urls`` — DOT
3.4's default URL conf additionally mounts dynamic client
registration (``register/``, ``register/<client_id>/``), the RFC 8414
/ RFC 9728 metadata endpoints, and the application-management views.
A refactor to ``include("oauth2_provider.urls")`` would silently
mount client self-registration, which is incompatible with the
states/groups whitelist model (an auto-registered app has an empty
whitelist and ``AccessPolicy`` treats that as "allow every user
holding ``access_oidc``"). These tests turn that implicit invariant
into an explicit one.
"""

from django.test import TestCase

# Exact set of route names this app mounts. Adding a route is a
# conscious decision — update this set in the same change and say why
# in the commit body.
EXPECTED_ROUTE_NAMES = frozenset(
    {
        "authorize",
        "token",
        "revoke-token",
        "introspect",
        "authorized-token-list",
        "authorized-token-delete",
        "oidc-connect-discovery-info",
        "jwks-info",
        "user-info",
        "rp-initiated-logout",
    }
)

# Paths DOT's default URL conf would add under the same prefix; none
# may resolve here. ``register/`` is RFC 7591 DCR; the two
# ``.well-known`` entries are the RFC 8414 / RFC 9728 metadata views;
# ``applications/`` is DOT's self-service app management.
FORBIDDEN_PATHS = (
    "/o/register/",
    "/o/applications/",
    "/o/applications/register/",
    "/o/.well-known/oauth-authorization-server",
    "/o/.well-known/oauth-protected-resource",
)


class TestRouteInventory(TestCase):
    def test_mounted_route_names_are_pinned(self) -> None:
        from allianceauth_oidc import urls as oidc_urls

        actual = frozenset(pattern.name for pattern in oidc_urls.urlpatterns)
        added = actual - EXPECTED_ROUTE_NAMES
        removed = EXPECTED_ROUTE_NAMES - actual
        self.assertFalse(
            added or removed,
            f"route inventory drift: added={sorted(added)}, "
            f"removed={sorted(removed)}",
        )

    def test_dcr_and_metadata_routes_not_mounted(self) -> None:
        for path in FORBIDDEN_PATHS:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(
                    404,
                    response.status_code,
                    f"{path} must not be mounted — DOT's DCR / "
                    "metadata / app-management views bypass the "
                    "states/groups whitelist",
                )
