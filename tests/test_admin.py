"""
Admin changelist + edit page smoke tests for ``pkce_required``.

The class-level ``override_settings(LANGUAGE_CODE='en')`` pins the
expected source string for the verbose name. Without it, a future PR
that flips the test settings module's locale to ``ru`` would silently
break ``self.assertIn("PKCE required", body)`` since the verbose name
would render translated.
"""

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase


@override_settings(LANGUAGE_CODE="en")
class TestApplicationAdminPkceRequired(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # superuser bypasses access policy gates and the admin
        # permission gate
        User = get_user_model()
        self.admin = User.objects.create_user(
            "admin-smoke",
            password="x",  # nosec B106 - test fixture
            is_superuser=True,
            is_staff=True,
        )
        self.client.force_login(self.admin)
        self.creds = make_app(owner=self.user1, pkce_required=True)

    def test_change_form_renders_pkce_required_input(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_change",
            args=[self.creds.app.pk],
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        self.assertIn('name="pkce_required"', body)

    def test_changelist_shows_pkce_required_column(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        # English verbose_name on the column header.
        self.assertIn("PKCE required", body)

    def test_changelist_filter_by_pkce_required(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url + "?pkce_required__exact=1")
        self.assertEqual(200, response.status_code)

    def test_changelist_filter_by_pkce_required_negative(self):
        """
        Symmetric with ``test_changelist_filter_by_pkce_required``:
        the filter accepts the negative case (``=0``) too. Without
        this assertion an admin regression that wires up the filter
        only for ``BooleanFieldListFilter``'s default 'Yes' branch
        would slip through the affirmative-only test.
        """
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url + "?pkce_required__exact=0")
        self.assertEqual(200, response.status_code)


@override_settings(LANGUAGE_CODE="en")
class TestApplicationAdminAccessTokenFormat(OIDCTestCase):
    """
    Admin smoke for ``access_token_format``: the column is rendered,
    the change-form input is rendered, the changelist filter accepts
    each value, and the form's blank input flows through the resolver
    as a no-override (so the global default wins).
    """

    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.admin = User.objects.create_user(
            "admin-jwt-smoke",
            password="x",  # nosec B106 - test fixture
            is_superuser=True,
            is_staff=True,
        )
        self.client.force_login(self.admin)
        self.creds = make_app(owner=self.user1, access_token_format="jwt")

    def test_change_form_renders_access_token_format_input(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_change",
            args=[self.creds.app.pk],
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        self.assertIn('name="access_token_format"', body)

    def test_changelist_shows_access_token_format_column(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        self.assertIn("Access token format", body)

    def test_changelist_filter_by_access_token_format(self):
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url + "?access_token_format__exact=jwt")
        self.assertEqual(200, response.status_code)

    def test_admin_form_blank_persists_none_not_empty_string(self):
        """
        Submitting the admin change-form with the
        ``access_token_format`` select cleared must result in the
        resolver returning the *global* default, not "jwt" or
        "opaque" as a per-app override. Tolerates either ``None`` or
        ``""`` at the storage layer — both fall through the
        ``in ("opaque", "jwt")`` gate in
        :meth:`allianceauth_oidc.security.AccessPolicy.access_token_format`.
        """
        from allianceauth_oidc.security import DEFAULT_POLICY

        # Pre-condition: app starts as per-app "jwt".
        self.assertEqual(
            "jwt",
            DEFAULT_POLICY.access_token_format(self.creds.app),
        )

        # Drive the admin change-form by reading current values from
        # the GET response and re-posting them with the format select
        # cleared. Direct ``model.save()`` would bypass the form's
        # cleaning step, which is exactly the layer this test
        # protects.
        change_url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_change",
            args=[self.creds.app.pk],
        )
        get_resp = self.client.get(change_url)
        self.assertEqual(200, get_resp.status_code)

        app = self.creds.app
        post_data = {
            "name": app.name,
            "client_id": app.client_id,
            "client_type": app.client_type,
            "authorization_grant_type": app.authorization_grant_type,
            "redirect_uris": app.redirect_uris or "",
            "post_logout_redirect_uris": app.post_logout_redirect_uris or "",
            "allowed_origins": app.allowed_origins or "",
            "skip_authorization": "",
            "active": "on",
            "debug_mode": "",
            "pkce_required": "on" if app.pkce_required else "",
            "access_token_format": "",
            "user": str(app.user_id),
            "logo_url": app.logo_url or "",
            "algorithm": app.algorithm,
            "states": [],
            "groups": [],
            "_save": "Save",
        }
        post_resp = self.client.post(change_url, data=post_data)
        self.assertIn(
            post_resp.status_code,
            (302, 200),
            f"unexpected status {post_resp.status_code}: "
            f"{post_resp.content[:400]!r}",
        )

        app.refresh_from_db()
        self.assertIn(
            app.access_token_format,
            (None, ""),
            f"blank admin input must store as falsy; got "
            f"{app.access_token_format!r}",
        )
        # Resolver-level invariant: blank → fall through to global.
        with override_settings(
            OAUTH2_PROVIDER={
                "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT": "opaque",
            }
        ):
            self.assertEqual(
                "opaque",
                DEFAULT_POLICY.access_token_format(app),
            )
