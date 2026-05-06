"""
Admin changelist + edit page smoke tests for ``pkce_required``.

Tests run with ``LANGUAGE_CODE='en'`` so assertions cite the English
source string for the verbose name.
"""

from django.contrib.auth import get_user_model
from django.urls import reverse

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase


class TestApplicationAdminPkceRequired(OIDCTestCase):
    def setUp(self) -> None:
        super().setUp()
        # superuser bypasses access policy gates and the admin
        # permission gate
        User = get_user_model()
        self.admin = User.objects.create_user(
            "admin-smoke", password="x", is_superuser=True, is_staff=True
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
