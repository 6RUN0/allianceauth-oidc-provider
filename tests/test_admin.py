"""
Admin changelist + edit page smoke tests for ``pkce_required``.

The class-level ``override_settings(LANGUAGE_CODE='en')`` pins the
expected source string for the verbose name. Without it, a future PR
that flips the test settings module's locale to ``ru`` would silently
break ``self.assertIn("PKCE required", body)`` since the verbose name
would render translated.
"""

from typing import Any

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


@override_settings(LANGUAGE_CODE="en")
class TestApplicationAdminSendTestBackchannelLogout(OIDCTestCase):
    """
    The bulk-action ``send_test_backchannel_logout`` lets an operator
    fire a synthetic ``oidc_logout_required`` for an arbitrary set of
    selected applications without contriving a real user logout.

    Three contracts under test:

    1. An app WITH ``backchannel_logout_uri`` triggers the signal.
    2. An app WITHOUT one is skipped silently (warning surfaces; no
       signal emitted for that row).
    3. The action is wired into the admin changelist's ``action``
       drop-down — the integration point operators actually click on.
    """

    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.admin = User.objects.create_user(
            "admin-bcl",
            password="x",  # nosec B106 - test fixture
            is_superuser=True,
            is_staff=True,
        )
        self.client.force_login(self.admin)
        self.with_bcl = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.org/bcl/",
        )
        self.without_bcl = make_app(owner=self.user1)

    def _fire_action(self, *app_pks: int) -> Any:
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        return self.client.post(
            url,
            data={
                "action": "send_test_backchannel_logout",
                "_selected_action": [str(pk) for pk in app_pks],
            },
            follow=True,
        )

    def test_action_emits_signal_for_bcl_configured_app(self) -> None:
        from allianceauth_oidc.signals import oidc_logout_required

        captured: list[tuple[int, str]] = []

        def sink(sender, user, application, reason, **kw):
            captured.append((application.pk, reason))

        oidc_logout_required.connect(sink, dispatch_uid="test.admin.bcl.sink")
        try:
            resp = self._fire_action(self.with_bcl.app.pk)
        finally:
            oidc_logout_required.disconnect(dispatch_uid="test.admin.bcl.sink")
        self.assertEqual(200, resp.status_code)
        self.assertEqual(
            [(self.with_bcl.app.pk, "admin_test")],
            captured,
        )

    def test_action_skips_app_without_bcl_uri(self) -> None:
        from allianceauth_oidc.signals import oidc_logout_required

        captured: list[int] = []

        def sink(sender, user, application, reason, **kw):
            captured.append(application.pk)

        oidc_logout_required.connect(sink, dispatch_uid="test.admin.skip.sink")
        try:
            resp = self._fire_action(
                self.with_bcl.app.pk, self.without_bcl.app.pk
            )
        finally:
            oidc_logout_required.disconnect(
                dispatch_uid="test.admin.skip.sink"
            )
        self.assertEqual(200, resp.status_code)
        # Only the BCL-configured app fires; the unconfigured one is
        # silently skipped (operator sees a warning, not a hard fail).
        self.assertEqual([self.with_bcl.app.pk], captured)

    def test_changelist_renders_action_in_dropdown(self) -> None:
        """
        Pin the changelist's ``action`` ``<select>`` actually carries
        the option. Catches a regression where the method is defined
        but the ``actions = (...)`` tuple loses the entry.
        """
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        self.assertIn("send_test_backchannel_logout", body)

    def test_c1_action_skips_revoke_only_apps_with_warning(self) -> None:
        """
        regression: an app configured with
        ``backchannel_logout_on_revoke_only=True`` must NOT receive
        the synthetic ``admin_test`` signal — the dispatcher would
        silently no-op on it, so the admin button looked successful
        while delivering nothing. The action must skip such apps
        BEFORE emitting the signal and surface a warning naming the
        flag so the operator sees the divergence immediately.
        """
        from allianceauth_oidc.signals import oidc_logout_required

        revoke_only_app = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.org/bcl/",
        )
        revoke_only_app.app.backchannel_logout_on_revoke_only = True
        revoke_only_app.app.save(
            update_fields=["backchannel_logout_on_revoke_only"]
        )

        captured: list[int] = []

        def sink(sender, user, application, reason, **kw):
            captured.append(application.pk)

        oidc_logout_required.connect(
            sink, dispatch_uid="test.admin.revoke_only.sink"
        )
        try:
            resp = self._fire_action(
                self.with_bcl.app.pk, revoke_only_app.app.pk
            )
        finally:
            oidc_logout_required.disconnect(
                dispatch_uid="test.admin.revoke_only.sink"
            )

        self.assertEqual(200, resp.status_code)
        # Only the non-revoke-only app got the signal.
        self.assertEqual([self.with_bcl.app.pk], captured)
        # The follow-up changelist response carries the warning.
        body = resp.content.decode("utf-8")
        self.assertIn("backchannel_logout_on_revoke_only", body)


@override_settings(LANGUAGE_CODE="en")
class TestApplicationAdminRegistrationSource(OIDCTestCase):
    """
    DOT 3.4 provenance fields are visible but never editable.

    ``registration_source`` records HOW a row came to exist (manual /
    DCR / CIMD) — exactly the field an operator needs during incident
    response to spot a self-registered client, so it must be readable
    in the change-form and filterable in the changelist. It must NOT
    be editable: ``oauth2_provider.cimd`` branches on
    ``registration_source == "cimd"`` into a network-fetching refresh
    path, so letting an operator flip a hand-registered app to
    ``cimd`` would hand it to that machinery.
    """

    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.admin = User.objects.create_user(
            "admin-regsource",
            password="x",  # nosec B106 - test fixture
            is_superuser=True,
            is_staff=True,
        )
        self.client.force_login(self.admin)
        self.creds = make_app(owner=self.user1)

    def _change_url(self) -> str:
        return reverse(
            "admin:allianceauth_oidc_allianceauthapplication_change",
            args=[self.creds.app.pk],
        )

    def test_change_form_shows_registration_source_readonly(self) -> None:
        response = self.client.get(self._change_url())
        self.assertEqual(200, response.status_code)
        body = response.content.decode("utf-8")
        # Visible (label rendered) ...
        self.assertIn("Registration source", body)
        # ... but not editable (no bound form input for either
        # provenance field).
        self.assertNotIn('name="registration_source"', body)
        self.assertNotIn('name="cimd_expires_at"', body)

    def test_changelist_filter_by_registration_source(self) -> None:
        url = reverse(
            "admin:allianceauth_oidc_allianceauthapplication_changelist"
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        # The filter sidebar renders the field's verbose name — the
        # affordance an operator uses to spot non-manual rows.
        self.assertIn(
            "registration source",
            response.content.decode("utf-8").lower(),
        )
        response = self.client.get(url + "?registration_source__exact=manual")
        self.assertEqual(200, response.status_code)

    def test_admin_post_cannot_tamper_registration_source(self) -> None:
        """
        A crafted POST carrying ``registration_source=cimd`` must not
        change the stored value — read-only fields ignore posted data.
        """
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
            "registration_source": "cimd",
            "_save": "Save",
        }
        post_resp = self.client.post(self._change_url(), data=post_data)
        self.assertIn(
            post_resp.status_code,
            (302, 200),
            f"unexpected status {post_resp.status_code}: "
            f"{post_resp.content[:400]!r}",
        )
        app.refresh_from_db()
        self.assertEqual("manual", app.registration_source)
