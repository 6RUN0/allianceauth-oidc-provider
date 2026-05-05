"""
Tests for /o/userinfo/ — claim emission, scope filtering, and bearer-token
requirements.
"""

import json

from ._oidc_testcase import OIDCTestCase


class TestUserinfoClaims(OIDCTestCase):
    def _userinfo_for_user1_with_scope(self, scope: str) -> dict:
        """Common code-flow → userinfo helper for scope-filtering tests."""
        self.grant_oidc_access(self.user1)
        self.user1.email = "user1@example.com"
        self.user1.save()
        self.user1.groups.add(self.test_grp)
        self.user1.refresh_from_db()
        data = {
            "response_type": "code",
            "client_id": self.oauth_id,
            "redirect_uri": "http://localhost/redir/",
            "scope": scope,
            "state": f"scope-{scope.replace(' ', '_')}",
            "allow": True,
        }
        code, _, _ = self.authorize_post_and_extract_code(
            self.user1,
            data=data,
            expected_redirect_uri="http://localhost/redir/",
        )
        token_resp = self.exchange_code_for_token(
            code=code,
            redirect_uri="http://localhost/redir/",
            expected_status=200,
        )
        access_token = json.loads(token_resp.content)["access_token"]
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(200, resp.status_code)
        return json.loads(resp.content.decode("utf-8"))

    def test_userinfo_returns_expected_claims(self):
        """
        /o/userinfo/ returns additional claims:

        name, picture, groups (+ email if set).
        """
        info = self._userinfo_for_user1_with_scope("openid profile email")

        self.assertEqual(self.char1.character_name, info.get("name"))
        self.assertIn(str(self.char1.character_id), info.get("picture", ""))

        self.assertIn("groups", info)
        self.assertIsInstance(info["groups"], list)
        self.assertIn(self.test_grp.name, info["groups"])

        self.assertEqual("user1@example.com", info.get("email"))

    def test_userinfo_scope_openid_only_returns_only_sub(self):
        """
        Scope=`openid` MUST NOT leak profile/email claims.

        Regression for the contract that DOT's get_oidc_claims filters via
        oidc_claim_scope; if a future claim is added to get_additional_claims
        without a matching oidc_claim_scope entry, this catches it.
        """
        info = self._userinfo_for_user1_with_scope("openid")
        self.assertEqual({"sub"}, set(info.keys()))

    def test_userinfo_scope_openid_email_returns_only_sub_and_email(self):
        """Scope=`openid email` MUST NOT leak profile claims."""
        info = self._userinfo_for_user1_with_scope("openid email")
        self.assertEqual({"sub", "email"}, set(info.keys()))
        self.assertEqual("user1@example.com", info["email"])

    def test_locale_claim_omitted_when_user_language_is_blank(self):
        """
        Regression: `UserProfile.language` is a CharField with default="";
        the locale claim must not be emitted as an empty string.
        """
        self.user1.profile.language = ""
        self.user1.profile.save()
        self.user1.refresh_from_db()
        info = self._userinfo_for_user1_with_scope("openid profile email")
        self.assertNotIn("locale", info)

    def test_locale_claim_present_when_user_language_is_set(self):
        """Positive counterpart of the previous test."""
        self.user1.profile.language = "ru"
        self.user1.profile.save()
        self.user1.refresh_from_db()
        info = self._userinfo_for_user1_with_scope("openid profile email")
        self.assertEqual("ru", info.get("locale"))

    def test_userinfo_requires_bearer_token(self):
        """/o/userinfo/ must require Authorization: Bearer <token>."""
        resp = self.client.get("/o/userinfo/")
        self.assertIn(resp.status_code, (401, 403))
