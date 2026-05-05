"""Tests for /o/userinfo/ — claim emission, scope filtering, and bearer-token
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
        tokens = self.run_code_flow(
            self.user1,
            scope=scope,
            state=f"scope-{scope.replace(' ', '_')}",
            expect_id_token="openid" in scope.split(),
        )
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
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

    def test_email_claim_omitted_when_user_email_is_whitespace(self):
        """
        Regression: ``User.email = "   "`` is truthy and would have
        leaked into the email claim under a naive ``if email:`` check.
        The provider strips whitespace and treats whitespace-only
        emails as absent.
        """
        # Need to bypass the helper's `user1.email = "user1@example.com"`
        # so we can test the whitespace case directly.
        self.grant_oidc_access(self.user1)
        self.user1.email = "   "
        self.user1.save()
        self.user1.refresh_from_db()

        tokens = self.run_code_flow(
            self.user1,
            scope="openid email",
            state="whitespace-email",
        )
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        info = json.loads(resp.content.decode("utf-8"))
        self.assertNotIn("email", info)

    # -------------------------------------------------- multi-alt / edge cases

    def test_name_and_picture_come_from_main_character_not_alts(self):
        """
        User1's main is char1 (corp1, no alliance) and they have an alt char2
        also in corp1.

        The `name` claim must come from the *main* character,
        even when alts exist in different corps.
        """
        info = self._userinfo_for_user1_with_scope("openid profile")
        self.assertEqual(self.char1.character_name, info.get("name"))
        self.assertIn(str(self.char1.character_id), info.get("picture", ""))
        # Alt's name MUST NOT leak in.
        self.assertNotEqual(self.char2.character_name, info.get("name"))

    def test_user_without_main_character_omits_name_and_picture(self):
        """
        User4 is set up without a main_character.

        Userinfo must respond 200 and just omit `name`/`picture`, not
        crash with AttributeError.
        """
        self.grant_oidc_access(self.user4)
        tokens = self.run_code_flow(self.user4, state="no-main")
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        self.assertEqual(200, resp.status_code)
        info = json.loads(resp.content.decode("utf-8"))
        self.assertNotIn("name", info)
        self.assertNotIn("picture", info)

    def test_groups_claim_is_deterministic_across_calls(self):
        """
        With many groups (enough to defeat any DB-default ordering luck), two
        consecutive userinfo calls must return identical `groups` arrays.

        The contract is: Django groups sorted alphabetically, then the
        state name appended at the end. Adversarial fixture: 50 groups
        whose insertion order != alphabetical order, so a missing
        sort() would surface as B-tree leakage between calls.
        """
        from django.contrib.auth.models import Group

        # Mix prefixes so insertion order != alphabetical order.
        names = (
            [f"z-grp-{i:02d}" for i in range(15)]
            + [f"a-grp-{i:02d}" for i in range(15)]
            + [f"m-grp-{i:02d}" for i in range(20)]
        )
        groups = Group.objects.bulk_create([Group(name=n) for n in names])
        for g in groups:
            self.user1.groups.add(g)
        self.user1.refresh_from_db()

        info1 = self._userinfo_for_user1_with_scope("openid profile")
        info2 = self._userinfo_for_user1_with_scope("openid profile")
        self.assertEqual(info1.get("groups"), info2.get("groups"))

        # Stronger structural assertion: Django groups portion (everything
        # except the trailing state name) is alphabetically sorted, and
        # the state name is the final element.
        claim = info1.get("groups", [])
        django_groups, state_name = claim[:-1], claim[-1]
        self.assertEqual("Member", state_name)
        self.assertEqual(sorted(django_groups), django_groups)

    def test_groups_claim_includes_state_name_alongside_groups(self):
        """
        The groups claim is the union of Django Group names AND the user's
        state name (Member/Blue/Guest).

        user1 has the helper-added
        ``self.test_grp`` and state Member.
        """
        info = self._userinfo_for_user1_with_scope("openid profile")
        groups = info.get("groups", [])
        self.assertIn(self.test_grp.name, groups)
        self.assertIn("Member", groups)
        # No duplicates from accidental double-append.
        self.assertEqual(len(groups), len(set(groups)))
