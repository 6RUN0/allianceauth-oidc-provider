"""
Tests for /o/userinfo/ — claim emission, scope filtering, and bearer-token
requirements.
"""

import json

from django.contrib.auth.models import Group
from django.test import override_settings

from ._oidc_testcase import (
    SCOPE_FULL,
    SCOPE_OPENID,
    SCOPE_PROFILE,
    OIDCTestCase,
)


class TestUserinfoClaims(OIDCTestCase):
    def _userinfo_for_user1_with_scope(
        self,
        scope: str,
        *,
        email: str = "user1@example.com",
        with_test_group: bool = True,
    ) -> dict:
        """
        Common code-flow → userinfo helper for scope-filtering tests.

        ``email`` lets the whitespace-regression test pass a non-default value;
        ``with_test_group=False`` skips the implicit ``test_grp`` membership
        for tests where it would interfere.
        """
        self.grant_oidc_access(self.user1)
        self.user1.email = email
        self.user1.save()
        if with_test_group:
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
        """/o/userinfo/ returns name, picture, groups (+ email if set)."""
        info = self._userinfo_for_user1_with_scope(SCOPE_FULL)

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
        info = self._userinfo_for_user1_with_scope(SCOPE_OPENID)
        self.assertEqual({"sub"}, set(info.keys()))

    def test_userinfo_scope_openid_email_returns_only_sub_and_email(self):
        """Scope=`openid email` MUST NOT leak profile claims."""
        info = self._userinfo_for_user1_with_scope(f"{SCOPE_OPENID} email")
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
        info = self._userinfo_for_user1_with_scope(SCOPE_FULL)
        self.assertNotIn("locale", info)

    def test_locale_claim_present_when_user_language_is_set(self):
        """Positive counterpart of the previous test."""
        self.user1.profile.language = "ru"
        self.user1.profile.save()
        self.user1.refresh_from_db()
        info = self._userinfo_for_user1_with_scope(SCOPE_FULL)
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
        info = self._userinfo_for_user1_with_scope(
            f"{SCOPE_OPENID} email", email="   "
        )
        self.assertNotIn("email", info)

    # -------------------------------------------------- multi-alt / edge cases

    def test_name_and_picture_come_from_main_character_not_alts(self):
        """
        User1's main is char1 (corp1, no alliance) and they have an alt
        char2 also in corp1.

        The `name` claim must come from the *main* character, even when alts
        exist in different corps.
        """
        info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        self.assertEqual(self.char1.character_name, info.get("name"))
        self.assertIn(str(self.char1.character_id), info.get("picture", ""))
        # Alt's name MUST NOT leak in.
        self.assertNotEqual(self.char2.character_name, info.get("name"))

    @override_settings(
        ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE="https://cdn.example.test/portraits/{character_id}-{size}.png",
        ALLIANCEAUTH_OIDC_PORTRAIT_SIZE=512,
    )
    def test_picture_claim_honours_portrait_template_overrides(self):
        """
        Operators can override the portrait URL template and size via Django
        settings (e.g. for a mirrored CDN).

        The `picture` claim must reflect both.
        """
        info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        expected = f"https://cdn.example.test/portraits/{self.char1.character_id}-512.png"
        self.assertEqual(expected, info.get("picture"))

    @override_settings(
        ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE=(
            "https://cdn.example.test/portraits/{wrong_placeholder}.png"
        ),
    )
    def test_malformed_portrait_template_skips_picture_without_500(self):
        """
        A typo in the operator-supplied portrait URL template (missing the
        ``{character_id}``/``{size}`` placeholders) used to raise inside id-
        token signing and 500 the token endpoint.

        Now: degrade gracefully — the userinfo response still succeeds, the
        ``picture`` claim is simply omitted, and a warning is logged so the
        operator can spot the misconfiguration.
        """
        with self.assertLogs(
            "extensions.allianceauth_oidc.auth_provider", level="WARNING"
        ) as cm:
            info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)

        self.assertNotIn("picture", info)
        # Other profile claims must still be emitted.
        self.assertEqual(self.char1.character_name, info.get("name"))
        joined = "\n".join(cm.output)
        self.assertIn("ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE", joined)

    def test_groups_claim_is_capped_for_pathological_users(self):
        """
        A user with a runaway number of group memberships used to produce an
        unbounded ``groups`` claim — JWTs are URL-encoded into headers and
        cookies, so a 200KB token from a 10k-group user is effectively unusable
        downstream.

        The validator caps the list at ``MAX_GROUPS_IN_CLAIM`` and emits a
        warning so operators see the truncation. The state name must still
        appear at the tail (it is appended after truncation).
        """
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        cap = AllianceAuthOAuth2Validator.MAX_GROUPS_IN_CLAIM
        # Two extra so the truncation branch fires; sortable as `cap_grp_NNN`.
        extras = [
            Group.objects.create(name=f"cap_grp_{i:04d}")
            for i in range(cap + 2)
        ]
        for g in extras:
            self.user1.groups.add(g)

        with self.assertLogs(
            "extensions.allianceauth_oidc.auth_provider", level="WARNING"
        ) as cm:
            info = self._userinfo_for_user1_with_scope(
                SCOPE_PROFILE, with_test_group=False
            )

        groups = info["groups"]
        # cap groups + 1 trailing state name. The implicit test group is
        # excluded by `with_test_group=False`.
        self.assertEqual(cap + 1, len(groups))
        # State must remain at the tail regardless of truncation.
        self.assertEqual(self.user1.profile.state.name, groups[-1])
        joined = "\n".join(cm.output)
        self.assertIn("groups claim truncated", joined)

    def test_user_without_main_character_omits_name_and_picture(self):
        """
        User4 is set up without a main_character.

        Userinfo must respond 200 and just omit `name`/`picture`, not crash
        with AttributeError.
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

    def test_eve_claims_emitted_for_user_with_main_character(self):
        """
        Default prefix ``eve_`` and scope ``profile``: the full set of
        EVE claims (character/corporation/alliance) is emitted for a
        user whose main_character is in a corp inside an alliance.
        """
        info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        # user1's main is char1, corp1 (NPC corp without an alliance).
        self.assertEqual(self.char1.character_id, info["eve_character_id"])
        self.assertEqual(self.char1.corporation_id, info["eve_corporation_id"])
        self.assertEqual(
            self.char1.corporation_name, info["eve_corporation_name"]
        )
        self.assertEqual(
            self.char1.corporation_ticker, info["eve_corporation_ticker"]
        )
        # corp1 has no alliance — alliance-* claims must be omitted, not
        # emitted as null. Tests the omit contract.
        for omitted in (
            "eve_alliance_id",
            "eve_alliance_name",
            "eve_alliance_ticker",
        ):
            self.assertNotIn(omitted, info)

    def test_eve_alliance_claims_emitted_for_alliance_corp(self):
        """
        user2's main (char3) is in corp2/alli1 — the alliance trio of
        claims must be present and reflect the corp's denormalised
        alliance fields.
        """
        self.grant_oidc_access(self.user2)
        tokens = self.run_code_flow(self.user2, state="alli-claims")
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        info = json.loads(resp.content.decode("utf-8"))
        self.assertEqual(self.char3.alliance_id, info["eve_alliance_id"])
        self.assertEqual(self.char3.alliance_name, info["eve_alliance_name"])
        self.assertEqual(
            self.char3.alliance_ticker, info["eve_alliance_ticker"]
        )

    def test_eve_claim_prefix_override_works_end_to_end(self):
        """
        ``@override_settings(ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX="custom_")``
        now propagates through both the claim emission *and* DOT's
        scope-map filter, end-to-end on a live userinfo request.

        Regression: an earlier implementation snapshotted the scope
        map at class-definition time, so a runtime prefix flip would
        emit ``custom_*`` claims that DOT then filtered out (no
        scope-map entry). The current implementation keys the map on
        the cached ``OIDCSettings`` snapshot — invalidated on
        ``setting_changed`` — so the override is honoured by both
        sides of the pipeline.
        """
        from allianceauth_oidc import app_settings

        with override_settings(ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX="custom_"):
            self.assertEqual("custom_", app_settings.eve_claim_prefix())
            info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        # New prefix made it through: claim emitted under custom_ AND
        # bound under custom_ in the scope map → DOT lets it through.
        self.assertIn("custom_character_id", info)
        # Old prefix is gone: scope map no longer contains eve_*
        # entries under the override.
        self.assertNotIn("eve_character_id", info)

    def test_eve_claims_omitted_for_user_without_main_character(self):
        """
        user4 has no main_character; every EVE claim must be absent
        regardless of scope. Mirrors the existing ``name``/``picture``
        omit contract for the same fixture.
        """
        self.grant_oidc_access(self.user4)
        tokens = self.run_code_flow(self.user4, state="eve-no-main")
        resp = self.client.get(
            "/o/userinfo/",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        info = json.loads(resp.content.decode("utf-8"))
        for claim in (
            "eve_character_id",
            "eve_corporation_id",
            "eve_corporation_name",
            "eve_corporation_ticker",
            "eve_alliance_id",
            "eve_alliance_name",
            "eve_alliance_ticker",
        ):
            self.assertNotIn(claim, info)

    def test_groups_claim_is_deterministic_across_calls(self):
        """
        With many groups (enough to defeat any DB-default ordering luck),
        two consecutive userinfo calls must return identical `groups` arrays.

        The contract is: Django groups sorted alphabetically, then the
        state name appended at the end. Adversarial fixture: 50 groups
        whose insertion order != alphabetical order, so a missing
        sort() would surface as B-tree leakage between calls.
        """
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

        info1 = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        info2 = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
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

        user1 has the helper-added ``self.test_grp`` and state Member.
        """
        info = self._userinfo_for_user1_with_scope(SCOPE_PROFILE)
        groups = info.get("groups", [])
        self.assertIn(self.test_grp.name, groups)
        self.assertIn("Member", groups)
        # No duplicates from accidental double-append.
        self.assertEqual(len(groups), len(set(groups)))
