"""
Pure-Python tests for ``allianceauth_oidc.claims.ClaimsBuilder``.

Each ``_xxx`` method is exercised on synthetic users built from
``types.SimpleNamespace`` plus a tiny in-memory queryset stub. No
database, no Alliance Auth import, no DOT — these run as
``SimpleTestCase`` in milliseconds and let edge cases be table-
driven instead of one-test-per-fixture.

Integration coverage of the same code path lives in
``test_userinfo.py`` (HTTP-level, ``OIDCTestCase`` fixture) — the two
suites complement each other; do not collapse them.
"""

from __future__ import annotations

import contextlib
import logging
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from allianceauth_oidc.app_settings import OIDCSettings
from allianceauth_oidc.claims import ClaimsBuilder


def _settings(**overrides: object) -> OIDCSettings:
    base = {
        "log_masked_secrets": False,
        "log_mask_head": 2,
        "log_mask_tail": 2,
        "portrait_url_template": (
            "https://images.evetech.net/characters/"
            "{character_id}/portrait?size={size}"
        ),
        "portrait_size": 128,
        "eve_claim_prefix": "eve_",
        "eve_claim_scope": "profile",
        "email_verified_default": True,
        "force_email_verified": None,
        "default_access_token_format": "opaque",
        "jwt_size_warn_bytes": 4096,
    }
    base.update(overrides)
    return OIDCSettings(**base)


class _GroupsQS:
    """Minimal queryset-shaped stub: ``groups.all().values_list(...)``."""

    def __init__(self, names: list[str]) -> None:
        self._names = names

    def all(self) -> _GroupsQS:
        return self

    def values_list(self, _field: str, flat: bool = False) -> list[str]:
        # The production code passes ``flat=True``; we just return the
        # list of names. Honouring ``flat=False`` is unnecessary here.
        del flat
        return list(self._names)


def _user(
    *,
    email: str | None = None,
    main: object | None = None,
    state_name: str | None = None,
    language: str | None = None,
    group_names: list[str] | None = None,
    user_id: int = 42,
) -> SimpleNamespace:
    """Build a synthetic ``user``-shaped object the builder accepts."""
    profile = SimpleNamespace(
        main_character=main,
        state=SimpleNamespace(name=state_name) if state_name else None,
        language=language,
    )
    return SimpleNamespace(
        id=user_id,
        email=email,
        profile=profile,
        groups=_GroupsQS(group_names or []),
    )


def _main(
    *,
    character_id: int | None = None,
    character_name: str | None = None,
    corporation_id: int | None = None,
    corporation_name: str | None = None,
    corporation_ticker: str | None = None,
    alliance_id: int | None = None,
    alliance_name: str | None = None,
    alliance_ticker: str | None = None,
    faction_id: int | None = None,
    faction_name: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        character_id=character_id,
        character_name=character_name,
        corporation_id=corporation_id,
        corporation_name=corporation_name,
        corporation_ticker=corporation_ticker,
        alliance_id=alliance_id,
        alliance_name=alliance_name,
        alliance_ticker=alliance_ticker,
        faction_id=faction_id,
        faction_name=faction_name,
    )


class TestEmailClaim(SimpleTestCase):
    def test_omitted_when_none(self):
        builder = ClaimsBuilder(user=_user(email=None), settings=_settings())
        out = builder.build()
        # Both ``email`` and ``email_verified`` must stay out — the
        # latter is only meaningful when an address is actually
        # present, and OIDC §5.1 ties them together as a pair.
        self.assertNotIn("email", out)
        self.assertNotIn("email_verified", out)

    def test_omitted_when_blank(self):
        builder = ClaimsBuilder(user=_user(email=""), settings=_settings())
        out = builder.build()
        self.assertNotIn("email", out)
        self.assertNotIn("email_verified", out)

    def test_omitted_when_only_whitespace(self):
        # Defensive: copy-paste / buggy admin imports occasionally
        # land "  " in the email field.
        builder = ClaimsBuilder(user=_user(email="   "), settings=_settings())
        self.assertNotIn("email", builder.build())

    def test_emitted_when_present(self):
        builder = ClaimsBuilder(
            user=_user(email="alice@example.test"), settings=_settings()
        )
        self.assertEqual("alice@example.test", builder.build()["email"])

    def test_whitespace_stripped(self):
        builder = ClaimsBuilder(
            user=_user(email="  bob@example.test  "), settings=_settings()
        )
        self.assertEqual("bob@example.test", builder.build()["email"])

    def test_email_verified_true_when_aa_verifies_at_registration(self):
        # Default settings mirror AA's REGISTRATION_VERIFY_EMAIL=True;
        # any user with a populated email completed AA's confirmation
        # workflow, so we forward verification truthfully.
        builder = ClaimsBuilder(
            user=_user(email="alice@example.test"),
            settings=_settings(email_verified_default=True),
        )
        out = builder.build()
        self.assertEqual("alice@example.test", out["email"])
        self.assertIs(True, out["email_verified"])

    def test_email_verified_false_when_aa_skips_verification(self):
        # When the operator sets REGISTRATION_VERIFY_EMAIL=False, AA
        # never validated the address; we MUST NOT claim verification.
        builder = ClaimsBuilder(
            user=_user(email="alice@example.test"),
            settings=_settings(email_verified_default=False),
        )
        out = builder.build()
        self.assertEqual("alice@example.test", out["email"])
        self.assertIs(False, out["email_verified"])

    def test_aa_skip_email_placeholder_forces_email_verified_false(self):
        # The companion ``aa_skip_email`` plugin stamps users without a
        # real address with a synthetic placeholder; those addresses
        # are by definition unverified, so ``email_verified`` MUST be
        # ``False`` regardless of REGISTRATION_VERIFY_EMAIL.
        with patch(
            "allianceauth_oidc.claims._aa_skip_email_is_placeholder",
            return_value=True,
        ):
            builder = ClaimsBuilder(
                user=_user(email="bob_42@noreply.example"),
                settings=_settings(email_verified_default=True),
            )
            out = builder.build()
        self.assertEqual("bob_42@noreply.example", out["email"])
        self.assertIs(False, out["email_verified"])

    def test_aa_skip_email_placeholder_overrides_verify_email_true(self):
        # Even on a stricter site (REGISTRATION_VERIFY_EMAIL=True) a
        # placeholder must report ``email_verified=False``: the
        # placeholder is the marker that the user skipped verification.
        with patch(
            "allianceauth_oidc.claims._aa_skip_email_is_placeholder",
            return_value=True,
        ):
            builder = ClaimsBuilder(
                user=_user(email="bob_42@noreply.example"),
                settings=_settings(email_verified_default=False),
            )
            out = builder.build()
        self.assertIs(False, out["email_verified"])

    def test_real_email_after_placeholder_uses_settings_default(self):
        # When the user later replaced the placeholder with a real
        # address, the detector returns False and we fall back to the
        # global verification policy.
        with patch(
            "allianceauth_oidc.claims._aa_skip_email_is_placeholder",
            return_value=False,
        ):
            builder = ClaimsBuilder(
                user=_user(email="alice@example.test"),
                settings=_settings(email_verified_default=True),
            )
            out = builder.build()
        self.assertIs(True, out["email_verified"])

    def test_email_verified_false_when_aa_skip_email_not_installed(self):
        # The detector is None when the optional plugin is absent; we
        # then trust the global setting and do not flag the email as
        # placeholder. This is the production path on installations
        # without aa_skip_email.
        with patch(
            "allianceauth_oidc.claims._aa_skip_email_is_placeholder",
            None,
        ):
            builder = ClaimsBuilder(
                user=_user(email="alice@example.test"),
                settings=_settings(email_verified_default=True),
            )
            out = builder.build()
        self.assertIs(True, out["email_verified"])

    def test_force_email_verified_matrix(self):
        """
        Sweep the force_email_verified x default x placeholder matrix.

        Pins each branch of the escape-hatch decision tree:

        * ``force_true_overrides_default_false`` — operator
          forces verified=True even though AA's default emits
          False. Use case: users imported from a trusted
          external IdP.
        * ``force_true_overrides_placeholder`` — Force takes
          precedence over the placeholder check; that IS the
          point of an escape hatch.
        * ``force_false_overrides_default_true`` — site policy
          distrusts AA's confirmation workflow and wants every
          RP to re-verify on its own.
        * ``force_none_uses_auto_decision_tree`` — sanity pin
          on the default no-op: ``None`` leaves the placeholder
          + REGISTRATION_VERIFY_EMAIL pipeline in charge.
        """
        cases: tuple[
            tuple[str, bool | None, bool, bool | None, str, bool], ...
        ] = (
            (
                "force_true_overrides_default_false",
                True,
                False,
                None,
                "alice@example.test",
                True,
            ),
            (
                "force_true_overrides_placeholder",
                True,
                True,
                True,
                "bob_42@noreply.example",
                True,
            ),
            (
                "force_false_overrides_default_true",
                False,
                True,
                None,
                "alice@example.test",
                False,
            ),
            (
                "force_none_uses_auto_decision_tree",
                None,
                True,
                None,
                "alice@example.test",
                True,
            ),
        )
        for (
            label,
            force,
            default,
            placeholder_returns,
            email,
            expected,
        ) in cases:
            placeholder_ctx: contextlib.AbstractContextManager[object]
            if placeholder_returns is None:
                placeholder_ctx = contextlib.nullcontext()
            else:
                placeholder_ctx = patch(
                    "allianceauth_oidc.claims._aa_skip_email_is_placeholder",
                    return_value=placeholder_returns,
                )
            with self.subTest(case=label), placeholder_ctx:
                out = ClaimsBuilder(
                    user=_user(email=email),
                    settings=_settings(
                        email_verified_default=default,
                        force_email_verified=force,
                    ),
                ).build()
                self.assertIs(expected, out["email_verified"])


class TestPictureClaim(SimpleTestCase):
    def test_omitted_when_no_main_character(self):
        builder = ClaimsBuilder(user=_user(main=None), settings=_settings())
        self.assertNotIn("picture", builder.build())

    def test_omitted_when_main_has_no_character_id(self):
        builder = ClaimsBuilder(
            user=_user(main=_main(character_id=None)), settings=_settings()
        )
        self.assertNotIn("picture", builder.build())

    def test_emitted_with_default_template(self):
        builder = ClaimsBuilder(
            user=_user(main=_main(character_id=123)), settings=_settings()
        )
        self.assertEqual(
            "https://images.evetech.net/characters/123/portrait?size=128",
            builder.build()["picture"],
        )

    def test_honours_size_override(self):
        builder = ClaimsBuilder(
            user=_user(main=_main(character_id=99)),
            settings=_settings(portrait_size=512),
        )
        self.assertIn("size=512", builder.build()["picture"])

    def test_invalid_template_logged_and_skipped(self):
        # Template references an unknown placeholder — the builder
        # must catch the format error and log a warning, not 500.
        bad = _settings(
            portrait_url_template="https://example.test/{nope}.png"
        )
        builder = ClaimsBuilder(
            user=_user(main=_main(character_id=7)), settings=bad
        )
        with self.assertLogs(
            "extensions.allianceauth_oidc.claims", level="WARNING"
        ) as cap:
            out = builder.build()
        self.assertNotIn("picture", out)
        self.assertTrue(
            any(
                "invalid ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE" in m
                for m in cap.output
            )
        )


class TestNameClaim(SimpleTestCase):
    def test_omitted_when_no_main(self):
        builder = ClaimsBuilder(user=_user(main=None), settings=_settings())
        self.assertNotIn("name", builder.build())

    def test_omitted_when_main_has_no_name(self):
        builder = ClaimsBuilder(
            user=_user(main=_main(character_name=None)), settings=_settings()
        )
        self.assertNotIn("name", builder.build())

    def test_emitted_when_present(self):
        builder = ClaimsBuilder(
            user=_user(main=_main(character_name="CharOne")),
            settings=_settings(),
        )
        self.assertEqual("CharOne", builder.build()["name"])


class TestGroupsClaim(SimpleTestCase):
    def test_omitted_when_no_groups_and_no_state(self):
        builder = ClaimsBuilder(user=_user(), settings=_settings())
        self.assertNotIn("groups", builder.build())

    def test_state_alone_emits_singleton_list(self):
        # A user with no Django groups but a state still gets the
        # state appended — consumers that map states the same way
        # they map groups depend on this.
        builder = ClaimsBuilder(
            user=_user(state_name="Member"), settings=_settings()
        )
        self.assertEqual(["Member"], builder.build()["groups"])

    def test_groups_sorted_then_state_appended(self):
        # Sort is required for caching consumers; state lands at the
        # tail unconditionally.
        builder = ClaimsBuilder(
            user=_user(group_names=["zeta", "alpha"], state_name="Blue"),
            settings=_settings(),
        )
        self.assertEqual(["alpha", "zeta", "Blue"], builder.build()["groups"])

    def test_oversized_groups_truncated_with_warning(self):
        # 300 groups > default cap of 256 → truncate, then append
        # state. Total length must be cap + 1.
        names = [f"g{i:04d}" for i in range(300)]
        builder = ClaimsBuilder(
            user=_user(group_names=names, state_name="Member"),
            settings=_settings(),
        )
        with self.assertLogs(
            "extensions.allianceauth_oidc.claims", level="WARNING"
        ):
            out = builder.build()
        self.assertEqual(257, len(out["groups"]))
        self.assertEqual("Member", out["groups"][-1])

    def test_custom_cap_honoured(self):
        builder = ClaimsBuilder(
            user=_user(group_names=["a", "b", "c"]),
            settings=_settings(),
            max_groups=2,
        )
        with self.assertLogs(
            "extensions.allianceauth_oidc.claims", level="WARNING"
        ):
            out = builder.build()
        self.assertEqual(["a", "b"], out["groups"])

    def test_groups_at_exact_cap_not_truncated_no_warning(self):
        # Pin ``>`` against ``>=`` (and ``Gt_*`` family) on the cap
        # check ``if len(groups_list) > self.max_groups:``.
        #
        # ``test_oversized_groups_truncated_with_warning`` covers 300
        # vs cap 256 — both ``>`` and ``>=`` are True for that input.
        # ``test_custom_cap_honoured`` covers 3 vs cap 2 — same: both
        # operators agree. The boundary ``len == cap`` is the only
        # input where the two disagree (``>`` False = keep,
        # ``>=`` True = truncate / warn).
        names = [f"g{i:04d}" for i in range(2)]  # exactly 2 groups
        builder = ClaimsBuilder(
            user=_user(group_names=names, state_name=None),
            settings=_settings(),
            max_groups=2,
        )
        with self.assertNoLogs(
            "extensions.allianceauth_oidc.claims", level="WARNING"
        ):
            out = builder.build()
        # All groups kept (no truncation, no state-append).
        self.assertEqual(names, out["groups"])


class TestLocaleClaim(SimpleTestCase):
    def test_omitted_when_blank(self):
        # ``UserProfile.language`` defaults to "" — must not be emitted.
        builder = ClaimsBuilder(user=_user(language=""), settings=_settings())
        self.assertNotIn("locale", builder.build())

    def test_emitted_when_set(self):
        builder = ClaimsBuilder(
            user=_user(language="ru"), settings=_settings()
        )
        self.assertEqual("ru", builder.build()["locale"])


class TestEveClaims(SimpleTestCase):
    def test_only_non_empty_fields_emitted(self):
        # NPC corp case: corporation_id present, alliance_id missing.
        # The alliance fields must be omitted entirely (not rendered
        # as ``null``) so consumers can use ``"eve_alliance_id" in p``
        # as a presence test.
        builder = ClaimsBuilder(
            user=_user(
                main=_main(
                    character_id=1,
                    corporation_id=100,
                    corporation_name="ABC",
                    corporation_ticker="ABC",
                )
            ),
            settings=_settings(),
        )
        out = builder.build()
        self.assertEqual(1, out["eve_character_id"])
        self.assertEqual(100, out["eve_corporation_id"])
        self.assertEqual("ABC", out["eve_corporation_ticker"])
        self.assertNotIn("eve_alliance_id", out)
        self.assertNotIn("eve_alliance_name", out)

    def test_prefix_override_respected(self):
        # Prefix is read from settings on every call, so flipping it
        # via OIDCSettings produces the expected key namespace.
        builder = ClaimsBuilder(
            user=_user(main=_main(character_id=42)),
            settings=_settings(eve_claim_prefix="custom_"),
        )
        out = builder.build()
        self.assertIn("custom_character_id", out)
        self.assertNotIn("eve_character_id", out)

    def test_every_eve_claim_name_is_reachable_via_builder(self):
        # Anti-drift test: every EVE claim name declared in
        # ``_EVE_CLAIM_NAMES`` must be reachable through the builder.
        # If the tuple is extended without updating the EveCharacter
        # accessor list or the ``_main`` test factory, this surfaces
        # the gap as a missing key in the output dict.
        from allianceauth_oidc.claims import _EVE_CLAIM_NAMES

        kwargs = {n: f"v_{n}" for n in _EVE_CLAIM_NAMES}
        # character_id / *_id are typically int; the builder doesn't
        # care about type, just truthiness.
        builder = ClaimsBuilder(
            user=_user(main=_main(**kwargs)),  # type: ignore[arg-type]
            settings=_settings(),
        )
        out = builder.build()
        for name in _EVE_CLAIM_NAMES:
            self.assertIn(f"eve_{name}", out, f"missing eve_{name}")


class TestBuilderComposition(SimpleTestCase):
    def test_empty_user_returns_empty_dict(self):
        # User with nothing populated should produce no claims at all
        # (no email, no main, no state, no language, no groups).
        builder = ClaimsBuilder(user=_user(), settings=_settings())
        self.assertEqual({}, builder.build())

    def test_logger_can_be_injected(self):
        # Tests should be able to capture warnings from a per-test
        # logger instead of the module global. Inject one and confirm
        # it's the channel that fires.
        capture = logging.getLogger("test.claims_builder.injected")
        builder = ClaimsBuilder(
            user=_user(group_names=["a"], state_name="X"),
            settings=_settings(),
            max_groups=0,
            log=capture,
        )
        with self.assertLogs(capture, level="WARNING"):
            builder.build()
