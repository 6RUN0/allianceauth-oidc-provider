"""
Unit tests for ``allianceauth_oidc.app_settings``.

Pure-Python tests over the ``OIDCSettings`` dataclass — no database,
no ``OIDCTestCase`` fixture. Validation is the main concern here:
``__post_init__`` is the operator-facing fail-fast boundary, so each
rejected value gets an explicit case.
"""

import dataclasses

from django.test import SimpleTestCase, override_settings

from allianceauth_oidc.app_settings import (
    EVE_PORTRAIT_VALID_SIZES,
    OIDCSettings,
    _cached_snapshot,
)


def _good_kwargs(**overrides: object) -> dict:
    """Default ctor kwargs that pass validation; ``**overrides`` to mutate."""
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
    }
    base.update(overrides)
    return base


class TestOIDCSettingsValidation(SimpleTestCase):
    def test_default_kwargs_pass_validation(self):
        # Sanity check: the helper itself produces a valid snapshot.
        settings = OIDCSettings(**_good_kwargs())
        self.assertEqual(128, settings.portrait_size)

    def test_negative_log_mask_head_rejected(self):
        with self.assertRaisesRegex(ValueError, "LOG_MASK_HEAD"):
            OIDCSettings(**_good_kwargs(log_mask_head=-1))

    def test_negative_log_mask_tail_rejected(self):
        with self.assertRaisesRegex(ValueError, "LOG_MASK_TAIL"):
            OIDCSettings(**_good_kwargs(log_mask_tail=-1))

    def test_invalid_portrait_size_rejected(self):
        # 100 is not one of EVE's served sizes; the full set is the
        # invariant we want to surface in the error message.
        with self.assertRaisesRegex(ValueError, "PORTRAIT_SIZE"):
            OIDCSettings(**_good_kwargs(portrait_size=100))

    def test_every_eve_valid_size_accepted(self):
        # Documented invariant: the validator's accepted set matches
        # ``EVE_PORTRAIT_VALID_SIZES``. If the constant changes, this
        # test will catch the regression alongside the validator.
        for size in EVE_PORTRAIT_VALID_SIZES:
            with self.subTest(size=size):
                settings = OIDCSettings(**_good_kwargs(portrait_size=size))
                self.assertEqual(size, settings.portrait_size)

    def test_frozen_instance_rejects_mutation(self):
        # ``frozen=True`` is part of the contract — request-path code
        # should not be able to flip ``log_masked_secrets`` mid-flight.
        settings = OIDCSettings(**_good_kwargs())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            settings.log_masked_secrets = True  # type: ignore[misc]


class TestOIDCSettingsFromDjango(SimpleTestCase):
    def test_defaults_match_legacy_accessors(self):
        # With no overrides, the classmethod must produce the same
        # values the seven free accessors return; this guards against
        # drift between OIDCSettings and the legacy free functions.
        snap = OIDCSettings.from_django()
        self.assertFalse(snap.log_masked_secrets)
        self.assertEqual(2, snap.log_mask_head)
        self.assertEqual(2, snap.log_mask_tail)
        self.assertEqual(128, snap.portrait_size)
        self.assertEqual("eve_", snap.eve_claim_prefix)
        self.assertEqual("profile", snap.eve_claim_scope)
        # AA's REGISTRATION_VERIFY_EMAIL defaults to True; mirrors here.
        self.assertTrue(snap.email_verified_default)

    @override_settings(REGISTRATION_VERIFY_EMAIL=False)
    def test_email_verified_default_follows_aa_setting(self):
        # When the operator disabled AA's email confirmation step,
        # we must NOT claim verification — emit ``False``.
        snap = OIDCSettings.from_django()
        self.assertFalse(snap.email_verified_default)

    def test_force_email_verified_default_is_none(self):
        # Absent setting → None → auto decision tree authoritative.
        snap = OIDCSettings.from_django()
        self.assertIsNone(snap.force_email_verified)

    @override_settings(ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED=True)
    def test_force_email_verified_true_normalised(self):
        snap = OIDCSettings.from_django()
        self.assertIs(True, snap.force_email_verified)

    @override_settings(ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED=False)
    def test_force_email_verified_false_normalised(self):
        snap = OIDCSettings.from_django()
        self.assertIs(False, snap.force_email_verified)

    @override_settings(ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED=1)
    def test_force_email_verified_truthy_int_coerced_to_bool(self):
        # Operators occasionally write ``1`` instead of ``True`` in
        # settings.py; accept it as the obvious intent.
        snap = OIDCSettings.from_django()
        self.assertIs(True, snap.force_email_verified)

    @override_settings(
        ALLIANCEAUTH_OIDC_LOG_MASKED_SECRETS=True,
        ALLIANCEAUTH_OIDC_LOG_MASK_HEAD=4,
        ALLIANCEAUTH_OIDC_LOG_MASK_TAIL=4,
        ALLIANCEAUTH_OIDC_PORTRAIT_SIZE=512,
        ALLIANCEAUTH_OIDC_EVE_CLAIM_PREFIX="custom_",
        ALLIANCEAUTH_OIDC_EVE_CLAIM_SCOPE="eve",
    )
    def test_override_settings_reflected_in_snapshot(self):
        # Regression: a previous implementation snapshotted at import,
        # so @override_settings was invisible. The classmethod reads
        # the live settings on every call, so each test sees its own
        # values.
        snap = OIDCSettings.from_django()
        self.assertTrue(snap.log_masked_secrets)
        self.assertEqual(4, snap.log_mask_head)
        self.assertEqual(4, snap.log_mask_tail)
        self.assertEqual(512, snap.portrait_size)
        self.assertEqual("custom_", snap.eve_claim_prefix)
        self.assertEqual("eve", snap.eve_claim_scope)


class TestSnapshotCaching(SimpleTestCase):
    """
    Cover the ``functools.lru_cache`` backing of ``from_django()``.

    Production avoids the seven-getattr + validation cost on every
    claim build; tests cover identity cache hit, ``setting_changed``
    invalidation under ``@override_settings``, and the ``startswith``
    filter that prevents non-OIDC setting flips from busting the cache.
    """

    def setUp(self) -> None:
        # Each test starts with a clean cache so prior tests'
        # @override_settings exits cannot leak a stale entry.
        _cached_snapshot.cache_clear()

    def test_repeated_from_django_returns_same_instance(self):
        a = OIDCSettings.from_django()
        b = OIDCSettings.from_django()
        self.assertIs(a, b)
        info = _cached_snapshot.cache_info()
        self.assertEqual(1, info.hits)
        self.assertEqual(1, info.misses)

    def test_override_settings_invalidates_cache(self):
        first = OIDCSettings.from_django()
        self.assertEqual(128, first.portrait_size)
        with override_settings(ALLIANCEAUTH_OIDC_PORTRAIT_SIZE=512):
            second = OIDCSettings.from_django()
        self.assertEqual(512, second.portrait_size)
        # Exiting the override block re-fires setting_changed, so the
        # next read is the post-override value (back to default).
        third = OIDCSettings.from_django()
        self.assertEqual(128, third.portrait_size)
        self.assertIsNot(first, second)
        self.assertIsNot(second, third)

    @override_settings(USE_TZ=False)
    def test_unrelated_setting_does_not_bust_cache(self):
        # Only ALLIANCEAUTH_OIDC_* changes should clear the cache.
        # Without this guard, every Django setting flip would force a
        # snapshot rebuild; the @override_settings above would have
        # cleared the cache during setUp.
        a = OIDCSettings.from_django()
        b = OIDCSettings.from_django()
        self.assertIs(a, b)
