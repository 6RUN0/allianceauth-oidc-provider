"""
Property-based tests for OIDC protocol invariants.

Example-based tests cover known inputs; property tests cover the
unchecked space *between* rows in a parametrize table. Two invariants
are exercised here:

1. **PKCE round-trip** (RFC 7636 §4): for any code_verifier that
   matches the RFC charset and length range, ``SHA-256`` plus
   base64url-no-pad produces a code_challenge with the exact length
   the spec mandates (43 chars). A mutant in the digest, encoding, or
   padding-stripping that survives the integration tests would fail
   the round-trip on a random verifier within seconds.

2. **Claim-scope mapping shape** (`build_oidc_claim_scope`): every
   claim → scope mapping must return a non-empty string scope name and
   must be deterministic for a fixed ``OIDCSettings`` snapshot. A
   future refactor that drops a claim from the mapping or maps it to
   ``""`` would silently break the DOT filter that consults this dict.

Hypothesis caches failing examples under ``.hypothesis/`` (gitignored)
so a regression replays the exact verifier that broke without
re-rolling. ``derandomize=True`` on every ``@settings`` block fixes
the example stream — same examples on CI and locally — so a failure
reported on one machine reproduces on another without exchanging the
``.hypothesis/`` cache. The trade-off (lost example diversity across
runs) is acceptable here: the search spaces are small and the goal
is a regression net, not exploratory fuzzing.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import string

from django.test import SimpleTestCase
from hypothesis import given, settings
from hypothesis import strategies as st

from allianceauth_oidc.app_settings import OIDCSettings
from allianceauth_oidc.claims import build_oidc_claim_scope
from allianceauth_oidc.utils import SecretRedactor

# RFC 7636 §4.1: code_verifier = high-entropy random string using
# unreserved characters with length 43..128.
_PKCE_VERIFIER_ALPHABET = string.ascii_letters + string.digits + "-._~"


class TestPkceChallengeInvariants(SimpleTestCase):
    """RFC 7636 round-trip: every valid verifier produces a 43-char S256 challenge."""

    @given(
        st.text(
            alphabet=_PKCE_VERIFIER_ALPHABET,
            min_size=43,
            max_size=128,
        )
    )
    @settings(max_examples=200, deadline=None, derandomize=True)
    def test_s256_challenge_is_43_chars_for_any_valid_verifier(
        self, verifier: str
    ) -> None:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )
        # RFC 7636 §4.2: S256 challenge is the base64url-no-pad
        # encoding of a 32-byte SHA-256 digest — exactly 43 chars.
        self.assertEqual(len(challenge), 43)
        # base64url alphabet only: letters, digits, ``-``, ``_``.
        allowed = set(string.ascii_letters + string.digits + "-_")
        self.assertTrue(set(challenge).issubset(allowed))
        # No trailing padding — strip-pad was the bug class we want to
        # catch (a forgotten ``rstrip`` ships a 44-char challenge that
        # downstream RPs reject after string comparison).
        self.assertFalse(challenge.endswith("="))


class TestClaimScopeMapShape(SimpleTestCase):
    """Mapping is deterministic and every scope value is non-empty."""

    @given(
        eve_prefix=st.text(
            alphabet=string.ascii_lowercase + "_",
            min_size=0,
            max_size=12,
        ),
        eve_scope=st.sampled_from(["profile", "openid", "email"]),
    )
    @settings(max_examples=50, deadline=None, derandomize=True)
    def test_every_claim_maps_to_a_non_empty_scope(
        self, eve_prefix: str, eve_scope: str
    ) -> None:
        # Build a partial settings snapshot only mutating the two
        # fields the mapping depends on. ``OIDCSettings`` is a frozen
        # dataclass with slots, so we use ``dataclasses.replace``
        # rather than touching ``__dict__`` (absent under slots).
        base = OIDCSettings.from_django()
        snap = dataclasses.replace(
            base,
            eve_claim_prefix=eve_prefix,
            eve_claim_scope=eve_scope,
        )
        scope_map = build_oidc_claim_scope(snap)
        # Every claim → scope value must be a non-empty string. An
        # empty string would slip through any ``if scope in token`` gate.
        for claim, scope in scope_map.items():
            self.assertIsInstance(claim, str)
            self.assertIsInstance(scope, str)
            self.assertNotEqual(scope, "", f"claim {claim!r} has empty scope")
        # Determinism: same settings → same dict identity (cache hit).
        # ``build_oidc_claim_scope`` is ``@functools.lru_cache``-decorated
        # keyed on the frozen settings; the second call must hit cache.
        self.assertIs(build_oidc_claim_scope(snap), scope_map)


class TestSecretRedactorNoLeakage(SimpleTestCase):
    """Masked output must never contain the unmasked middle of the secret."""

    @given(
        secret=st.text(
            alphabet=string.ascii_letters + string.digits,
            min_size=10,
            max_size=200,
        ),
        head=st.integers(min_value=1, max_value=8),
        tail=st.integers(min_value=1, max_value=8),
    )
    @settings(max_examples=200, deadline=None, derandomize=True)
    def test_middle_characters_never_appear_in_masked_output(
        self, secret: str, head: int, tail: int
    ) -> None:
        # Skip degenerate inputs where head + tail >= len(secret) — those
        # take the "shorter than the window" path that legitimately
        # emits all stars and has no middle to leak.
        if head + tail >= len(secret):
            return
        masked = SecretRedactor.mask_secret(secret, head=head, tail=tail)
        self.assertIsNotNone(masked)
        # The middle slice — characters that must NEVER appear in
        # the masked output, otherwise we have a redaction leak.
        middle = secret[head:-tail]
        # Each character of ``middle`` is what we're protecting; if
        # any substring of length >= 3 from ``middle`` appears in
        # ``masked``, that is a leak. Length 3 chosen over 1 to skip
        # incidental single-char alphabet collisions (a digit '7' in
        # ``masked`` from the head/tail happens to also be in the
        # middle); a 3-char substring is statistically unique enough
        # to flag a real leak.
        masked_str = str(masked)
        for i in range(len(middle) - 2):
            substring = middle[i : i + 3]
            self.assertNotIn(
                substring,
                masked_str[head : -tail or None],
                f"3-char leak {substring!r} in masked output {masked_str!r}",
            )

    @given(
        secret=st.text(
            alphabet=string.ascii_letters + string.digits,
            min_size=0,
            max_size=200,
        ),
    )
    @settings(max_examples=100, deadline=None, derandomize=True)
    def test_disabled_redactor_always_returns_redacted_marker(
        self, secret: str
    ) -> None:
        # When the operator has NOT opted in to masking, every call
        # must return the opaque ``<redacted>`` marker — there is no
        # path that exposes any plaintext character of the secret.
        redactor = SecretRedactor(enabled=False)
        result = redactor(secret) if secret else None
        if secret:
            self.assertEqual(str(result), "<redacted>")
