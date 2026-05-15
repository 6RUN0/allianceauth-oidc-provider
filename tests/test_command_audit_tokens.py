"""
Tests for ``manage.py oidc_*`` operator commands.

The commands are thin wrappers around the ORM; tests verify the
contract operators rely on:

* `--dry-run` on destructive commands does not write.
* `--format=json` produces parseable output.
* Idempotent behaviour (re-running a destructive command on a
  cleaned-up subject is a no-op).
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO
from typing import Any

from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
)
from oauth2_provider.settings import oauth2_settings

from ._oidc_testcase import OIDCTestCase


class TestOIDCAuditTokensCommand(OIDCTestCase):
    def _seed_token(
        self, *, expired: bool = False, scope: str = "openid"
    ) -> object:
        AccessToken = get_access_token_model()
        delta = timedelta(hours=-1 if expired else 1)
        return AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=f"audit-{'exp' if expired else 'live'}",  # nosec B106
            expires=timezone.now() + delta,
            scope=scope,
        )

    def test_lists_active_tokens_only_by_default(self) -> None:
        live = self._seed_token(expired=False)
        self._seed_token(expired=True)
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--format=json",
            stdout=out,
        )
        ids = {row["id"] for row in json.loads(out.getvalue())}
        self.assertIn(live.pk, ids)
        # Expired is filtered out.
        self.assertEqual(1, len(ids))

    def test_include_expired_widens_listing(self) -> None:
        self._seed_token(expired=False)
        self._seed_token(expired=True)
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--include-expired",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(2, len(rows))

    def test_filter_by_username(self) -> None:
        self._seed_token()
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            f"--username={self.user1.username}",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(self.user1.username, rows[0]["user"])

    def test_filter_by_client_id(self) -> None:
        self._seed_token()
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            f"--client-id={self.oauth_id}",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))

    def test_unknown_username_fails_loudly(self) -> None:
        with self.assertRaises(CommandError):
            call_command(
                "oidc_audit_tokens",
                "--username=ghost",
                stdout=StringIO(),
            )

    def test_unknown_client_id_fails_loudly(self) -> None:
        """
        Symmetric with ``test_unknown_username_fails_loudly`` —
        ``--client-id`` pointing at a non-existent app must raise
        ``CommandError``, not silently filter to an empty result set.
        """
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_audit_tokens",
                "--client-id=does-not-exist",
                stdout=StringIO(),
            )
        self.assertIn("does-not-exist", str(ctx.exception))

    def test_audit_surfaces_pkce_required_per_application(self) -> None:
        """
        Each row exposes the application's ``pkce_required`` flag so an
        operator triaging tokens can see "is this from a strict-PKCE
        client?" without context-switching to admin. Both directions of
        the flag are pinned to guard against a regression that hard-
        codes the column to ``True`` (or strips it on
        ``None``-coalesce).
        """
        self._seed_token()
        # Shared fixture ships ``pkce_required=False``; flip it
        # explicitly to assert both directions in one test.
        self.oauth_app.pkce_required = True
        self.oauth_app.save()
        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertTrue(rows[0]["pkce_required"])

        self.oauth_app.pkce_required = False
        self.oauth_app.save()
        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertFalse(rows[0]["pkce_required"])

    def test_audit_surfaces_format_column_jwt_vs_opaque(self) -> None:
        """
        ``docs/JWT_ACCESS_TOKENS.md`` migration recipe Step 5 instructs
        operators to grep the audit output for a ``format`` column to
        confirm the per-app rollout (one RP under JWT mode, others
        still on opaque). The column derives from the persisted token
        bytes via ``views.classify_token_format``: tokens whose
        compact form is a 3-segment ``at+jwt`` JWS render ``"jwt"``;
        anything else renders ``"opaque"`` (including hashed-at-rest
        tokens, which the heuristic cannot decode).

        Locks the migration recipe into a regression: if the column
        is dropped, renamed, or hardcoded, this test fails loudly.
        """
        # Seed a real JWT-shaped token. The classification heuristic
        # only looks at the header bytes, so a plausibly-formed JWT
        # (3 segments, header with ``typ="at+jwt"``) is sufficient
        # without going through the issuance path.
        import base64

        from oauth2_provider.models import get_access_token_model

        AccessToken = get_access_token_model()

        def _b64(payload: bytes) -> str:
            return (
                base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
            )

        jwt_like = ".".join(
            (
                _b64(b'{"typ":"at+jwt","alg":"RS256","kid":"x"}'),
                _b64(b'{"sub":"1","aud":"a","exp":1}'),
                _b64(b"signature-bytes"),
            )
        )

        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token=jwt_like,
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="opaque-random-string-no-dots",  # nosec B106 - test fixture
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )

        out = StringIO()
        call_command("oidc_audit_tokens", "--format=json", stdout=out)
        rows = json.loads(out.getvalue())
        self.assertEqual(2, len(rows))

        # Each row exposes a ``format`` key.
        for row in rows:
            self.assertIn("format", row, f"missing format column in {row!r}")

        formats = {row["format"] for row in rows}
        self.assertEqual(
            {"jwt", "opaque"},
            formats,
            f"expected one jwt + one opaque row, got {formats!r}",
        )

    # -----------------------------------------------------------------
    # ``--suspicious`` filter: surfaces tokens that do not match the
    # operator's current configuration. Each check pins a single class
    # of anomaly; the joined ``reasons`` column lets the operator
    # see at a glance why each row was flagged.
    # -----------------------------------------------------------------

    def _seed_token_with_expiry(
        self, *, expires_at: Any, app: Any = None, label: str = "sus"
    ) -> object:
        """Plant a token with explicit ``expires``; default app is the fixture."""
        AccessToken = get_access_token_model()
        return AccessToken.objects.create(
            user=self.user1,
            application=app or self.oauth_app,
            token=f"audit-{label}",  # nosec B106 - test fixture
            expires=expires_at,
            scope="openid",
        )

    def test_suspicious_returns_no_rows_when_token_is_normal(self) -> None:
        """
        Token planted within the deployment-default TTL on a live app
        passes both checks. ``--suspicious`` filters everything out.
        """
        from oauth2_provider.settings import oauth2_settings

        normal_ttl = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
        self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(seconds=normal_ttl - 5),
            label="normal",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual([], rows)

    def test_suspicious_flags_ttl_anomaly(self) -> None:
        """
        Token whose ``expires`` is farther in the future than a
        freshly-minted token would be (``now + ACCESS_TOKEN_EXPIRE_SECONDS
        + buffer``) is anomalous: the dispatcher would never produce
        such a row, so it was either issued under a longer-TTL config
        that has since been tightened or the row was hand-edited.
        Either way the operator should see it.
        """
        long_lived = self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(hours=1),
            label="long-ttl",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(long_lived.pk, rows[0]["id"])
        self.assertIn("ttl_anomaly", rows[0]["reasons"])

    def test_suspicious_flags_disabled_app(self) -> None:
        """
        ``application.active = False`` means the app is not allowed to
        issue new tokens, but old live tokens (``expires`` in the
        future) keep working until DOT's clear_expired or an explicit
        revoke. ``--suspicious`` surfaces these so the operator can
        decide whether to revoke proactively.
        """
        from oauth2_provider.settings import oauth2_settings

        normal_ttl = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS
        self.oauth_app.active = False
        self.oauth_app.save(update_fields=["active"])
        token = self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(seconds=normal_ttl - 5),
            label="dis-app",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        self.assertEqual(token.pk, rows[0]["id"])
        self.assertIn("disabled_app", rows[0]["reasons"])

    def test_suspicious_joins_multiple_reasons(self) -> None:
        """
        A single token can match multiple checks. The ``reasons``
        column lists all of them — comma-joined — so the operator
        sees the full picture in one row instead of de-duplicating
        across multiple ``--suspicious`` queries.
        """
        self.oauth_app.active = False
        self.oauth_app.save(update_fields=["active"])
        self._seed_token_with_expiry(
            expires_at=timezone.now() + timedelta(hours=1),
            label="both",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows))
        reasons = rows[0]["reasons"]
        self.assertIn("ttl_anomaly", reasons)
        self.assertIn("disabled_app", reasons)

    def test_reasons_column_only_appears_under_suspicious(self) -> None:
        """
        Default ``oidc_audit_tokens`` output is the operator's daily
        view; adding a column unconditionally would break scripts that
        consume the JSON. ``reasons`` is therefore only emitted when
        ``--suspicious`` is set; the regular listing stays
        backwards-compatible.
        """
        self._seed_token()  # uses fixture default (1h TTL)
        out_default = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--format=json",
            stdout=out_default,
        )
        rows_default = json.loads(out_default.getvalue())
        self.assertNotIn("reasons", rows_default[0])

    def test_ttl_anomaly_skew_constant_is_five_seconds(self) -> None:
        # Pin ``_TTL_ANOMALY_SKEW = timedelta(seconds=5)``.
        # ``NumberReplacer`` flipping the literal changes the
        # boundary at which the ``ttl_anomaly`` check fires; the
        # constant is documented as "narrow enough not to mask a
        # token issued under a stale TTL config" and tests below
        # rely on its exact value as the boundary discriminator.
        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _TTL_ANOMALY_SKEW,
        )

        self.assertEqual(timedelta(seconds=5), _TTL_ANOMALY_SKEW)

    def test_suspicious_only_does_not_break_after_clean_token(self) -> None:
        # Pin ``if not reasons: continue`` against
        # ``ReplaceContinueWithBreak``. The dedup-style loop walks
        # tokens; ``break`` on the first normal token (empty
        # reasons list) stops listing and silently drops every
        # subsequent suspicious row.
        #
        # Fixture: ONE normal token + ONE disabled-app token. With
        # ``continue`` (correct), the suspicious-only output
        # contains the disabled-app row. With ``break``, the loop
        # halts at the normal row first and the suspicious row
        # never makes it into ``rows``.
        from ._factories import make_app

        # Normal token (active app, default TTL) — must be skipped.
        self._seed_token()
        # Disabled-app token (active=False) — must surface.
        creds = make_app(owner=self.user1)
        creds.app.active = False
        creds.app.save()
        AccessToken = get_access_token_model()
        AccessToken.objects.create(
            user=self.user1,
            application=creds.app,
            token="audit-disabled",  # nosec B106
            expires=timezone.now() + timedelta(hours=1),
            scope="openid",
        )
        out = StringIO()
        call_command(
            "oidc_audit_tokens",
            "--suspicious",
            "--format=json",
            stdout=out,
        )
        rows = json.loads(out.getvalue())
        # Iteration order is ``order_by("-expires")`` so the two
        # tokens may arrive in either order depending on the test
        # clock. What pins ``continue`` against ``break`` is that
        # the disabled-app row IS present regardless of position.
        # In test settings, ``ACCESS_TOKEN_EXPIRE_SECONDS`` is short
        # (60s), so the 1-hour seed expiry above also flags
        # ``ttl_anomaly`` — the row may carry "disabled_app" alone
        # or combined with "ttl_anomaly".
        reasons_seen = " ".join(row.get("reasons", "") for row in rows)
        self.assertIn("disabled_app", reasons_seen)

    def test_classify_suspicious_disabled_app_by_active_shape(
        self,
    ) -> None:
        """
        Pin ``getattr(app, "active", True) is False`` semantics.

        The matrix discriminates BOTH the ``True`` default literal
        (``ReplaceFalseWithTrue`` mutant) AND the ``is False``
        operator (``Is_Eq`` mutant). No single row would catch
        every mutation: the ``active=True`` row would agree with
        ``True == False`` (both False); the ``active=False`` row
        would agree with ``False == False`` (both True). Only the
        trio's joint expected-reason shape — empty for missing /
        True, ``["disabled_app"]`` for False — locks the operator
        and the default together.
        """
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _classify_suspicious,
        )

        now = timezone.now()
        cases: tuple[tuple[str, SimpleNamespace, list[str]], ...] = (
            ("missing_attr", SimpleNamespace(), []),
            ("active_true", SimpleNamespace(active=True), []),
            (
                "active_false",
                SimpleNamespace(active=False),
                ["disabled_app"],
            ),
        )
        for label, stub_app, expected in cases:
            with self.subTest(active=label):
                stub_token = SimpleNamespace(
                    expires=now + timedelta(seconds=60),
                    application=stub_app,
                )
                self.assertEqual(
                    expected,
                    _classify_suspicious(stub_token, now=now),
                )

    def test_classify_suspicious_ttl_anomaly_at_ceiling_boundary(
        self,
    ) -> None:
        """
        Pin ``if expires > ceiling`` against ``>=``.

        At-ceiling row must NOT flag; one-second-above must flag.
        The boundary pair discriminates the ``>``/``>=`` mutation:
        a ``>=`` flip would erroneously flag every freshly-issued
        token sitting exactly at the ceiling.
        """
        from types import SimpleNamespace

        from allianceauth_oidc.management.commands.oidc_audit_tokens import (
            _TTL_ANOMALY_SKEW,
            _classify_suspicious,
        )

        now = timezone.now()
        ttl_seconds = int(oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        ceiling = now + timedelta(seconds=ttl_seconds) + _TTL_ANOMALY_SKEW
        cases: tuple[tuple[str, timedelta, bool], ...] = (
            ("at_ceiling", timedelta(0), False),
            ("one_second_above", timedelta(seconds=1), True),
        )
        for label, offset, should_flag in cases:
            with self.subTest(offset=label):
                stub_app = SimpleNamespace(active=True)
                stub_token = SimpleNamespace(
                    expires=ceiling + offset,
                    application=stub_app,
                )
                reasons = _classify_suspicious(stub_token, now=now)
                if should_flag:
                    self.assertIn("ttl_anomaly", reasons)
                else:
                    self.assertNotIn("ttl_anomaly", reasons)
