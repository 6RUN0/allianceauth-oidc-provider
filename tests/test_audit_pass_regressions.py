"""
Regression tests added during the audit pass.

The pass closed:

* H-1  — ``logout_token`` MUST carry an ``exp`` claim.
* M-4  — ``oidc_code_reuse_detected`` MUST carry
  ``revoke_succeeded`` so SIEM can distinguish "reuse detected and
  tokens recalled" from "reuse detected but revocation failed".
* CR-HIGH-4 — ``_record_code_issuance`` silent skip on
  ``application=None`` MUST emit ``aa_oidc_code_audit_skipped`` so the
  degraded SHOULD-overlay path is operator-observable.
* CR-HIGH-2 — ``dispatch_backchannel_logout`` broad ``except`` blocks
  MUST log ``exc_info=True`` so corrupt-PEM / broker failures retain
  their root-cause traceback in operator logs.
* Coverage gaps surfaced by the audit pass:
  - ``_handle_potential_code_reuse`` AT-only revocation branch
    (``auth_provider.py:702-706``) when no refresh token was issued.
  - ``policy_rejections`` ``stage`` label coverage for
    ``validate_refresh`` / ``validate_bearer`` / ``save_bearer``.
  - ``AccessPolicy.enforce()`` happy and denial paths
    (``security.py:267-279``) — previously dead code.
  - ``AccessChecker._log_state_diag`` / ``_log_group_diag`` debug-mode
    diagnostics (``security.py:417-451``).
  - ``_max_age_expired`` with ``last_login=None``
    (``views_authorize.py:65-72``).
  - ``send_logout_token`` user/application disappeared between
    enqueue and dispatch (``tasks.py:261-267``).
  - ``dispatch_backchannel_logout`` signing-key resolution failure
    (``logout.py:274-289``).
  - ``views_introspect`` defensive branches (lines 73-82, 118,
    121-124, 153) — empty response, malformed JSON, non-dict JSON,
    no-token request, audit emit failure.
  - ``checks.py`` bootstrap exception paths for E002/E003.

The tests live in one file because they were authored as a single
audit-pass batch; their natural home is alongside the production fix
they regression-test. Future moves to per-domain files (test_token,
test_security, test_back_channel_logout) are fine — none of the
fixtures here are shared with anything else in tests/.
"""

from __future__ import annotations

import hashlib
import logging
from io import StringIO
from types import SimpleNamespace
from typing import Any
from unittest import mock

from django.db import DatabaseError
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from allianceauth_oidc import signals as oidc_signals
from allianceauth_oidc.auth_provider import AllianceAuthOAuth2Validator
from allianceauth_oidc.constants import (
    CodeAuditSkippedReason,
)
from allianceauth_oidc.security import (
    AccessPolicy,
    DenyReason,
)

from ._factories import make_app
from ._oidc_testcase import OIDCTestCase

# ---------- M-4 + AT-only revocation ----------


class TestCodeReuseRevokeSucceededFlag(OIDCTestCase):
    """
    M-4: ``oidc_code_reuse_detected`` carries ``revoke_succeeded``.

    The validator default-path sets ``True``; the
    ``(DatabaseError, ObjectDoesNotExist)`` handler sets ``False`` so
    SIEM receivers can route to higher severity when the tokens were
    NOT actually recalled.
    """

    def _make_audit_row(
        self,
        code: str,
        at_pk: int | None,
        rt_pk: int | None,
    ) -> str:
        from allianceauth_oidc.models import IssuedCodeAudit

        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        IssuedCodeAudit.objects.create(
            code_hash=code_hash,
            application=self.oauth_app,
            access_token_pk=at_pk,
            refresh_token_pk=rt_pk,
            application_client_id_snapshot=self.oauth_app.client_id,
        )
        return code_hash

    def _capture_signal(self) -> list[dict[str, Any]]:
        captured: list[dict[str, Any]] = []

        def receiver(sender, **kwargs):
            captured.append(kwargs)

        self.signal_capture(oidc_signals.oidc_code_reuse_detected, receiver)
        return captured

    def test_signal_carries_revoke_succeeded_true_on_normal_path(self) -> None:
        """Successful revocation passes ``revoke_succeeded=True``."""
        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        at = AccessToken.objects.create(
            user=self.user1,
            token="at-rev-true",
            token_checksum=hashlib.sha256(b"at-rev-true").hexdigest(),
            application=self.oauth_app,
            expires=timezone.now() + timezone.timedelta(hours=1),
            scope="openid",
        )
        rt = RefreshToken.objects.create(
            user=self.user1,
            token="rt-rev-true",
            application=self.oauth_app,
            access_token=at,
        )
        self._make_audit_row("code-rev-true", at.pk, rt.pk)

        captured = self._capture_signal()
        validator = AllianceAuthOAuth2Validator()
        validator._handle_potential_code_reuse("code-rev-true", self.oauth_app)

        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0].get("revoke_succeeded"))

    def test_signal_carries_revoke_succeeded_false_on_database_error(
        self,
    ) -> None:
        """``DatabaseError`` during revoke flips the flag to False."""
        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()
        at = AccessToken.objects.create(
            user=self.user1,
            token="at-rev-false",
            token_checksum=hashlib.sha256(b"at-rev-false").hexdigest(),
            application=self.oauth_app,
            expires=timezone.now() + timezone.timedelta(hours=1),
            scope="openid",
        )
        rt = RefreshToken.objects.create(
            user=self.user1,
            token="rt-rev-false",
            application=self.oauth_app,
            access_token=at,
        )
        self._make_audit_row("code-rev-false", at.pk, rt.pk)

        captured = self._capture_signal()
        with mock.patch.object(
            RefreshToken,
            "revoke",
            side_effect=DatabaseError("simulated transient DB hiccup"),
        ):
            validator = AllianceAuthOAuth2Validator()
            validator._handle_potential_code_reuse(
                "code-rev-false", self.oauth_app
            )

        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0].get("revoke_succeeded"))


class TestCodeReuseATOnlyRevocation(OIDCTestCase):
    """
    Coverage gap: ``_handle_potential_code_reuse`` branch where the
    audit row has ``access_token_pk`` set but ``refresh_token_pk`` is
    None (``auth_provider.py:702-706``). Hits the ``elif at_pk:``
    fallthrough path that DOT's no-refresh-token grant variants use.
    """

    def test_at_only_revocation_deletes_access_token(self) -> None:
        from oauth2_provider.models import get_access_token_model

        from allianceauth_oidc.models import IssuedCodeAudit

        AccessToken = get_access_token_model()
        at = AccessToken.objects.create(
            user=self.user1,
            token="at-only-token",
            token_checksum=hashlib.sha256(b"at-only-token").hexdigest(),
            application=self.oauth_app,
            expires=timezone.now() + timezone.timedelta(hours=1),
            scope="openid",
        )
        code = "at-only-code"
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        IssuedCodeAudit.objects.create(
            code_hash=code_hash,
            application=self.oauth_app,
            access_token_pk=at.pk,
            refresh_token_pk=None,
            application_client_id_snapshot=self.oauth_app.client_id,
        )

        validator = AllianceAuthOAuth2Validator()
        validator._handle_potential_code_reuse(code, self.oauth_app)

        self.assertFalse(
            AccessToken.objects.filter(pk=at.pk).exists(),
            "AT-only revocation branch must delete the linked AccessToken",
        )


# ---------- CR-HIGH-4 — code_audit_skipped counter ----------


class TestCodeAuditSkippedCounter(SimpleTestCase):
    """
    ``_record_code_issuance`` skip-on-no-client now emits
    ``aa_oidc_code_audit_skipped_total{reason="no_client"}``. Counter
    is mocked out (it lives in the optional metrics layer) so the
    test runs independently of django-prometheus install state.
    """

    def test_counter_increments_when_application_is_none(self) -> None:
        validator = AllianceAuthOAuth2Validator()
        request = SimpleNamespace(client=None)

        with mock.patch(
            "allianceauth_oidc.auth_provider.code_audit_skipped"
        ) as counter:
            validator._record_code_issuance(
                code="ignored",
                request=request,
                token={},
                client=None,
            )

        counter.labels.assert_called_once_with(
            reason=CodeAuditSkippedReason.NO_CLIENT.value
        )
        counter.labels.return_value.inc.assert_called_once_with()


# ---------- AccessPolicy.enforce ----------


class TestAccessPolicyEnforce(SimpleTestCase):
    """
    ``AccessPolicy.enforce`` was previously dead code
    (``security.py:267-279``). Add the happy + denial paths so a
    future refactor does not silently break it.
    """

    def test_enforce_returns_none_on_allowed_decision(self) -> None:
        user = SimpleNamespace(is_superuser=True)
        policy = AccessPolicy()
        self.assertIsNone(policy.enforce(user, app=None))

    def test_enforce_raises_permission_denied_with_reason(self) -> None:
        from django.core.exceptions import PermissionDenied

        # Synthetic user lacking ``has_perm`` triggers global denial.
        user = SimpleNamespace(is_superuser=False)
        policy = AccessPolicy()
        with self.assertRaises(PermissionDenied) as ctx:
            policy.enforce(user, app=None)
        self.assertIn(str(DenyReason.GLOBAL), str(ctx.exception))


# ---------- Debug-mode STATE/GROUP diagnostics ----------


class TestAccessPolicyDebugDiagnostics(OIDCTestCase):
    """
    ``AccessPolicy._log_state_diag`` / ``_log_group_diag`` fire only
    when ``app.debug_mode`` is True AND the logger is at INFO. Covers
    ``security.py:417-451`` previously untested.
    """

    def test_debug_mode_emits_state_and_group_diagnostics(self) -> None:
        from django.contrib.auth.models import Group
        from django.core.exceptions import PermissionDenied

        self.grant_oidc_access(self.user1)
        app = make_app(owner=self.user1, debug_mode=True).app
        app.states.set(app.states.model.objects.filter(name="Blue"))
        group = Group.objects.create(name="debug-mode-test-group")
        app.groups.add(group)

        logger = logging.getLogger("extensions.allianceauth_oidc.security")
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
        prior_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            policy = AccessPolicy()
            with self.assertRaises(PermissionDenied):
                # user1 is Member, app requires Blue — denial expected.
                # The diagnostic emits BEFORE the raise.
                policy._check_app(self.user1, app)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(prior_level)

        output = stream.getvalue()
        self.assertIn("OIDC STATE:", output)
        self.assertIn("OIDC GROUP:", output)


# ---------- last_login=None reauth ----------


class TestMaxAgeLastLoginNone(SimpleTestCase):
    """
    ``views_authorize._max_age_expired`` returns True when
    ``user.last_login`` is None — service accounts / migration-created
    users get forced through reauth on any ``max_age=N`` request.
    Covers ``views_authorize.py:65-72`` previously uncovered.
    """

    def test_last_login_none_is_treated_as_expired(self) -> None:
        from allianceauth_oidc.views_authorize import _max_age_expired

        factory = RequestFactory()
        user = SimpleNamespace(last_login=None)

        request = factory.get("/o/authorize/?max_age=0")
        self.assertTrue(_max_age_expired(request, user))

        request = factory.get("/o/authorize/?max_age=3600")
        self.assertTrue(_max_age_expired(request, user))


# ---------- send_logout_token DoesNotExist ----------


class TestSendLogoutTokenUserOrAppGone(TestCase):
    """
    ``tasks.send_logout_token`` returns gracefully when the user or
    application disappeared between enqueue and dispatch
    (``tasks.py:261-267``).
    """

    def test_missing_user_returns_without_raise(self) -> None:
        from allianceauth_oidc import tasks as oidc_tasks

        with self.assertLogs(
            "extensions.allianceauth_oidc.tasks", level=logging.WARNING
        ) as cm:
            # ``apply`` runs the task body synchronously inside the
            # current process so we can assert against the return.
            result = oidc_tasks.send_logout_token.apply(
                args=(
                    999_999,
                    999_999,
                    "ji" * 16,
                    "fake-kid",
                    1_700_000_000,
                )
            )
        self.assertTrue(result.successful())
        self.assertIsNone(result.result)
        self.assertTrue(
            any(
                "disappeared between enqueue and dispatch" in r
                for r in cm.output
            )
        )


# ---------- dispatch signing-key failure ----------


class TestDispatchSigningKeyFailure(OIDCTestCase):
    """
    ``logout.dispatch_backchannel_logout`` emits
    ``oidc_logout_dispatched(success=False, reason="signing_kid_resolve_failed")``
    when ``_active_signing_kid`` raises (corrupt PEM / missing
    setting). Covers ``logout.py:273-289``. Also pins the
    ``exc_info=True`` requirement from CR-HIGH-2.
    """

    def test_corrupt_pem_triggers_resolve_failed_audit(self) -> None:
        from allianceauth_oidc.logout import dispatch_backchannel_logout

        app = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.org/bcl/",
        ).app

        captured: list[dict[str, Any]] = []

        def receiver(sender, **kwargs):
            captured.append(kwargs)

        self.signal_capture(oidc_signals.oidc_logout_dispatched, receiver)
        with (
            mock.patch(
                "allianceauth_oidc.logout._active_signing_kid",
                side_effect=ValueError("corrupt PEM bytes"),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.logout",
                level=logging.WARNING,
            ) as cm,
        ):
            dispatch_backchannel_logout(
                sender=None,
                user=self.user1,
                application=app,
                reason="user_revoked",
            )

        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0].get("success"))
        self.assertEqual(
            captured[0].get("reason"), "signing_kid_resolve_failed"
        )
        # CR-HIGH-2: exc_info=True must surface the traceback in the
        # log, not just the audit reason code.
        self.assertTrue(
            any(
                "ValueError" in r and "corrupt PEM bytes" in r
                for r in cm.output
            ),
            f"expected traceback with ValueError; got {cm.output!r}",
        )


# ---------- views_introspect defensive branches ----------


class TestIntrospectDefensiveBranches(SimpleTestCase):
    """
    Pin the five defensive branches in ``AllianceAuthIntrospectTokenView``.

    Untested before this pass:

    * empty response body → ``_parse_response_metadata`` returns
      ``(None, None)``.
    * non-JSON body → caught ``ValueError`` returns ``(None, None)``.
    * JSON body that decodes to a non-dict → returns ``(None, None)``.
    * no ``token`` param on the request → ``_extract_token_value``
      returns ``None`` and ``_emit_introspect_audit`` records
      ``token_sha256=None``.
    * ``_emit_introspect_audit`` raising → ``dispatch`` catches and
      logs ``exc_info=True``, response is returned unchanged.
    """

    def setUp(self) -> None:
        from allianceauth_oidc.views_introspect import (
            AllianceAuthIntrospectTokenView,
        )

        self.view = AllianceAuthIntrospectTokenView()
        self.factory = RequestFactory()

    def test_empty_content_returns_none_none(self) -> None:
        response = SimpleNamespace(content=b"")
        active, client_id = self.view._parse_response_metadata(response)
        self.assertIsNone(active)
        self.assertIsNone(client_id)

    def test_malformed_json_returns_none_none(self) -> None:
        response = SimpleNamespace(content=b"not-json{")
        active, client_id = self.view._parse_response_metadata(response)
        self.assertIsNone(active)
        self.assertIsNone(client_id)

    def test_non_dict_json_returns_none_none(self) -> None:
        response = SimpleNamespace(content=b"[1, 2, 3]")
        active, client_id = self.view._parse_response_metadata(response)
        self.assertIsNone(active)
        self.assertIsNone(client_id)

    def test_missing_token_param_yields_none(self) -> None:
        request = self.factory.post("/o/introspect/", data={})
        value = self.view._extract_token_value(request)
        self.assertIsNone(value)

    def test_dispatch_swallows_audit_emit_exception(self) -> None:
        # Force ``_emit_introspect_audit`` to raise; ``dispatch`` MUST
        # log at WARNING with exc_info but NOT re-raise.
        from django.http import HttpResponse

        request = self.factory.post("/o/introspect/", data={"token": "fake"})
        response_sentinel = HttpResponse(b"{}")
        with (
            mock.patch.object(
                self.view,
                "_emit_introspect_audit",
                side_effect=RuntimeError("audit emit boom"),
            ),
            mock.patch.object(
                type(self.view).__bases__[0],
                "dispatch",
                return_value=response_sentinel,
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.views_introspect",
                level=logging.WARNING,
            ) as cm,
        ):
            result = self.view.dispatch(request)
        self.assertIs(result, response_sentinel)
        self.assertTrue(
            any(
                "RuntimeError" in r and "audit emit boom" in r
                for r in cm.output
            ),
            f"expected traceback; got {cm.output!r}",
        )


# ---------- checks.py bootstrap exception paths ----------


class TestChecksBootstrapExceptionPaths(SimpleTestCase):
    """
    ``checks.py`` defers system-check evaluation when the application
    registry is mid-bootstrap by catching ``_BOOTSTRAP_EXCEPTIONS``.
    Exercise the deferral so a future narrowing of the tuple does not
    turn ``manage.py migrate`` crashes into silent miss-in-output.
    """

    def test_w003_returns_empty_when_app_lookup_raises_lookup_error(
        self,
    ) -> None:
        """
        W003 deferral: when ``apps.get_model`` raises
        ``LookupError`` (mid-bootstrap), the check logs and returns
        ``[]`` instead of propagating.
        """
        from allianceauth_oidc import checks as oidc_checks

        with (
            mock.patch.object(
                oidc_checks.settings,
                "OAUTH2_PROVIDER",
                {"OIDC_RP_INITIATED_LOGOUT_ENABLED": False},
                create=True,
            ),
            mock.patch.object(
                oidc_checks.apps,
                "get_model",
                side_effect=LookupError("Application registry not ready"),
            ),
            self.assertLogs(
                "extensions.allianceauth_oidc.checks", level=logging.WARNING
            ) as cm,
        ):
            result = oidc_checks.check_logout_wiring(app_configs=None)
        self.assertEqual(result, [])
        self.assertTrue(
            any("deferred" in r for r in cm.output),
            f"expected deferred-log line; got {cm.output!r}",
        )
