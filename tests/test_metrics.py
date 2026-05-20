"""
Tests for the optional Prometheus metrics layer.

Counters/histograms/gauges live in
``allianceauth_oidc/_metrics.py``. They emit into the default
``prometheus_client.REGISTRY`` when ``django-prometheus`` is
importable, and resolve to no-op stubs otherwise — see the module
docstring for the cooperate-don't-depend rationale.

Test discipline
---------------
Prometheus metrics are process-global; one test's increments are
visible to every subsequent test. Always read deltas around the
action under test rather than absolute counter values, to stay
robust under any test ordering and the ``--parallel=auto`` Django
runner.
"""

from __future__ import annotations

import subprocess  # nosec B404
import sys
import textwrap

from django.test import SimpleTestCase
from prometheus_client import REGISTRY

from ._oidc_testcase import GrantedOIDCTestCase, OIDCTestCase


def _sample_value(name: str, **labels: str) -> float:
    """
    Read a single labelled sample from the default registry.

    Returns ``0.0`` when no sample with the requested name + label
    combo exists — Prometheus' own semantics: an unseen label combo
    is implicitly zero until the first ``inc()``.
    """
    for metric in REGISTRY.collect():
        for sample in metric.samples:
            if sample.name == name and sample.labels == labels:
                return sample.value
    return 0.0


class TestTokensIssuedCounter(GrantedOIDCTestCase):
    """``aa_oidc_tokens_issued_total`` increments per issued token."""

    def test_counter_increments_on_successful_code_flow(self) -> None:
        """
        Authorization-code → token-exchange must increment
        ``aa_oidc_tokens_issued_total{grant_type="authorization_code",
        client_id=<test_app>}`` by one.
        """
        labels = {
            "grant_type": "authorization_code",
            "client_id": self.oauth_id,
        }
        before = _sample_value("aa_oidc_tokens_issued_total", **labels)

        body = self.run_code_flow(self.user1, state="metrics-counter")
        self.assertIn("access_token", body)

        after = _sample_value("aa_oidc_tokens_issued_total", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )


class TestAuthorizeDeniedCounter(OIDCTestCase):
    """``aa_oidc_authorize_denied_total`` increments per policy refusal."""

    def test_global_denial_increments_counter_with_reason_global(
        self,
    ) -> None:
        """
        Authenticated user without the global ``access_oidc``
        permission must trip the ``reason="global"`` denial path
        in ``AuthAuthorizationView.dispatch`` and increment the
        counter by one.
        """
        labels = {"reason": "global"}
        before = _sample_value("aa_oidc_authorize_denied_total", **labels)

        resp = self.authorize_get_default(self.user1, scope="openid")
        self.assertDeniedGlobal(resp, self.user1)

        after = _sample_value("aa_oidc_authorize_denied_total", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )

    def test_app_denial_increments_counter_with_reason_app(self) -> None:
        """
        User with global access but failing the per-app state
        whitelist must trip the ``reason="app"`` denial path and
        increment the counter by one. ``user1`` is in state
        ``"Member"`` (per ``OIDCTestCase.setUpTestData``); the app
        below admits only ``"Blue"``, so user1 fails the policy.
        """
        from ._factories import make_app

        self.grant_oidc_access(self.user1)
        creds = make_app(owner=self.user1, states=["Blue"])

        labels = {"reason": "app"}
        before = _sample_value("aa_oidc_authorize_denied_total", **labels)

        resp = self.authorize_get_default(
            self.user1,
            scope="openid",
            extra={"client_id": creds.client_id},
        )
        self.assertDeniedApp(resp, self.user1, creds.app)

        after = _sample_value("aa_oidc_authorize_denied_total", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )


class TestPolicyRejectionsCounter(OIDCTestCase):
    """
    ``aa_oidc_policy_rejections_total{stage,reason}`` increments at
    every enforcement stage. The counter is intentionally emitted
    side-by-side with the older :data:`authorize_denied` so dashboards
    can migrate without a flag-day cutover; the test below pins both
    counters fire for the same authorize denial.
    """

    def test_authorize_global_denial_increments_both_counters(self) -> None:
        """
        Same authorize-time denial fires the legacy counter AND the
        cross-stage counter — proves the parallel-emit contract for
        the migration window.
        """
        legacy_labels = {"reason": "global"}
        new_labels = {"stage": "authorize", "reason": "global"}
        legacy_before = _sample_value(
            "aa_oidc_authorize_denied_total", **legacy_labels
        )
        new_before = _sample_value(
            "aa_oidc_policy_rejections_total", **new_labels
        )

        resp = self.authorize_get_default(self.user1, scope="openid")
        self.assertDeniedGlobal(resp, self.user1)

        legacy_after = _sample_value(
            "aa_oidc_authorize_denied_total", **legacy_labels
        )
        new_after = _sample_value(
            "aa_oidc_policy_rejections_total", **new_labels
        )
        self.assertEqual(1.0, legacy_after - legacy_before)
        self.assertEqual(1.0, new_after - new_before)

    def test_validate_code_denial_increments_policy_rejections(self) -> None:
        """
        Validator stage emits ``policy_rejections{stage="validate_code"}``
        with the deny reason from ``policy.decide``. Exercises the
        ``_enforce_policy`` path directly so the test does not need to
        drive a full code-exchange round-trip (which would require the
        DOT super().validate_code to return True first).
        """
        from types import SimpleNamespace

        from allianceauth_oidc.auth_provider import AllianceAuthOAuth2Validator

        # user1 has no global perm in the default fixture, so the real
        # DEFAULT_POLICY returns a GlobalDeny here.
        validator = AllianceAuthOAuth2Validator()
        request = SimpleNamespace(user=self.user1)

        labels = {"stage": "validate_code", "reason": "global"}
        before = _sample_value("aa_oidc_policy_rejections_total", **labels)

        allowed = validator._enforce_policy(
            request, self.oauth_app, stage="validate_code"
        )
        self.assertFalse(allowed)

        after = _sample_value("aa_oidc_policy_rejections_total", **labels)
        self.assertEqual(1.0, after - before)


class TestBclMetrics(OIDCTestCase):
    """
    ``aa_oidc_bcl_delivery_seconds`` histogram tracks HTTP round-trip
    latency per attempt; ``aa_oidc_bcl_dispatches_total`` counts
    terminal ``oidc_logout_dispatched`` events by outcome (success
    plus the closed set of failure reasons defined in
    :data:`allianceauth_oidc.constants.BCL_DISPATCH_OUTCOMES`). The
    dead-letter rate is a PromQL sum over the failure-outcomes
    subset, not a separate Counter.
    """

    def setUp(self) -> None:
        super().setUp()
        from ._factories import make_app

        creds = make_app(
            owner=self.user1,
            backchannel_logout_uri="https://rp.example.com/bcl",
        )
        self.bcl_app = creds.app

    def _active_signing_kid(self) -> str:
        from jwcrypto import jwk
        from oauth2_provider.settings import oauth2_settings

        pem = oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode()
        return str(jwk.JWK.from_pem(pem).thumbprint())

    def test_success_observes_delivery_histogram_with_outcome_success(
        self,
    ) -> None:
        """
        A 2xx RP response must increment the ``_count`` sample of
        ``aa_oidc_bcl_delivery_seconds{client_id, outcome="success"}``
        — proving the histogram is observed exactly once per
        delivered logout_token.
        """
        from unittest import mock

        from allianceauth_oidc.tasks import send_logout_token

        labels = {
            "client_id": self.bcl_app.client_id,
            "outcome": "success",
        }
        before = _sample_value("aa_oidc_bcl_delivery_seconds_count", **labels)

        import socket

        # Stub request-time SSRF gate so the metric assertion is not
        # blocked by DNS resolution against rp.example.com (which is
        # NXDOMAIN on CI and the fail-closed branch returns before
        # the histogram is observed).
        with (
            mock.patch(
                "allianceauth_oidc._dns_safety.resolve_host_bounded",
                return_value=[
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        0,
                        "",
                        ("1.1.1.1", 0),
                    )
                ],
            ),
            mock.patch("allianceauth_oidc.tasks.requests.post") as post,
        ):
            post.return_value = mock.MagicMock(status_code=204)
            send_logout_token(
                user_pk=self.user1.pk,
                application_pk=self.bcl_app.pk,
                jti="d" * 32,
                signing_kid=self._active_signing_kid(),
                iat=1_700_000_000,
            )

        after = _sample_value("aa_oidc_bcl_delivery_seconds_count", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )

    def test_dispatches_counter_increments_with_outcome_success(
        self,
    ) -> None:
        """
        ``oidc_logout_dispatched`` with ``success=True`` increments
        ``aa_oidc_bcl_dispatches_total{outcome="success"}``. The
        counter fires on every terminal event regardless of
        success, so this label is the dashboard denominator for
        success-rate queries.
        """
        from allianceauth_oidc.signals import (
            BackChannelLogoutSender,
            oidc_logout_dispatched,
        )

        labels = {
            "client_id": self.bcl_app.client_id,
            "outcome": "success",
        }
        before = _sample_value("aa_oidc_bcl_dispatches_total", **labels)

        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=self.bcl_app,
            user_pk=self.user1.pk,
            jti="d" * 32,
            success=True,
            attempt_count=1,
        )

        after = _sample_value("aa_oidc_bcl_dispatches_total", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )

    def test_dispatches_counter_increments_with_outcome_from_reason(
        self,
    ) -> None:
        """
        ``oidc_logout_dispatched`` with ``success=False`` increments
        ``aa_oidc_bcl_dispatches_total{outcome=<reason>}`` — the
        terminal ``reason`` becomes the histogram-aligned ``outcome``
        label so a single Grafana query joins both metrics.
        """
        from allianceauth_oidc.signals import (
            BackChannelLogoutSender,
            oidc_logout_dispatched,
        )

        # ``signing_kid_retired`` exercises the dispatch outcome
        # set's coverage of pre-HTTP failures (logout.py emits this
        # when the captured kid has rotated out of the active /
        # inactive sets before the worker picks the task up). This
        # is a regression test for the convention-review finding
        # that the previous ``_DEAD_LETTER_REASONS`` set omitted
        # both ``signing_kid_resolve_failed`` and
        # ``broker_unavailable``.
        labels = {
            "client_id": self.bcl_app.client_id,
            "outcome": "signing_kid_retired",
        }
        before = _sample_value("aa_oidc_bcl_dispatches_total", **labels)

        oidc_logout_dispatched.send(
            sender=BackChannelLogoutSender,
            application=self.bcl_app,
            user_pk=self.user1.pk,
            jti="d" * 32,
            success=False,
            attempt_count=1,
            reason="signing_kid_retired",
        )

        after = _sample_value("aa_oidc_bcl_dispatches_total", **labels)
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1, got {after - before} "
            f"(labels={labels}, before={before}, after={after})",
        )

    def test_dispatch_outcome_set_covers_every_emitted_reason(
        self,
    ) -> None:
        """
        The closed value-set in ``constants.BCL_DISPATCH_OUTCOMES``
        must include every ``reason`` literal emitted alongside
        ``success=False`` in ``tasks.send_logout_token`` and
        ``logout.dispatch_backchannel_logout``. Drift here would
        produce counter samples with an unrecognised ``outcome``
        label that Grafana queries silently miss; the test fires
        on every emitter modification so the convention rule from
        ``docs/METRICS.md`` ("label value sets are module-level
        Final[frozenset] constants") stays enforced.
        """
        from allianceauth_oidc.constants import BCL_DISPATCH_OUTCOMES

        emitted_reasons = {
            "redirect_blocked",
            "rp_client_error",
            "retries_exhausted",
            "signing_kid_retired",
            "signing_kid_resolve_failed",
            "broker_unavailable",
            # Emitted by ``tasks._request_time_ssrf_gate_passes`` —
            # the DNS rebinding TOCTOU defence that re-resolves the
            # backchannel_logout_uri host between admin save and
            # worker dispatch.
            "dns_resolve_failed",
            "unsafe_target_ip",
        }
        missing = emitted_reasons - BCL_DISPATCH_OUTCOMES
        self.assertEqual(
            set(),
            missing,
            f"BCL_DISPATCH_OUTCOMES missing emitter values: {missing}",
        )
        # ``success`` is the terminal-success outcome, separate from
        # the ``reason``-driven failure set.
        self.assertIn("success", BCL_DISPATCH_OUTCOMES)


class TestNoOpMetricAPISurface(SimpleTestCase):
    """
    Documented API surface of ``_NoOpMetric``.

    Reloading the real ``_metrics`` module under a patched
    ``sys.modules`` would force the live ``Counter``/``Histogram``
    objects to re-register against the default ``REGISTRY``, which
    fails with ``ValueError: Duplicated timeseries`` because the
    originals are still registered from the suite's first import.
    Instead, this class exercises the stub class directly — the
    contract documented in ``docs/METRICS.md`` ("No-op stub
    contract") is what sibling AA modules will copy, and that
    contract is fully observable without a module reload. The
    receiver code paths that read ``_ENABLED`` are already covered
    by the other test classes here issuing real signals under the
    live (enabled) gate.
    """

    def test_labels_returns_self_for_chaining(self) -> None:
        from allianceauth_oidc._metrics import _NoOpMetric

        stub = _NoOpMetric()
        self.assertIs(stub, stub.labels(client_id="x", outcome="y"))
        # Empty label call also chains — Counter() without labels
        # would still expose .labels() in real prometheus_client.
        self.assertIs(stub, stub.labels())

    def test_documented_methods_return_none_without_raising(self) -> None:
        from allianceauth_oidc._metrics import _NoOpMetric

        stub = _NoOpMetric()
        self.assertIsNone(stub.inc())
        self.assertIsNone(stub.inc(2.5))
        self.assertIsNone(stub.observe(0.123))
        self.assertIsNone(stub.set(1.0))
        # ``set_function`` is the only Gauge contract method that
        # accepts a callable; the stub must accept and discard it.
        self.assertIsNone(stub.set_function(lambda: 99.0))

    def test_module_gate_is_currently_enabled_under_test_env(self) -> None:
        """
        The dev env installs ``django-prometheus``, so the gate
        MUST be enabled and real metrics MUST live in the default
        registry — guards against a regression where the
        try/import accidentally flips the wrong way.
        """
        from prometheus_client import Counter, Histogram

        from allianceauth_oidc import _metrics

        self.assertTrue(_metrics._ENABLED)
        self.assertIsInstance(_metrics.tokens_issued, Counter)
        self.assertIsInstance(_metrics.bcl_delivery_seconds, Histogram)
        self.assertIsInstance(_metrics.bcl_dispatches, Counter)
        self.assertIsInstance(_metrics.tokens_cleaned, Counter)


class TestNoopFallbackSmoke(SimpleTestCase):
    """
    Smoke the no-op fallback in a clean subprocess.

    The in-process tests above exercise the live (enabled) gate and
    the ``_NoOpMetric`` class directly; this test fills the only
    remaining gap — that the module **itself** falls back cleanly
    when ``django_prometheus`` is unimportable. A reload inside the
    suite cannot prove that: the live ``Counter`` / ``Histogram``
    objects are already registered against the default ``REGISTRY``,
    so re-executing the module body raises
    ``ValueError: Duplicated timeseries``. A fresh subprocess starts
    with an empty registry and an unloaded ``allianceauth_oidc``
    package — every module-level metric resolves to ``_NoOpMetric``
    on first import.

    Implementation note: ``sys.modules["django_prometheus"] = None``
    is the PEP-328 idiom for "mask this package even if it is on
    sys.path" — subsequent ``import django_prometheus`` raises
    ``ImportError`` regardless of what the venv actually has
    installed. That is the production path on any deployment that
    does not pull the ``[metrics]`` extra (or another AA module's
    dependency chain) into the AA venv.
    """

    _SCRIPT = textwrap.dedent(
        """
        import sys

        sys.modules["django_prometheus"] = None

        from allianceauth_oidc import _metrics as m

        assert m._ENABLED is False, f"_ENABLED={m._ENABLED!r}"
        for name in (
            "tokens_issued",
            "authorize_denied",
            "policy_rejections",
            "bcl_delivery_seconds",
            "bcl_dispatches",
            "tokens_cleaned",
        ):
            obj = getattr(m, name)
            cls = type(obj).__name__
            assert cls == "_NoOpMetric", f"{name}: {cls}"
        m.tokens_issued.labels(grant_type="x", client_id="y").inc()
        m.tokens_issued.labels(grant_type="x", client_id="y").inc(2.5)
        m.bcl_delivery_seconds.labels(
            client_id="x", outcome="success"
        ).observe(0.5)
        m.tokens_cleaned.inc(7)
        m.connect_metrics_receivers()
        print("OK")
        """
    ).strip()

    def test_metrics_falls_back_to_noop_when_django_prometheus_missing(
        self,
    ) -> None:
        """
        ``_metrics`` must import cleanly with ``django_prometheus``
        masked; every module-level metric must be a ``_NoOpMetric``;
        chained ``.labels().inc()`` / ``.observe()`` must be silent
        no-ops; ``connect_metrics_receivers()`` must not raise (the
        ``_on_token_issued`` / ``_on_logout_dispatched`` receivers
        early-return on ``not _ENABLED``, so a wired-up receiver
        firing under the no-op gate stays harmless).
        """
        result = subprocess.run(  # nosec B603
            [sys.executable, "-c", self._SCRIPT],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            0,
            result.returncode,
            (
                f"subprocess smoke failed (rc={result.returncode})\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            ),
        )
        self.assertEqual("OK", result.stdout.strip())


class TestTokensCleanedCounter(OIDCTestCase):
    """
    ``aa_oidc_tokens_cleaned_total`` increments by the number of
    expired ``AccessToken`` rows removed in each
    ``clear_expired_tokens`` Celery task run. Combined with the
    ``aa_oidc_tokens_issued_total`` rate, operator dashboards
    derive an "active tokens" approximation without needing a
    Gauge — Gauge ``set_function`` is incompatible with the
    ``prometheus_client`` multiprocess collector that real AA
    gunicorn deployments rely on.
    """

    def test_cleaned_counter_increments_by_removed_token_count(
        self,
    ) -> None:
        from datetime import timedelta

        from django.utils import timezone
        from oauth2_provider.models import get_access_token_model

        from allianceauth_oidc.tasks import clear_expired_tokens

        AccessToken = get_access_token_model()
        now = timezone.now()
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="cleanup-metric-orphan-1",  # nosec B106
            expires=now - timedelta(hours=1),
            scope="openid",
        )
        AccessToken.objects.create(
            user=self.user1,
            application=self.oauth_app,
            token="cleanup-metric-orphan-2",  # nosec B106
            expires=now - timedelta(hours=1),
            scope="openid",
        )

        before = _sample_value("aa_oidc_tokens_cleaned_total")
        clear_expired_tokens()
        after = _sample_value("aa_oidc_tokens_cleaned_total")

        self.assertEqual(
            2.0,
            after - before,
            f"expected two removed tokens, got delta={after - before}",
        )


class TestCodeReuseAuditMissesCounter(OIDCTestCase):
    """
    ``aa_oidc_code_reuse_audit_misses_total{client_id}`` fires
    when :meth:`AllianceAuthOAuth2Validator._handle_potential_code_reuse`
    walks ``IssuedCodeAudit`` and finds no row for the presented
    code. This is the observability hook for the RFC 6749 §10.5
    SHOULD-overlay race window: pre-refactor the branch was silent, so
    a reuse hit that landed inside the
    ``_record_code_issuance``-after-``save_bearer_token`` window
    degraded to log-only without surfacing on dashboards.

    Operators correlate this counter against the
    ``oidc_code_reuse_detected`` Django signal — the counter is an
    upper bound (fuzzers probing ``/o/token/`` with random codes
    also hit the same branch), the signal is the confirmed-hit
    indicator.
    """

    def test_audit_miss_increments_counter_with_client_id_label(
        self,
    ) -> None:
        """
        A ``_handle_potential_code_reuse`` call against a code with
        no ``IssuedCodeAudit`` row increments the counter by one,
        labelled with the presenting client's ``client_id``.
        """
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        labels = {"client_id": self.oauth_app.client_id}
        before = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels
        )

        validator = AllianceAuthOAuth2Validator()
        # No IssuedCodeAudit row exists for this code — drives the
        # ``audit is None`` branch where  increments the counter.
        validator._handle_potential_code_reuse(
            "code-with-no-audit-row", self.oauth_app
        )

        after = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels
        )
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1 for client_id={self.oauth_app.client_id!r}, "
            f"got {after - before}",
        )

    def test_audit_miss_counter_increments_separately_per_client_id(
        self,
    ) -> None:
        """
        Two distinct clients fuzzing ``/o/token/`` with random codes
        each contribute to their own ``client_id`` bucket — the
        label is not shared. Pin this so a future operator dashboard
        slicing by ``client_id`` does not collapse traffic from
        different RPs into a single time series.
        """
        from allianceauth_oidc.auth_provider import (
            AllianceAuthOAuth2Validator,
        )

        from ._factories import make_app

        # Reuse the fixture app + create a second app to exercise
        # the per-client_id label split.
        second_app = make_app(owner=self.user2).app

        labels_a = {"client_id": self.oauth_app.client_id}
        labels_b = {"client_id": second_app.client_id}
        before_a = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels_a
        )
        before_b = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels_b
        )

        validator = AllianceAuthOAuth2Validator()
        validator._handle_potential_code_reuse(
            "miss-code-app-a", self.oauth_app
        )
        validator._handle_potential_code_reuse("miss-code-app-b", second_app)

        after_a = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels_a
        )
        after_b = _sample_value(
            "aa_oidc_code_reuse_audit_misses_total", **labels_b
        )
        self.assertEqual(1.0, after_a - before_a)
        self.assertEqual(1.0, after_b - before_b)


class TestAuditReceiverFailuresCounter(OIDCTestCase):
    """
     / ``aa_oidc_audit_receiver_failures_total{signal,
    receiver_dispatch_uid}`` fires when an audit-signal receiver
    raises during dispatch. Single counter covers all four audit
    signals — without this metric, a silently-broken SIEM forwarder
    leaves no trace beyond a log line operators rarely watch.
    """

    def test_failing_receiver_increments_counter_with_signal_label(
        self,
    ) -> None:
        from allianceauth_oidc.signals import (
            dispatch_audit_signal,
            oidc_token_issued,
        )

        def boom(sender, **kwargs):
            raise RuntimeError("simulated SIEM forwarder failure")

        # Strong reference — ``Signal.connect`` defaults to weak.
        self._boom = boom
        oidc_token_issued.connect(boom, dispatch_uid="test-arf-boom")
        self.addCleanup(
            oidc_token_issued.disconnect, dispatch_uid="test-arf-boom"
        )

        labels = {
            "signal": "oidc_token_issued",
            "receiver_dispatch_uid": "test-arf-boom",
        }
        before = _sample_value(
            "aa_oidc_audit_receiver_failures_total", **labels
        )

        dispatch_audit_signal(
            oidc_token_issued,
            signal_name="oidc_token_issued",
            sender=type(self),
            request=None,
            token=None,
            body=None,
        )

        after = _sample_value(
            "aa_oidc_audit_receiver_failures_total", **labels
        )
        self.assertEqual(
            1.0,
            after - before,
            f"expected delta=1 for label set {labels!r}; got {after - before}",
        )

    def test_successful_receivers_do_not_increment_counter(self) -> None:
        from allianceauth_oidc.signals import (
            dispatch_audit_signal,
            oidc_token_issued,
        )

        captured: list = []

        def receiver(sender, **kwargs):
            captured.append(kwargs)

        self._receiver = receiver
        oidc_token_issued.connect(receiver, dispatch_uid="test-arf-ok")
        self.addCleanup(
            oidc_token_issued.disconnect, dispatch_uid="test-arf-ok"
        )

        labels = {
            "signal": "oidc_token_issued",
            "receiver_dispatch_uid": "test-arf-ok",
        }
        before = _sample_value(
            "aa_oidc_audit_receiver_failures_total", **labels
        )

        dispatch_audit_signal(
            oidc_token_issued,
            signal_name="oidc_token_issued",
            sender=type(self),
            request=None,
            token=None,
            body=None,
        )

        # Receiver ran.
        self.assertEqual(1, len(captured))
        # Counter did NOT move for this label set.
        after = _sample_value(
            "aa_oidc_audit_receiver_failures_total", **labels
        )
        self.assertEqual(0.0, after - before)
