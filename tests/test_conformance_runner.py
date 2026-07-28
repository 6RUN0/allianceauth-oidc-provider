"""
Unit tests for the conformance plan runner.

The runner's ``run_plan`` body talks to a live OpenID Conformance
Suite instance, which only ``nox -s conformance`` can provide. The
**summary aggregation** is pure-Python and lives in
``_emit_summary`` — that's the regression line for the gate-on-fail
contract that CI will rely on, and it's what we cover here.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from tests.conformance.run_plan import ModuleResult, _emit_summary


class TestEmitSummary(unittest.TestCase):
    def test_all_passed_returns_zero(self) -> None:
        results = [
            ModuleResult(name="m1", test_id="id1", result="PASSED"),
            ModuleResult(name="m2", test_id="id2", result="REVIEW"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(0, _emit_summary(results, strict_warnings=False))

    def test_any_failed_returns_one(self) -> None:
        results = [
            ModuleResult(name="m1", test_id="id1", result="PASSED"),
            ModuleResult(name="m2", test_id="id2", result="FAILED"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, _emit_summary(results, strict_warnings=False))

    def test_timeout_counts_as_failure(self) -> None:
        results = [
            ModuleResult(name="m1", test_id="id1", result="TIMEOUT"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, _emit_summary(results, strict_warnings=False))

    def test_warning_does_not_fail_by_default(self) -> None:
        results = [
            ModuleResult(name="m1", test_id="id1", result="PASSED"),
            ModuleResult(name="m2", test_id="id2", result="WARNING"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(0, _emit_summary(results, strict_warnings=False))

    def test_warning_fails_under_strict_warnings(self) -> None:
        results = [
            ModuleResult(name="m1", test_id="id1", result="WARNING"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, _emit_summary(results, strict_warnings=True))

    def test_skipped_counts_as_failure(self) -> None:
        # SKIPPED is intentionally a failure: most plan modules that
        # SKIP do so because the provider didn't advertise a feature
        # the plan needed (e.g. dynamic registration). The full
        # ``oidcc-config`` plan has optional modules; if those should
        # be tolerated, drop them from the plan rather than masking
        # SKIPs in the gate.
        results = [
            ModuleResult(name="m1", test_id="id1", result="SKIPPED"),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(1, _emit_summary(results, strict_warnings=False))

    def test_summary_text_lists_every_module(self) -> None:
        results = [
            ModuleResult(name="alpha", test_id="aaa", result="PASSED"),
            ModuleResult(name="beta", test_id="bbb", result="WARNING"),
        ]
        buf = io.StringIO()
        with redirect_stdout(buf):
            _emit_summary(results, strict_warnings=False)
        out = buf.getvalue()
        self.assertIn("alpha", out)
        self.assertIn("beta", out)
        self.assertIn("passed=1", out)
        self.assertIn("warned=1", out)
        self.assertIn("failed=0", out)


class TestPlanConfigBrowserRouting(unittest.TestCase):
    """
    Pin the browser-entry routing contract of ``build_plan_config``.

    The suite picks the FIRST top-level browser entry whose ``match``
    fits the ``goToUrl`` URL, then runs that entry's tasks strictly
    in order (``BrowserControl.goToUrl`` / ``WebRunner``). Two
    invariants encode hard-won regressions:

    1. The login-page snapshot task must be reachable ONLY from the
       positive-flow entry (``response_type=``). Negative modules
       bind error-page placeholders to their visit; a login snapshot
       there consumes the placeholder and the suite finishes the
       test mid-flow (``oidcc-response-type-missing`` /
       ``oidcc-ensure-registered-redirect-uri`` flipped to FAILED).
    2. Entry order: bad-redirect (``*/callback/*``), then JAR
       (``request=``), then positive (``response_type=``), then the
       fallback for ``oidcc-response-type-missing`` — a positive
       entry listed earlier would swallow the negative flows.
    """

    def setUp(self) -> None:
        from tests.conformance.runner.plan_config import build_plan_config

        self.entries = build_plan_config()["browser"]

    def test_entry_order_negatives_before_positive(self) -> None:
        patterns = [entry["match"] for entry in self.entries]
        self.assertEqual(4, len(patterns))
        self.assertTrue(patterns[0].endswith("/callback/*"))
        self.assertIn("request=", patterns[1])
        self.assertNotIn("response_type=", patterns[1])
        self.assertIn("response_type=", patterns[2])
        self.assertTrue(patterns[3].endswith("/o/authorize*"))
        self.assertNotIn("=", patterns[3])

    def test_login_snapshot_only_in_positive_entry(self) -> None:
        def snapshot_positions(entry: dict) -> list[int]:
            return [
                index
                for index, task in enumerate(entry["tasks"])
                if task["task"].startswith("Snapshot login page")
            ]

        self.assertEqual([], snapshot_positions(self.entries[0]))
        self.assertEqual([], snapshot_positions(self.entries[1]))
        self.assertEqual([], snapshot_positions(self.entries[3]))
        # Present exactly once in the positive entry, BEFORE Login —
        # it must capture the still-unfilled form.
        positive = self.entries[2]
        self.assertEqual([0], snapshot_positions(positive))
        self.assertEqual("Login", positive["tasks"][1]["task"])

    def test_login_task_never_touches_placeholders(self) -> None:
        # The shotgun regression: an update-image-placeholder command
        # inside the shared Login task fills whatever placeholder the
        # visit bound — including error-page placeholders.
        for entry in self.entries:
            for task in entry["tasks"]:
                if task["task"] != "Login":
                    continue
                for command in task.get("commands", []):
                    self.assertFalse(
                        any(
                            isinstance(part, str)
                            and part.startswith("update-image-placeholder")
                            for part in command
                        ),
                        f"Login task carries a placeholder fill: {command}",
                    )

    def test_authorize_entries_end_with_implicit_submission_wait(
        self,
    ) -> None:
        # Every authorize-flow entry must keep the browser window
        # alive until the suite callback page delivered its async
        # XHR — dropping the task resurrects the "HtmlUnit lottery"
        # WAITING timeouts.
        for entry in self.entries[1:]:
            last = entry["tasks"][-1]
            self.assertEqual("Wait for implicit submission", last["task"])
            self.assertTrue(last["optional"])
            # The match must be anchored to the suite origin. The
            # suite embeds redirect_uri into the authorize URL RAW
            # (no percent-encoding), so an unanchored
            # ``*/test/a/conformance/callback*`` also matches the
            # provider's own authorize/error page whenever the query
            # carries ``redirect_uri=…/test/a/conformance/callback…``
            # — the wait then times out on the error page and
            # interrupts the module (seen on
            # ``oidcc-ensure-request-object-with-redirect-uri``).
            self.assertTrue(
                str(last["match"]).startswith("https://"),
                f"submission-wait match must be origin-anchored, "
                f"got {last['match']!r}",
            )
