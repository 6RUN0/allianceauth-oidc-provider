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
