"""
Unit tests for the conformance plan runner.

The runner's ``run_plan`` body talks to a live OpenID Conformance
Suite instance, which only ``nox -s conformance`` can provide. The
**summary aggregation** is pure-Python and lives in
``_emit_summary`` — that's the regression line for the gate-on-fail
contract that CI will rely on, and it's what we cover here.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

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


class TestUnknownResultsFail(unittest.TestCase):
    """
    Pin the allowlist classification of suite results.

    The suite reports ``result=UNKNOWN`` / ``status=INTERRUPTED`` for
    a module stopped before its verdict (e.g. alias conflict). Only
    PASS/WARN results may count as non-failures; anything else has to
    turn the run red instead of vanishing from every counter.
    """

    def _run(self, result: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = _emit_summary(
                [ModuleResult(name="m1", test_id="id1", result=result)],
                strict_warnings=False,
            )
        return code, buf.getvalue()

    def test_unknown_result_counts_as_failure(self) -> None:
        code, out = self._run("UNKNOWN")
        self.assertEqual(1, code)
        self.assertIn("failed=1", out)

    def test_interrupted_result_counts_as_failure(self) -> None:
        code, out = self._run("INTERRUPTED")
        self.assertEqual(1, code)
        self.assertIn("failed=1", out)

    def test_unexpected_result_string_counts_as_failure(self) -> None:
        code, _ = self._run("SOMETHING-NEW")
        self.assertEqual(1, code)


def _write_json(path: pathlib.Path, payload: object) -> pathlib.Path:
    """Serialise ``payload`` to ``path`` and return the path."""
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestExpectedFailurePinsResult(unittest.TestCase):
    """
    Pin the ``{module: {"result": ..., "reason": ...}}`` ledger schema.

    An entry acknowledges exactly one result. A listed module that
    ends with any other non-passing result is a regression, not an
    XFAIL: a SKIPPED-acknowledged module turning FAILED must fail the
    run.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)

    def _load(self, payload: object) -> dict:
        from tests.conformance.runner.filtering import (
            load_expected_failures,
        )

        return load_expected_failures(
            _write_json(self.tmp / "expected.json", payload)
        )

    def _summary(self, result: str, expected: dict) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = _emit_summary(
                [ModuleResult(name="m1", test_id="id1", result=result)],
                strict_warnings=False,
                expected_failures=expected,
            )
        return code, buf.getvalue()

    def test_matching_result_is_xfail(self) -> None:
        expected = self._load(
            {"m1": {"result": "SKIPPED", "reason": "scope not offered"}}
        )
        code, out = self._summary("SKIPPED", expected)
        self.assertEqual(0, code)
        self.assertIn("xfail=1", out)

    def test_other_failure_result_is_real_failure(self) -> None:
        expected = self._load(
            {"m1": {"result": "SKIPPED", "reason": "scope not offered"}}
        )
        code, out = self._summary("FAILED", expected)
        self.assertEqual(1, code)
        self.assertIn("failed=1", out)
        self.assertIn("xfail=0", out)

    def test_plain_string_entry_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self._load({"m1": "reason without a pinned result"})

    def test_entry_without_result_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self._load({"m1": {"reason": "no result"}})

    def test_shipped_ledger_pins_a_failure_result(self) -> None:
        from tests.conformance.runner.config import (
            PASS_RESULTS,
            WARN_RESULTS,
        )
        from tests.conformance.runner.filtering import (
            load_expected_failures,
        )

        ledger = load_expected_failures(
            _CONFORMANCE_DIR / "expected_failures.json"
        )
        self.assertTrue(ledger)
        for name, entry in ledger.items():
            self.assertNotIn(entry.result, PASS_RESULTS | WARN_RESULTS, name)
            self.assertTrue(entry.reason, name)


_CONFORMANCE_DIR = pathlib.Path(__file__).resolve().parent / "conformance"
_PLAN = "oidcc-basic-certification-test-plan"


def _summary_payload(
    *results: tuple[str, str], plan_name: str = _PLAN
) -> dict:
    """Build a ``--summary-json`` payload from (name, result) pairs."""
    return {
        "plan_name": plan_name,
        "plan_id": "p1",
        "results": [
            {"name": name, "test_id": "t", "result": result}
            for name, result in results
        ],
        "skipped_filtered": [],
    }


class TestAggregateSummaries(unittest.TestCase):
    """
    Pin the per-module aggregator against lost and stale modules.

    Every module of the expected list must be accounted for: a
    missing, empty or unreadable per-module JSON and a harness crash
    (``run_plan.py`` exit code other than 0/1) are ERROR results for
    that module. Files for other modules or another plan are not
    evidence for this run.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.run_dir = pathlib.Path(tmp.name)
        self.modules_file = self.run_dir / "modules.txt"
        self.modules_file.write_text("m1\nm2\n", encoding="utf-8")

    def _aggregate(self, *extra: str) -> tuple[int, str]:
        from tests.conformance.aggregate_summaries import main

        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            code = main(
                [
                    str(self.run_dir),
                    "--expected-modules",
                    str(self.modules_file),
                    "--plan-name",
                    _PLAN,
                    *extra,
                ]
            )
        return code, buf.getvalue()

    def test_all_expected_modules_passed_returns_zero(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        _write_json(
            self.run_dir / "m2.json", _summary_payload(("m2", "PASSED"))
        )
        code, out = self._aggregate()
        self.assertEqual(0, code)
        self.assertIn("passed=2", out)

    def test_missing_module_json_is_error(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        code, out = self._aggregate()
        self.assertEqual(1, code)
        self.assertRegex(out, r"ERROR\s+m2")

    def test_empty_results_json_is_error(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        _write_json(self.run_dir / "m2.json", _summary_payload())
        code, out = self._aggregate()
        self.assertEqual(1, code)
        self.assertRegex(out, r"ERROR\s+m2")

    def test_malformed_json_is_error(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        (self.run_dir / "m2.json").write_text("{trunc", encoding="utf-8")
        code, out = self._aggregate()
        self.assertEqual(1, code)
        self.assertRegex(out, r"ERROR\s+m2")

    def test_harness_crash_exit_code_is_error(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        _write_json(
            self.run_dir / "m2.json", _summary_payload(("m2", "PASSED"))
        )
        exit_codes = self.run_dir / "exit_codes.tsv"
        exit_codes.write_text("m1\t0\nm2\t137\n", encoding="utf-8")
        code, out = self._aggregate("--exit-codes", str(exit_codes))
        self.assertEqual(1, code)
        self.assertRegex(out, r"ERROR\s+m2")

    def test_results_for_unexpected_modules_are_ignored(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        _write_json(
            self.run_dir / "m2.json", _summary_payload(("m2", "PASSED"))
        )
        _write_json(
            self.run_dir / "stale.json", _summary_payload(("stale", "FAILED"))
        )
        code, out = self._aggregate()
        self.assertEqual(0, code)
        self.assertNotIn("stale", out)

    def test_results_from_another_plan_are_ignored(self) -> None:
        _write_json(
            self.run_dir / "m1.json", _summary_payload(("m1", "PASSED"))
        )
        _write_json(
            self.run_dir / "m2.json",
            _summary_payload(("m2", "PASSED"), plan_name="other-plan"),
        )
        code, out = self._aggregate()
        self.assertEqual(1, code)
        self.assertRegex(out, r"ERROR\s+m2")


@unittest.skipIf(shutil.which("bash") is None, "bash not installed")
class TestRunPerModuleScript(unittest.TestCase):
    """
    Drive ``run_per_module.sh`` against docker/uv test doubles.

    Pins the shell half of the lost/stale-module contract: a module
    whose harness crashed or wrote no results turns the aggregate
    red, the loop still reaches the modules after it, and a JSON left
    in the results directory by an earlier run is never read.
    """

    def test_lost_modules_fail_and_stale_results_are_ignored(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        results_dir = pathlib.Path(tmp.name)
        # An earlier run left a PASSED verdict for the module that
        # crashes this time; it must not stand in for the lost result.
        _write_json(
            results_dir / "crash-b.json",
            _summary_payload(("crash-b", "PASSED")),
        )
        fakes = _CONFORMANCE_DIR / "fakes"
        env = {
            **os.environ,
            "PATH": f"{fakes}{os.pathsep}{os.environ['PATH']}",
            "PYTHONPATH": str(_CONFORMANCE_DIR.parents[1]),
            "STUB_PYTHON": sys.executable,
            "STUB_MODULES": "pass-a,crash-b,empty-c,pass-d",
        }
        proc = subprocess.run(
            [
                "bash",
                str(_CONFORMANCE_DIR / "run_per_module.sh"),
                "--plan",
                _PLAN,
                "--results-dir",
                str(results_dir),
            ],
            cwd=_CONFORMANCE_DIR.parents[1],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        out = proc.stdout
        self.assertNotEqual(0, proc.returncode, out + proc.stderr)
        self.assertRegex(out, r"ERROR\s+crash-b")
        self.assertRegex(out, r"ERROR\s+empty-c")
        self.assertRegex(out, r"PASSED\s+pass-d")
        self.assertIn("passed=2", out)
        self.assertIn("failed=2", out)


@unittest.skipIf(importlib.util.find_spec("nox") is None, "nox not installed")
class TestNoxSessionLedgerDefault(unittest.TestCase):
    """
    Pin that the nox sessions apply the shipped expected-failures file.

    Without it the four acknowledged SKIPPED modules turn every
    ``conformance_basic`` run red, so no green session run exists and
    a real regression is indistinguishable from the baseline.
    """

    def test_ledger_is_appended_by_default(self) -> None:
        from _nox.conformance import with_default_expected_failures

        args = with_default_expected_failures(["--plan", _PLAN])
        self.assertEqual(
            [
                "--plan",
                _PLAN,
                "--expected-failures",
                "tests/conformance/expected_failures.json",
            ],
            args,
        )

    def test_operator_ledger_is_kept(self) -> None:
        from _nox.conformance import with_default_expected_failures

        args = ["--expected-failures", "mine.json"]
        self.assertEqual(args, with_default_expected_failures(args))
