"""
Per-run summary: status table, XFAIL/XPASS bucketing, and the
copy-pasteable allowlist/denylist blocks.

Pure stdlib; deliberately decoupled from network code so it can be
exercised with synthetic ``ModuleResult`` lists in unit tests without
spinning up the suite stack.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from .config import (
    NON_FAILURE_RESULTS,
    PASS_RESULTS,
    REVIEW_RESULTS,
    WARN_RESULTS,
    ModuleResult,
)

if TYPE_CHECKING:
    import pathlib

    from .filtering import ExpectedFailure


def _bucket_results(
    results: list[ModuleResult],
    expected_failures: dict[str, ExpectedFailure],
) -> tuple[
    list[ModuleResult],  # passed
    list[ModuleResult],  # review
    list[ModuleResult],  # warned
    list[ModuleResult],  # failed_real
    list[ModuleResult],  # xfail
    list[ModuleResult],  # xpass
]:
    """
    Split a result list into the six buckets the summary cares
    about. Single source of truth so ``emit_summary`` and
    ``write_summary_json`` count identically.

    Every result outside ``NON_FAILURE_RESULTS`` is a failure; it is
    an XFAIL only when the module's ledger entry pins that exact
    result. A ledger module that did not fail (PASSED, REVIEW or
    WARNING) is an XPASS: its entry is stale.
    """
    passed = [r for r in results if r.result in PASS_RESULTS]
    review = [r for r in results if r.result in REVIEW_RESULTS]
    warned = [r for r in results if r.result in WARN_RESULTS]
    failed = [r for r in results if r.result not in NON_FAILURE_RESULTS]
    xfail = [
        r
        for r in failed
        if r.name in expected_failures
        and expected_failures[r.name].result == r.result
    ]
    xfail_names = {r.name for r in xfail}
    failed_real = [r for r in failed if r.name not in xfail_names]
    xpass = [
        r
        for r in results
        if r.result in NON_FAILURE_RESULTS and r.name in expected_failures
    ]
    return passed, review, warned, failed_real, xfail, xpass


def _write_alarms(
    xpass: list[ModuleResult],
    review: list[ModuleResult],
    expected_failures: dict[str, ExpectedFailure],
) -> None:
    """Print the UNEXPECTED PASS and NEEDS HUMAN REVIEW blocks."""
    if xpass:
        sys.stdout.write(
            "\n!!! UNEXPECTED PASS - these modules are listed in "
            "--expected-failures but did not fail. Edit the file to "
            "drop them; they may have been fixed upstream:\n"
        )
        for r in xpass:
            reason = expected_failures[r.name].reason
            sys.stdout.write(f"  {r.name}  {r.result}  ({reason})\n")
    if review:
        sys.stdout.write(
            "\n!!! NEEDS HUMAN REVIEW (not certification evidence) - "
            "inspect the screenshot the suite attached to:\n"
        )
        for r in review:
            sys.stdout.write(f"  {r.name}  ({r.test_id})\n")


def emit_summary(
    results: list[ModuleResult],
    *,
    skipped_filtered: list[str] | None = None,
    strict_warnings: bool,
    expected_failures: dict[str, ExpectedFailure] | None = None,
) -> int:
    """
    Print a one-line-per-module summary and return an exit code.

    ``skipped_filtered`` lists modules removed by ``--include`` /
    ``--exclude`` before execution. They are reported as ``FILTERED``
    so a green allowlist run is visibly distinct from a green full
    run, but do NOT participate in the exit-code calculation: the
    suite never saw them.

    ``expected_failures`` maps modules that are known not to pass
    (e.g. an unimplemented optional spec feature the suite SKIPs) to
    the exact result acknowledged for them. A module finishing with
    that result is re-bucketed as ``XFAIL`` and removed from the
    exit-code denylist; any other non-passing result stays a real
    failure. A listed module that did not fail raises ``XPASS``
    (unexpected pass) and fails the run: the stale entry would
    otherwise mask a later regression of that module.

    ``REVIEW`` modules count separately from ``passed`` and are
    listed under NEEDS HUMAN REVIEW; they do not change the exit
    code. A run in which no module executed exits 1: nothing was
    verified.
    """
    skipped_filtered = skipped_filtered or []
    expected_failures = expected_failures or {}
    passed, review, warned, failed_real, xfail, xpass = _bucket_results(
        results, expected_failures
    )

    # Bucketing is by module name, not by ``ModuleResult`` identity:
    # ``ModuleResult`` is a non-frozen dataclass with field-wise
    # ``__eq__``, so two results that happened to share name/test_id/
    # result/log_excerpt would collide under value equality. Name is
    # the stable per-module key the suite itself addresses.
    xfail_names = {r.name for r in xfail}
    xpass_names = {r.name for r in xpass}
    sys.stdout.write("\n=== Conformance summary ===\n")
    for r in results:
        if r.name in xfail_names:
            marker = "XFAIL"
        elif r.name in xpass_names:
            marker = "XPASS"
        else:
            marker = r.result
        sys.stdout.write(f"{marker:<8} {r.name}  ({r.test_id})\n")
    for name in skipped_filtered:
        sys.stdout.write(f"{'FILTERED':<8} {name}\n")
    sys.stdout.write(
        f"\npassed={len(passed)} review={len(review)} "
        f"warned={len(warned)} "
        f"failed={len(failed_real)} xfail={len(xfail)} "
        f"xpass={len(xpass)} skipped={len(skipped_filtered)} "
        f"total={len(results) + len(skipped_filtered)}\n"
    )

    _write_alarms(xpass, review, expected_failures)

    # Copy-pasteable allowlist / denylist blocks. After a discovery
    # run (e.g. ``--isolated`` against a full plan) the operator wants
    # to lock subsequent runs to a stable subset; sorted plain-text
    # blocks make that a one-shot copy. Only emitted when both halves
    # are non-empty — a fully-green or fully-red run does not need
    # the bucketing.
    pass_names = sorted(r.name for r in (passed + review + warned))
    fail_names = sorted(r.name for r in (failed_real + xfail))
    if pass_names and fail_names:
        sys.stdout.write("\n=== Module groups ===\n")
        sys.stdout.write(
            "# Allowlist (PASSED + REVIEW + WARNING) - paste into --include:\n"
        )
        for name in pass_names:
            sys.stdout.write(f"{name}\n")
        sys.stdout.write(
            "\n# Denylist (every other result) - paste into --exclude:\n"
        )
        for name in fail_names:
            sys.stdout.write(f"{name}\n")

    if not results:
        sys.stdout.write("\n!!! NO MODULE EXECUTED - nothing verified\n")
        return 1
    if failed_real or xpass:
        return 1
    if warned and strict_warnings:
        return 1
    return 0


def write_summary_json(
    path: pathlib.Path,
    *,
    results: list[ModuleResult],
    skipped_filtered: list[str],
    expected_failures: dict[str, ExpectedFailure],
    plan_name: str,
    plan_id: str,
) -> None:
    """
    Serialise a single run's outcome as JSON for offline aggregation.

    The schema is intentionally flat so a downstream aggregator
    (``aggregate_summaries.py``) can concatenate per-module files
    from a per-module restart loop into one combined view. Counts
    use the same six-bucket breakdown as ``emit_summary``.
    """
    passed, review, warned, failed_real, xfail, xpass = _bucket_results(
        results, expected_failures
    )
    payload = {
        "plan_name": plan_name,
        "plan_id": plan_id,
        "summary": {
            "passed": len(passed),
            "review": len(review),
            "warned": len(warned),
            "failed": len(failed_real),
            "xfail": len(xfail),
            "xpass": len(xpass),
            "skipped_filtered": len(skipped_filtered),
            "total": len(results) + len(skipped_filtered),
        },
        "results": [
            {
                "name": r.name,
                "test_id": r.test_id,
                "result": r.result,
            }
            for r in results
        ],
        "skipped_filtered": list(skipped_filtered),
        "expected_failures": {
            name: {"result": entry.result, "reason": entry.reason}
            for name, entry in expected_failures.items()
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
