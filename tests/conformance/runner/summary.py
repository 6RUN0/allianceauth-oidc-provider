"""
Per-run summary: status table, XFAIL/XPASS bucketing, and the
copy-pasteable allowlist/denylist blocks.

Pure stdlib; deliberately decoupled from network code so it can be
exercised with synthetic ``ModuleResult`` lists in unit tests without
spinning up the suite stack.
"""

from __future__ import annotations

import json
import pathlib
import sys

from .config import FAIL_RESULTS, PASS_RESULTS, WARN_RESULTS, ModuleResult


def _bucket_results(
    results: list[ModuleResult],
    expected_failures: dict[str, str],
) -> tuple[
    list[ModuleResult],  # passed
    list[ModuleResult],  # warned
    list[ModuleResult],  # failed_real
    list[ModuleResult],  # xfail
    list[ModuleResult],  # xpass
]:
    """
    Split a result list into the five buckets the summary cares
    about. Single source of truth so ``emit_summary`` and
    ``write_summary_json`` count identically.
    """
    fail_states = FAIL_RESULTS | {"TIMEOUT"}
    passed = [r for r in results if r.result in PASS_RESULTS]
    warned = [r for r in results if r.result in WARN_RESULTS]
    failed_real = [
        r
        for r in results
        if r.result in fail_states and r.name not in expected_failures
    ]
    xfail = [
        r
        for r in results
        if r.result in fail_states and r.name in expected_failures
    ]
    xpass = [r for r in passed if r.name in expected_failures]
    return passed, warned, failed_real, xfail, xpass


def emit_summary(
    results: list[ModuleResult],
    *,
    skipped_filtered: list[str] | None = None,
    strict_warnings: bool,
    expected_failures: dict[str, str] | None = None,
) -> int:
    """
    Print a one-line-per-module summary and return an exit code.

    ``skipped_filtered`` lists modules removed by ``--include`` /
    ``--exclude`` before execution. They are reported as ``FILTERED``
    so a green allowlist run is visibly distinct from a green full
    run, but do NOT participate in the exit-code calculation: the
    suite never saw them.

    ``expected_failures`` is a {name: reason} map of modules that are
    known to fail (e.g. an upstream HtmlUnit NPE, or unimplemented
    spec feature). A FAILED/TIMEOUT/ERROR module listed there is
    re-bucketed as ``XFAIL`` and removed from the exit-code denylist;
    a PASSED module listed there raises ``XPASS`` (unexpected pass)
    — that means the file is stale and should be edited.
    """
    skipped_filtered = skipped_filtered or []
    expected_failures = expected_failures or {}
    passed, warned, failed_real, xfail, xpass = _bucket_results(
        results, expected_failures
    )

    sys.stdout.write("\n=== Conformance summary ===\n")
    for r in results:
        marker = r.result
        if r in xfail:
            marker = "XFAIL"
        elif r in xpass:
            marker = "XPASS"
        sys.stdout.write(f"{marker:<8} {r.name}  ({r.test_id})\n")
    for name in skipped_filtered:
        sys.stdout.write(f"{'FILTERED':<8} {name}\n")
    sys.stdout.write(
        f"\npassed={len(passed)} warned={len(warned)} "
        f"failed={len(failed_real)} xfail={len(xfail)} "
        f"xpass={len(xpass)} skipped={len(skipped_filtered)} "
        f"total={len(results) + len(skipped_filtered)}\n"
    )

    if xpass:
        sys.stdout.write(
            "\n!!! UNEXPECTED PASS — these modules are listed in "
            "--expected-failures but PASSED. Edit the file to drop "
            "them; they may have been fixed upstream:\n"
        )
        for r in xpass:
            reason = expected_failures.get(r.name, "")
            sys.stdout.write(f"  {r.name}  ({reason})\n")

    # Copy-pasteable allowlist / denylist blocks. After a discovery
    # run (e.g. ``--isolated`` against a full plan) the operator wants
    # to lock subsequent runs to a stable subset; sorted plain-text
    # blocks make that a one-shot copy. Only emitted when both halves
    # are non-empty — a fully-green or fully-red run does not need
    # the bucketing.
    pass_names = sorted(r.name for r in (passed + warned))
    fail_names = sorted(r.name for r in (failed_real + xfail))
    if pass_names and fail_names:
        sys.stdout.write("\n=== Module groups ===\n")
        sys.stdout.write(
            "# Allowlist (PASSED + WARNING) — paste into --include:\n"
        )
        for name in pass_names:
            sys.stdout.write(f"{name}\n")
        sys.stdout.write(
            "\n# Denylist (FAILED + TIMEOUT) — paste into "
            "--exclude or --expected-failures:\n"
        )
        for name in fail_names:
            sys.stdout.write(f"{name}\n")

    if failed_real:
        return 1
    if warned and strict_warnings:
        return 1
    return 0


def write_summary_json(
    path: pathlib.Path,
    *,
    results: list[ModuleResult],
    skipped_filtered: list[str],
    expected_failures: dict[str, str],
    plan_name: str,
    plan_id: str,
) -> None:
    """
    Serialise a single run's outcome as JSON for offline aggregation.

    The schema is intentionally flat so a downstream aggregator
    (``aggregate_summaries.py``) can concatenate per-module files
    from a per-module restart loop into one combined view. Counts
    use the same five-bucket breakdown as ``emit_summary``.
    """
    passed, warned, failed_real, xfail, xpass = _bucket_results(
        results, expected_failures
    )
    payload = {
        "plan_name": plan_name,
        "plan_id": plan_id,
        "summary": {
            "passed": len(passed),
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
        "expected_failures": dict(expected_failures),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
