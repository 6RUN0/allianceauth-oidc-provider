"""
Aggregate per-module ``--summary-json`` files into one combined view.

Companion to ``run_per_module.sh``: that script writes one JSON per
module under ``RESULTS_DIR``; this aggregator walks the directory
and produces the same allowlist/denylist + counts that
``emit_summary`` prints for a shared-stack run.

Usage::

    python tests/conformance/aggregate_summaries.py results/
    python tests/conformance/aggregate_summaries.py results/ \
        --expected-failures known_failures.json

Exits non-zero if any module landed in the real-failures bucket
(matches the per-run exit-code contract).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from tests.conformance.runner.config import ModuleResult
from tests.conformance.runner.filtering import load_expected_failures
from tests.conformance.runner.summary import emit_summary


def _collect_results(
    results_dir: pathlib.Path,
) -> tuple[list[ModuleResult], list[str]]:
    """
    Walk ``results_dir`` and load every ``*.json`` summary written
    by a per-module run. Returns ``(results, skipped_filtered)`` —
    each module's first ``ModuleResult`` is taken (per-module runs
    only target one module, so each file should hold exactly one).
    """
    results: list[ModuleResult] = []
    skipped_seen: set[str] = set()
    for path in sorted(results_dir.glob("*.json")):
        data = json.loads(path.read_text())
        results.extend(
            ModuleResult(
                name=entry["name"],
                test_id=entry.get("test_id", ""),
                result=entry["result"],
            )
            for entry in data.get("results", [])
        )
        # Per-module runs only filter at most their own --exclude
        # patterns. Carrying the union across runs preserves any
        # global filter the operator passed via ``-- <runner args>``.
        skipped_seen.update(data.get("skipped_filtered", []))
    return results, sorted(skipped_seen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_dir",
        type=pathlib.Path,
        help="Directory containing per-module JSON summaries.",
    )
    parser.add_argument(
        "--expected-failures",
        type=pathlib.Path,
        default=None,
        metavar="FILE",
        help=(
            "Optional JSON file mapping ``module-name`` -> reason "
            "for XFAIL/XPASS bucketing during aggregation. Same "
            "schema as ``run_plan.py --expected-failures``."
        ),
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Treat WARNING modules as failures.",
    )
    args = parser.parse_args(argv)
    if not args.results_dir.is_dir():
        sys.stderr.write(f"not a directory: {args.results_dir}\n")
        return 2
    results, skipped_filtered = _collect_results(args.results_dir)
    if not results:
        sys.stderr.write(
            f"no *.json files in {args.results_dir}; nothing to aggregate\n"
        )
        return 2
    expected_failures = (
        load_expected_failures(args.expected_failures)
        if args.expected_failures is not None
        else None
    )
    return emit_summary(
        results,
        skipped_filtered=skipped_filtered,
        strict_warnings=args.strict_warnings,
        expected_failures=expected_failures,
    )


if __name__ == "__main__":
    raise SystemExit(main())
