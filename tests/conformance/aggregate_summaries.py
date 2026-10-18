r"""
Aggregate per-module ``--summary-json`` files into one combined view.

Companion to ``run_per_module.sh``: that script writes one
``<module>.json`` per module into a fresh per-run directory; this
aggregator reads exactly the files of the expected module list and
produces the same allowlist/denylist + counts that ``emit_summary``
prints for a shared-stack run.

Usage::

    python tests/conformance/aggregate_summaries.py RUN_DIR \
        --expected-modules RUN_DIR/modules.txt \
        --plan-name oidcc-basic-certification-test-plan \
        --exit-codes RUN_DIR/exit_codes.tsv \
        --expected-failures tests/conformance/expected_failures.json

Every expected module is accounted for: a missing, unreadable or
result-less ``<module>.json``, a file written for another plan, and a
``run_plan.py`` exit code other than 0 (all passed) or 1 (a module
failed) are reported as ``ERROR`` for that module. Exits non-zero if
any module landed in the real-failures bucket (matches the per-run
exit-code contract).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from tests.conformance.runner.config import ModuleResult
from tests.conformance.runner.filtering import load_expected_failures
from tests.conformance.runner.summary import emit_summary

# ``run_plan.py`` exits 0 when every module passed and 1 when a
# module failed (an uncaught Python exception also exits 1, which the
# missing or empty summary JSON then exposes). Anything else means
# the harness itself died: argparse error, signal, OOM kill.
_RUNNER_VERDICT_EXIT_CODES = frozenset({0, 1})


def _load_summary(
    path: pathlib.Path, plan_name: str | None
) -> tuple[dict | None, str]:
    """
    Load one per-module summary file for this run's plan.

    Returns ``(data, problem)``: the parsed object, or ``None`` with a
    human-readable reason when the file is missing, unreadable, not a
    JSON object, or was written for another plan.
    """
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return None, f"no summary file {path}"
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable summary file {path}: {exc}"
    if not isinstance(data, dict):
        problem = f"summary file {path} is not a JSON object"
    elif plan_name is not None and data.get("plan_name") != plan_name:
        problem = f"summary file {path} is for plan {data.get('plan_name')!r}"
    else:
        return data, ""
    return None, problem


def _read_module_result(
    path: pathlib.Path,
    module: str,
    plan_name: str | None,
) -> tuple[ModuleResult | None, bool, str]:
    """
    Read one module's verdict from its per-module summary file.

    Returns ``(result, filtered, problem)``: the module's own result,
    whether its run filtered it out (``--exclude`` forwarded by the
    operator), and a human-readable problem when neither is
    available. Only the entry naming ``module`` counts: the file of
    another module is never evidence for this one.
    """
    data, problem = _load_summary(path, plan_name)
    if data is None:
        return None, False, problem
    for entry in data.get("results", []):
        if isinstance(entry, dict) and entry.get("name") == module:
            result = ModuleResult(
                name=module,
                test_id=str(entry.get("test_id", "")),
                result=str(entry.get("result", "")),
            )
            return result, False, ""
    filtered = module in data.get("skipped_filtered", [])
    return None, filtered, f"summary file {path} holds no result for it"


def _read_exit_codes(path: pathlib.Path) -> dict[str, int]:
    """Parse the tab-separated module / exit-code lines of the loop."""
    codes: dict[str, int] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        module, _, code = line.partition("\t")
        codes[module] = int(code)
    return codes


def _collect_results(
    run_dir: pathlib.Path,
    *,
    expected_modules: list[str],
    plan_name: str | None,
    exit_codes: dict[str, int],
) -> tuple[list[ModuleResult], list[str]]:
    """
    Resolve every expected module to a result or a filter entry.

    Returns ``(results, skipped_filtered)``. A module whose verdict
    cannot be established becomes an ``ERROR`` result, with the
    reason written to stderr, so a lost module turns the aggregate
    red instead of shrinking the totals.
    """
    results: list[ModuleResult] = []
    skipped_filtered: list[str] = []
    for module in expected_modules:
        result, filtered, problem = _read_module_result(
            run_dir / f"{module}.json", module, plan_name
        )
        exit_code = exit_codes.get(module)
        if (
            exit_code is not None
            and exit_code not in _RUNNER_VERDICT_EXIT_CODES
        ):
            result = None
            filtered = False
            problem = f"run_plan.py exited with {exit_code}"
        if filtered:
            skipped_filtered.append(module)
            continue
        if result is None:
            sys.stderr.write(f"ERROR {module}: {problem}\n")
            result = ModuleResult(name=module, test_id="", result="ERROR")
        results.append(result)
    return results, skipped_filtered


def main(argv: list[str] | None = None) -> int:
    """Parse argv, aggregate the run directory, return an exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_dir",
        type=pathlib.Path,
        help="Per-run directory holding the <module>.json summaries.",
    )
    parser.add_argument(
        "--expected-modules",
        type=pathlib.Path,
        required=True,
        metavar="FILE",
        help=(
            "File with one plan module name per line; every listed "
            "module must have a verdict or it is reported as ERROR."
        ),
    )
    parser.add_argument(
        "--plan-name",
        default=None,
        help=(
            "Only accept summary files written for this plan; a "
            "file for another plan counts as a missing result."
        ),
    )
    parser.add_argument(
        "--exit-codes",
        type=pathlib.Path,
        default=None,
        metavar="FILE",
        help=(
            "Tab-separated ``<module> <exit code>`` lines recorded by "
            "run_per_module.sh; an exit code other than 0/1 marks "
            "the module ERROR."
        ),
    )
    parser.add_argument(
        "--expected-failures",
        type=pathlib.Path,
        default=None,
        metavar="FILE",
        help=(
            "Optional expected-failures ledger for XFAIL/XPASS "
            "bucketing during aggregation. Same schema as "
            "``run_plan.py --expected-failures``."
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
    expected_modules = [
        line.strip()
        for line in args.expected_modules.read_text().splitlines()
        if line.strip()
    ]
    if not expected_modules:
        sys.stderr.write(
            f"no module names in {args.expected_modules}; "
            "nothing to aggregate\n"
        )
        return 2
    exit_codes = (
        _read_exit_codes(args.exit_codes)
        if args.exit_codes is not None
        else {}
    )
    results, skipped_filtered = _collect_results(
        args.results_dir,
        expected_modules=expected_modules,
        plan_name=args.plan_name,
        exit_codes=exit_codes,
    )
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
