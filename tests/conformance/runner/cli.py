"""
Argparse front-end for the conformance plan runner.

The real work lives in ``orchestrator.run_plan``; this module is
strictly about decoding command-line arguments into the orchestrator
keyword set and wiring up logging.
"""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import sys

import requests

from .client import create_plan, wait_for_suite_ready
from .config import DEFAULT_VARIANT, PLAN_VARIANT_DEFAULTS, module_name
from .filtering import load_expected_failures
from .orchestrator import run_plan


def main(argv: list[str] | None = None) -> int:
    """Parse argv and dispatch to ``run_plan``. Returns exit code."""
    parser = argparse.ArgumentParser(
        description=(
            "Drive an OIDC Conformance Suite plan via the suite's "
            "REST API. Submits a test plan, kicks off every module "
            "in it, polls until each finishes, then prints an "
            "aggregate summary and exits non-zero if any module "
            "FAILED."
        )
    )
    parser.add_argument(
        "--plan",
        default="oidcc-config-certification-test-plan",
        help=(
            "Conformance plan name. Default is the Config Certification "
            "plan: one module (``oidcc-discovery-endpoint-verification``) "
            "that exercises the discovery + JWKS contract. Larger plans "
            "(e.g. ``oidcc-basic-certification-test-plan``, ~35 modules) "
            "need plan-specific variant juggling — see README. Query "
            "``/api/plan/available`` on the running suite for the full "
            "list."
        ),
    )
    parser.add_argument(
        "--variant",
        default="",
        help=(
            "Module-level variant JSON. Defaults to a code-flow + "
            "secret-basic + static-registration combo that fits this "
            "provider; override for other auth/response combos."
        ),
    )
    parser.add_argument(
        "--plan-variant",
        default="",
        help=(
            "Plan-level variant JSON; usually omit. Only some plans "
            "accept user-overridable variants at creation time and "
            "the suite rejects keys the plan pre-bakes."
        ),
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Treat WARNING modules as failures.",
    )
    parser.add_argument(
        "--include",
        nargs="+",
        metavar="PATTERN",
        default=None,
        help=(
            "Run only modules matching these patterns (allow-list). "
            "fnmatch globs supported, e.g. ``--include oidcc-server "
            "'oidcc-id-token-*'``. Without a glob the pattern is an "
            "exact name. Filtered modules show as FILTERED in the "
            "summary and do not influence the exit code."
        ),
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="PATTERN",
        default=None,
        help=(
            "Drop modules matching these patterns. fnmatch globs "
            "supported, e.g. ``--exclude 'oidcc-userinfo-*'`` to "
            "skip all userinfo modules. Applied after --include if "
            "both are given."
        ),
    )
    parser.add_argument(
        "--isolated",
        action="store_true",
        help=(
            "Create a fresh plan instance per module instead of "
            "sharing one plan across all modules. Use for discovery "
            "runs where one module's HtmlUnit NPE would otherwise "
            "poison subsequent modules' browser state. Costs ~1-2 "
            "seconds of plan-creation overhead per module."
        ),
    )
    parser.add_argument(
        "--sleep-between",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help=(
            "Seconds to wait between modules. Suite's WebRunner "
            "thread can still hold the plan alias for ~1-2 seconds "
            "after a module reports FINISHED, causing the next "
            "module to fail with 'alias conflict'. Default 5; set 0 "
            "to disable for offline-mode plans that do not exercise "
            "the browser path."
        ),
    )
    parser.add_argument(
        "--export-dir",
        type=pathlib.Path,
        default=None,
        metavar="DIR",
        help=(
            "After the run, download the suite's HTML report archive "
            "(GET /api/plan/exporthtml/{plan_id}) into this directory "
            "as ``{plan_id}.zip``. The archive contains one HTML file "
            "per module with full event log — useful for archiving a "
            "run or attaching to a certification submission."
        ),
    )
    parser.add_argument(
        "--expected-failures",
        type=pathlib.Path,
        default=None,
        metavar="FILE",
        help=(
            "JSON file mapping ``module-name`` -> reason. Modules "
            "listed there are treated as known-acknowledged failures: "
            "FAILED/TIMEOUT/ERROR are re-bucketed as XFAIL and do not "
            "influence the exit code; PASSED triggers an XPASS alarm "
            "so a stale entry doesn't go unnoticed. Mirrors the "
            "upstream run-test-plan.py --expected-failures-file "
            "pattern."
        ),
    )
    parser.add_argument(
        "--summary-json",
        type=pathlib.Path,
        default=None,
        metavar="FILE",
        help=(
            "Write a machine-readable summary as JSON to FILE for "
            "later aggregation by a per-module orchestrator (see "
            "``run_per_module.sh`` + ``aggregate_summaries.py``). "
            "Schema: {plan_name, plan_id, summary{...}, results[], "
            "skipped_filtered[], expected_failures{}}."
        ),
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help=(
            "Create a plan, print one module name per line and exit. "
            "Does not run any modules. Used by the per-module "
            "orchestrator to enumerate the plan before tearing the "
            "stack down for the per-module loop."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING"),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    module_variant = (
        json.loads(args.variant) if args.variant else DEFAULT_VARIANT
    )
    if args.plan_variant:
        plan_variant = json.loads(args.plan_variant)
    else:
        plan_variant = PLAN_VARIANT_DEFAULTS.get(args.plan)
    include = set(args.include) if args.include else None
    exclude = set(args.exclude) if args.exclude else None
    expected_failures = (
        load_expected_failures(args.expected_failures)
        if args.expected_failures is not None
        else None
    )
    if args.list_modules:
        # Discovery-only mode: create a plan, print module names,
        # exit. No modules are kicked off, so the suite stack can be
        # torn down right after. Wait for Spring Boot first — same
        # reason as in run_plan().
        session = requests.Session()
        wait_for_suite_ready(session)
        catalogue = create_plan(
            session, plan_name=args.plan, plan_variant=plan_variant
        )
        for entry in catalogue.get("modules", []):
            sys.stdout.write(f"{module_name(entry)}\n")
        return 0
    return run_plan(
        args.plan,
        module_variant=module_variant,
        plan_variant=plan_variant,
        strict_warnings=args.strict_warnings,
        include=include,
        exclude=exclude,
        isolated=args.isolated,
        sleep_between_s=args.sleep_between,
        export_dir=args.export_dir,
        expected_failures=expected_failures,
        summary_json=args.summary_json,
    )
