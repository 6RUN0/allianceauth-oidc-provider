"""
Test double for ``run_plan.py`` driven by ``run_per_module.sh`` tests.

``--expected-failures`` is parsed with the real loader, so a broken
ledger fails every invocation as in the real runner. ``--list-modules``
prints the comma-separated ``STUB_MODULES`` env value one name per
line. A per-module run picks its behaviour from the module-name
prefix, mirroring the real runner's outcomes:

- ``pass-``: summary JSON with PASSED, exit 0;
- ``warn-``: summary JSON with WARNING, exit 1 under
  ``--strict-warnings``, else 0;
- ``skip-``: summary JSON with SKIPPED, exit 1;
- ``empty-``: summary JSON with no results, exit 1 (exception inside
  the orchestrator ``try``, the ``finally`` still writes the file);
- ``crash-``: no summary JSON, exit 3 (harness died before writing).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from tests.conformance.runner.filtering import load_expected_failures


def main() -> int:
    """Emulate one ``run_plan.py`` invocation; return its exit code."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--list-modules", action="store_true")
    parser.add_argument("--include")
    parser.add_argument("--summary-json", type=pathlib.Path)
    parser.add_argument("--expected-failures", type=pathlib.Path)
    parser.add_argument("--strict-warnings", action="store_true")
    args, _ = parser.parse_known_args()
    if args.expected_failures is not None:
        load_expected_failures(args.expected_failures)
    if args.list_modules:
        for name in os.environ["STUB_MODULES"].split(","):
            sys.stdout.write(f"{name}\n")
        return 0
    module = args.include
    if module.startswith("crash-"):
        return 3
    if module.startswith("empty-"):
        results = []
    else:
        verdict = {"pass-": "PASSED", "warn-": "WARNING"}.get(
            module[:5], "SKIPPED"
        )
        results = [{"name": module, "test_id": "t", "result": verdict}]
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    args.summary_json.write_text(
        json.dumps(
            {
                "plan_name": args.plan,
                "plan_id": "p",
                "results": results,
                "skipped_filtered": [],
            }
        )
    )
    if module.startswith("warn-"):
        return 1 if args.strict_warnings else 0
    return 0 if module.startswith("pass-") else 1


if __name__ == "__main__":
    raise SystemExit(main())
