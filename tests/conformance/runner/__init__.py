"""
Drive an OIDC Conformance Suite plan via the suite's REST API.

Submits a test plan, kicks off every module in it, polls until each
finishes, then prints an aggregate summary and exits non-zero if any
module FAILED. WARNING-level results are surfaced but do not gate
the exit code by default — pass ``--strict-warnings`` to flip that.

Module layout:

- ``config``       — env vars, ``ModuleResult``, result vocabularies.
- ``plan_config``  — ``build_plan_config`` (suite plan JSON template).
- ``client``       — REST helpers: ``create_plan``, ``poll_module``,
  ``run_module``, ``export_plan_html``.
- ``filtering``    — ``filter_modules``, ``load_expected_failures``.
- ``summary``      — ``emit_summary`` (XFAIL/XPASS, allowlist blocks).
- ``orchestrator`` — ``run_plan`` (the public entry point).
- ``cli``          — argparse front-end (``main``).

Usage::

    python tests/conformance/run_plan.py
    python tests/conformance/run_plan.py --plan oidcc-test-plan
    python tests/conformance/run_plan.py --strict-warnings
"""

from __future__ import annotations

from .cli import main
from .config import (
    DEFAULT_VARIANT,
    FAIL_RESULTS,
    PASS_RESULTS,
    PLAN_VARIANT_DEFAULTS,
    WARN_RESULTS,
    ModuleResult,
)
from .orchestrator import run_plan
from .summary import emit_summary

__all__ = [
    "DEFAULT_VARIANT",
    "FAIL_RESULTS",
    "ModuleResult",
    "PASS_RESULTS",
    "PLAN_VARIANT_DEFAULTS",
    "WARN_RESULTS",
    "emit_summary",
    "main",
    "run_plan",
]
