"""
Thin compatibility shim — the runner moved to
``tests.conformance.runner``.

Kept so ``python tests/conformance/run_plan.py …`` (driven by
``noxfile.py``) keeps working, and so the existing
``tests.test_conformance_runner`` import path
(``from tests.conformance.run_plan import ModuleResult, _emit_summary``)
does not break. New code should import from
``tests.conformance.runner`` directly.
"""

from __future__ import annotations

from tests.conformance.runner import ModuleResult, main, run_plan
from tests.conformance.runner.summary import emit_summary as _emit_summary

__all__ = ["ModuleResult", "_emit_summary", "main", "run_plan"]


if __name__ == "__main__":
    raise SystemExit(main())
