"""
Plan-level orchestration: filter -> per-module run -> archive ->
summary.

Glues together ``client``, ``filtering`` and ``summary`` without
re-implementing any of their concerns. The single public entry point
is ``run_plan``; ``cli.main`` is the argparse front-end.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import requests

from .client import (
    create_plan,
    export_plan_html,
    run_module,
    wait_for_suite_ready,
)
from .filtering import filter_modules
from .summary import emit_summary, write_summary_json

if TYPE_CHECKING:
    import pathlib

    from .config import ModuleResult

logger = logging.getLogger(__name__)


def run_plan(
    plan_name: str,
    *,
    module_variant: dict[str, str] | None = None,
    plan_variant: dict[str, str] | None = None,
    strict_warnings: bool = False,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
    isolated: bool = False,
    sleep_between_s: float = 5.0,
    export_dir: pathlib.Path | None = None,
    expected_failures: dict[str, str] | None = None,
    summary_json: pathlib.Path | None = None,
) -> int:
    """
    Run every module in a plan and return a process exit code.

    ``plan_variant`` (subset, often empty) is passed at plan creation;
    ``module_variant`` (full set required by each module) is passed at
    module creation. The two-level split matches the suite's API:
    plans pre-bake some variants and reject user-supplied duplicates.
    ``include`` / ``exclude`` filter the plan's module list locally
    (see ``filter_modules``) — useful for skipping modules that hit
    upstream limitations (HtmlUnit 4.11.1 NPE).

    ``isolated=True`` creates a fresh plan per module instead of
    sharing one plan across all modules. Use it for discovery runs
    where one module's HtmlUnit NPE would otherwise poison subsequent
    modules' browser state. Costs ~1-2 seconds of plan-creation
    overhead per module; on a ~30-minute basic-cert run that is
    negligible.

    ``sleep_between_s`` is a pause inserted between modules to give
    the suite's WebRunner thread time to fully dispatch before the
    next module re-acquires the same plan ``alias`` (the field that
    routes callback URLs). Without the pause, fast back-to-back
    modules trigger ``TEST-RUNNER: Stopping test due to alias
    conflict`` on the second module, which then TIMEOUTs without
    ever running. Default 5 seconds — empirically sufficient on a
    developer laptop. Set to 0 to disable.

    Returns 0 if every module passed (and warnings are tolerated
    unless ``strict_warnings``); 1 otherwise. Filtered-out modules
    are reported in the summary but do NOT influence the exit code —
    they were never executed.
    """
    session = requests.Session()
    # Wait for Spring Boot to finish warming up — docker-compose's
    # --wait can return before /api/runner/available answers 200.
    # Without this, the initial POST /api/plan races startup and
    # leaves first-module diagnostics ambiguous.
    wait_for_suite_ready(session)
    # Always create one plan up front to discover the module list,
    # even in isolated mode — that is how we learn which modules the
    # plan ships. In shared mode this same plan is reused for every
    # module; in isolated mode each module runs against a fresh plan
    # created inside the loop and this initial plan is only the
    # "catalogue".
    catalogue = create_plan(
        session, plan_name=plan_name, plan_variant=plan_variant
    )
    catalogue_id = catalogue.get("id") or catalogue["_id"]
    modules = catalogue.get("modules", [])
    logger.info("plan id=%s contains %d modules", catalogue_id, len(modules))

    selected, skipped_filtered, missing = filter_modules(
        modules, include=include, exclude=exclude
    )
    if missing:
        # A typo in --include would otherwise silently produce an
        # empty run with exit 0 ("nothing failed"). Surface it loudly.
        logger.warning(
            "--include names not present in plan (typo?): %s",
            ", ".join(missing),
        )
    if skipped_filtered:
        logger.info(
            "filter applied: %d module(s) skipped, %d to run",
            len(skipped_filtered),
            len(selected),
        )
    if isolated:
        logger.info("isolated mode: each module runs against a fresh plan")

    module_variant = module_variant or {}

    results: list[ModuleResult] = []
    for index, entry in enumerate(selected):
        # Plan modules look like
        # ``{"testModule": "oidcc-server", "variant": {...}, ...}``.
        # Plans pre-bake the right variant for each module; using
        # ours globally breaks modules whose plan-variant differs
        # from the runner default (e.g.
        # ``oidcc-server-client-secret-post`` needs
        # ``client_auth_type=client_secret_post``). Prefer the
        # plan-supplied variant; fall back to the runner default
        # only if the plan didn't ship one.
        module_name = entry.get("testModule") or entry.get("name", "?")
        per_module_variant = entry.get("variant") or module_variant
        if isolated:
            fresh = create_plan(
                session,
                plan_name=plan_name,
                plan_variant=plan_variant,
            )
            target_plan_id = fresh.get("id") or fresh["_id"]
        else:
            target_plan_id = catalogue_id
        result = run_module(
            session,
            plan_id=target_plan_id,
            module_name=module_name,
            module_variant=per_module_variant,
        )
        results.append(result)
        logger.info("  %s -> %s", result.name, result.result)
        # Avoid alias conflict with the next module: suite's
        # WebRunner thread can still hold the plan alias for a
        # second or two after the module reports FINISHED. Skip
        # the pause after the last module.
        if sleep_between_s > 0 and index < len(selected) - 1:
            time.sleep(sleep_between_s)

    # Best-effort HTML archive — failure here logs and continues so
    # an export hiccup does not mask test outcomes.
    if export_dir is not None:
        try:
            archive = export_plan_html(
                session, plan_id=catalogue_id, target_dir=export_dir
            )
            logger.info("exported plan archive: %s", archive)
        except requests.RequestException as exc:
            logger.warning("export to %s failed: %s", export_dir, exc)

    if summary_json is not None:
        write_summary_json(
            summary_json,
            results=results,
            skipped_filtered=skipped_filtered,
            expected_failures=expected_failures or {},
            plan_name=plan_name,
            plan_id=str(catalogue_id),
        )
        logger.info("wrote summary json: %s", summary_json)

    return emit_summary(
        results,
        skipped_filtered=skipped_filtered,
        strict_warnings=strict_warnings,
        expected_failures=expected_failures or {},
    )
