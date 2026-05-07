"""
Thin wrapper over the conformance suite's REST API.

Three groups of helpers:

- Plan creation: ``create_plan`` (POST /api/plan).
- Module execution + polling: ``poll_module`` (GET /api/info/{id}),
  ``run_module`` (POST /api/runner + poll until verdict).
- Result archiving: ``export_plan_html`` (GET /api/plan/exporthtml/{id}).

The TLS dance (suite serves a self-signed cert for
``localhost.emobix.co.uk``) is handled with ``verify=False`` plus a
silenced ``urllib3`` warning — keeps the harness self-contained.
"""

from __future__ import annotations

import json
import logging
import pathlib
import time
from typing import Any

import requests
import urllib3

from .config import ModuleResult, SUITE_URL
from .plan_config import build_plan_config

# The suite's TLS cert is self-signed for localhost.emobix.co.uk; we
# verify hostnames manually but skip CA verification to keep the
# scaffolding self-contained.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def create_plan(
    session: requests.Session,
    *,
    plan_name: str,
    plan_variant: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    POST /api/plan to create a new test plan instance.

    ``plan_variant`` is the **subset** of variant keys the plan
    exposes to the user; passing keys the plan pre-bakes is rejected
    with a 400. Most plans accept an empty variant — the suite uses
    its baked-in defaults — so callers should omit unless they know
    the plan needs explicit overrides.
    """
    params: dict[str, Any] = {"planName": plan_name}
    if plan_variant:
        params["variant"] = json.dumps(plan_variant)
    resp = session.post(
        f"{SUITE_URL}/api/plan",
        params=params,
        json=build_plan_config(),
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def poll_module(
    session: requests.Session,
    *,
    module_id: str,
    timeout_s: int = 180,
    poll_interval_s: int = 3,
) -> str:
    """
    Wait for a module to leave the RUNNING state and return its result.

    Returns one of the strings in PASS_RESULTS / WARN_RESULTS /
    FAIL_RESULTS, or "TIMEOUT" if the module didn't finish in
    ``timeout_s`` seconds. Queries ``/api/info/{id}``: that endpoint
    carries the ``status`` (CREATED / WAITING / RUNNING / FINISHED /
    INTERRUPTED) and ``result`` (PASSED / FAILED / WARNING /
    SKIPPED) fields. ``/api/runner/{id}`` returns a different shape
    without these.

    Default ``timeout_s`` is 180s — empirically the browser-driven
    code-flow happy paths (login form fill + consent click + token
    exchange + userinfo probe) take ~60-90s on a developer laptop;
    cold-start under ``--isolated`` can push that further. The cap
    still bounds the impact of HtmlUnit 4.11.1's NPE — modules that
    truly hang return TIMEOUT within 3 minutes rather than wedging
    the whole run.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = session.get(
            f"{SUITE_URL}/api/info/{module_id}",
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        status = body.get("status", "")
        if status not in {"CREATED", "WAITING", "RUNNING"}:
            return body.get("result") or status or "UNKNOWN"
        time.sleep(poll_interval_s)
    return "TIMEOUT"


def run_module(
    session: requests.Session,
    *,
    plan_id: str,
    module_name: str,
    module_variant: dict[str, str],
) -> ModuleResult:
    """
    Kick off a single module under ``plan_id`` and wait for the verdict.

    POST /api/runner creates AND starts the test in one step; no
    separate "start" call needed (the older /api/runner/{id} POST is
    for resume/interactive use, not initial kickoff). The variant
    must be the FULL required set — the suite does not auto-merge
    plan-baked + user-supplied at module-creation time.

    A 500 / 4xx response from the suite (typically variant-mismatch
    on plan modules whose pre-baked variant differs from the runner
    default — e.g. ``oidcc-server-client-secret-post`` requires
    ``client_auth_type=client_secret_post``) is logged and surfaces
    as ``ERROR`` so a single misconfigured module does not crash the
    whole run.
    """
    try:
        create_resp = session.post(
            f"{SUITE_URL}/api/runner",
            params={
                "test": module_name,
                "plan": plan_id,
                "variant": json.dumps(module_variant),
            },
            verify=False,
            timeout=30,
        )
        create_resp.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        logger.warning(
            "could not start %s: HTTP %s (variant mismatch?)",
            module_name,
            status,
        )
        return ModuleResult(name=module_name, test_id="", result="ERROR")
    module_id = create_resp.json()["id"]
    logger.info("started %s -> %s", module_name, module_id)
    result = poll_module(session, module_id=module_id)
    return ModuleResult(name=module_name, test_id=module_id, result=result)


def export_plan_html(
    session: requests.Session,
    *,
    plan_id: str,
    target_dir: pathlib.Path,
) -> pathlib.Path:
    """
    Download the suite's HTML report archive for a finished plan.

    Calls ``GET /api/plan/exporthtml/{plan_id}`` and streams the
    response to ``{target_dir}/{plan_id}.zip``. The archive contains
    one HTML file per module with its full event log — useful for
    archiving a run, sharing with reviewers, or attaching to a
    certification submission.

    Mirrors the upstream ``conformance.py:exporthtml()`` pattern.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    archive = target_dir / f"{plan_id}.zip"
    resp = session.get(
        f"{SUITE_URL}/api/plan/exporthtml/{plan_id}",
        verify=False,
        timeout=120,
        stream=True,
    )
    resp.raise_for_status()
    with archive.open("wb") as fh:
        for chunk in resp.iter_content(chunk_size=8192):
            fh.write(chunk)
    return archive
