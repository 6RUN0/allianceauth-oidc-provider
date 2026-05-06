"""
Drive an OIDC Conformance Suite plan via the suite's REST API.

Submits a test plan, kicks off every module in it, polls until each
finishes, then prints an aggregate summary and exits non-zero if any
module FAILED. WARNING-level results are surfaced but do not gate the
exit code by default — pass ``--strict-warnings`` to flip that.

This driver is intentionally minimal:

- One HTTP client (``requests``), no async machinery.
- Plan config is built from environment variables so the same script
  works in CI and on a developer laptop.
- The suite's API is documented at the ``/api/info`` endpoint of any
  running suite instance; the relevant routes used here are
  ``/api/plan``, ``/api/runner``, and ``/api/log``.

Usage::

    python tests/conformance/run_plan.py
    python tests/conformance/run_plan.py --plan oidcc-test-plan
    python tests/conformance/run_plan.py --strict-warnings
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3

# The suite's TLS cert is self-signed for localhost.emobix.co.uk; we
# verify hostnames manually but skip CA verification to keep the
# scaffolding self-contained.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("conformance.runner")

# Defaults match docker-compose.yml + conformance_settings.py. Override
# via env when running against another stack.
SUITE_URL = os.environ.get(
    "CONFORMANCE_SUITE_URL", "https://localhost.emobix.co.uk:8443"
)
# Provider URL the suite uses for discoveryUrl + iss. Must align with
# ``OIDC_ISS_ENDPOINT`` in conformance_settings.py — same value lives
# on both sides (run_plan.py runs on host, settings on container) so
# the issuer claim validates.
PUBLIC_URL = os.environ.get(
    "CONFORMANCE_PUBLIC_URL",
    "http://provider:8080/o",
)
CLIENT_ID = os.environ.get("CONFORMANCE_CLIENT_ID", "conformance-client")
CLIENT_SECRET = os.environ.get(
    "CONFORMANCE_CLIENT_SECRET",
    "conformance-secret",  # nosec B105
)
CLIENT2_ID = os.environ.get("CONFORMANCE_CLIENT2_ID", "conformance-client2")
CLIENT2_SECRET = os.environ.get(
    "CONFORMANCE_CLIENT2_SECRET",
    "conformance-secret-2",  # nosec B105
)
USERNAME = os.environ.get("CONFORMANCE_USERNAME", "conformance")
PASSWORD = os.environ.get(
    "CONFORMANCE_PASSWORD",
    "conformance-pass",  # nosec B105
)
# Default variant passed at MODULE creation (the suite requires the
# full set per module). Plan creation, in contrast, must NOT include
# variants the plan pre-bakes — so we omit it entirely there. Tweak
# via ``--variant '{"k":"v"}'`` for plans that need a different combo.
DEFAULT_VARIANT: dict[str, str] = {
    "client_auth_type": "client_secret_basic",
    "client_registration": "static_client",
    "server_metadata": "discovery",
    "response_type": "code",
    "response_mode": "default",
}

# Result codes the suite emits. See ConformanceTestResult.java.
PASS_RESULTS: frozenset[str] = frozenset({"PASSED", "REVIEW"})
WARN_RESULTS: frozenset[str] = frozenset({"WARNING"})
FAIL_RESULTS: frozenset[str] = frozenset({"FAILED", "SKIPPED"})


@dataclass
class ModuleResult:
    """Per-module outcome reported by the suite."""

    name: str
    test_id: str
    result: str  # PASSED / FAILED / WARNING / REVIEW / SKIPPED
    log_excerpt: list[dict[str, Any]] = field(default_factory=list)


def build_plan_config() -> dict[str, Any]:
    """
    Build the JSON config the suite stores against a plan.

    Mirrors the shape suite plans expect: ``server.discoveryUrl`` plus
    a ``client`` block with our pre-registered credentials. Login
    credentials go under ``resource`` so the suite's browser driver
    can submit AA's standard Django login form.
    """
    return {
        "alias": "conformance",
        "description": "allianceauth-oidc-provider conformance run",
        "server": {
            # OIDC Discovery 1.0 §4: discoveryUrl is the issuer URL
            # plus exactly ``/.well-known/openid-configuration`` — no
            # trailing slash. The suite's CheckDiscEndpointDiscoveryUrl
            # validates this strictly.
            "discoveryUrl": (f"{PUBLIC_URL}/.well-known/openid-configuration"),
        },
        # The basic-cert plan drives two pre-registered clients
        # through some modules. Both must be created on the provider
        # side (see seed.py).
        "client": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        "client2": {
            "client_id": CLIENT2_ID,
            "client_secret": CLIENT2_SECRET,
        },
        "resource": {
            "resourceUrl": f"{PUBLIC_URL}/userinfo/",
        },
        # ``browser`` is a list of browser-driving sequences (the
        # suite casts it as a JsonArray on init). Selectors target
        # AA's stock Django auth login form; override the public URL
        # via env if your provider runs behind a reverse proxy with a
        # different path prefix.
        "browser": [
            # PUBLIC_URL ends with ``/o``; AA's login form lives on
            # the host root (``/account/login/``), so we match the URL
            # without the OIDC path prefix.
            {
                "match": (f"{PUBLIC_URL.rstrip('/o')}/account/login/*"),
                "tasks": [
                    {
                        "task": "Login",
                        "match": (
                            f"{PUBLIC_URL.rstrip('/o')}/account/login/*"
                        ),
                        "commands": [
                            ["text", "id", "id_username", USERNAME],
                            ["text", "id", "id_password", PASSWORD],
                            ["click", "css", "button[type=submit]"],
                        ],
                    }
                ],
            }
        ],
    }


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
    timeout_s: int = 300,
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


def run_plan(
    plan_name: str,
    *,
    module_variant: dict[str, str] | None = None,
    plan_variant: dict[str, str] | None = None,
    strict_warnings: bool = False,
) -> int:
    """
    Run every module in a plan and return a process exit code.

    ``plan_variant`` (subset, often empty) is passed at plan creation;
    ``module_variant`` (full set required by each module) is passed at
    module creation. The two-level split matches the suite's API:
    plans pre-bake some variants and reject user-supplied duplicates.
    Returns 0 if every module passed (and warnings are tolerated
    unless ``strict_warnings``); 1 otherwise.
    """
    session = requests.Session()
    plan = create_plan(session, plan_name=plan_name, plan_variant=plan_variant)
    plan_id = plan.get("id") or plan["_id"]
    modules = plan.get("modules", [])
    logger.info("plan id=%s contains %d modules", plan_id, len(modules))

    module_variant = module_variant or {}

    results: list[ModuleResult] = []
    for entry in modules:
        # Plan modules look like {"testModule": "oidcc-server", ...}
        module_name = entry.get("testModule") or entry.get("name", "?")
        # Each module needs to be kicked off individually with the
        # plan_id query param so the suite associates it with the
        # plan's config. The variant must be the FULL required set —
        # the suite does not auto-merge plan-baked + user-supplied at
        # module-creation time.
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
        module_id = create_resp.json()["id"]
        logger.info("started %s -> %s", module_name, module_id)
        # POST /api/runner creates AND starts the test in one step;
        # no separate "start" call needed (the older /api/runner/{id}
        # POST is for resume/interactive use, not initial kickoff).
        result = poll_module(session, module_id=module_id)
        results.append(
            ModuleResult(
                name=module_name,
                test_id=module_id,
                result=result,
            )
        )
        logger.info("  %s -> %s", module_name, result)

    return _emit_summary(results, strict_warnings=strict_warnings)


def _emit_summary(
    results: list[ModuleResult], *, strict_warnings: bool
) -> int:
    """Print a one-line-per-module summary and return an exit code."""
    passed = [r for r in results if r.result in PASS_RESULTS]
    warned = [r for r in results if r.result in WARN_RESULTS]
    failed = [
        r for r in results if r.result in FAIL_RESULTS or r.result == "TIMEOUT"
    ]

    sys.stdout.write("\n=== Conformance summary ===\n")
    for r in results:
        sys.stdout.write(f"{r.result:<8} {r.name}  ({r.test_id})\n")
    sys.stdout.write(
        f"\npassed={len(passed)} warned={len(warned)} "
        f"failed={len(failed)} total={len(results)}\n"
    )

    if failed:
        return 1
    if warned and strict_warnings:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
    plan_variant = json.loads(args.plan_variant) if args.plan_variant else None
    return run_plan(
        args.plan,
        module_variant=module_variant,
        plan_variant=plan_variant,
        strict_warnings=args.strict_warnings,
    )


if __name__ == "__main__":
    raise SystemExit(main())
