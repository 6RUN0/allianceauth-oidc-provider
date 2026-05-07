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
import fnmatch
import json
import logging
import os
import pathlib
import sys
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

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
# the issuer claim validates. ``https://`` because the conformance
# suite enforces TLS for OIDC discovery; the provider serves a
# self-signed cert backed by ``tls/ca.crt`` which the suite container
# imports at startup via ``USE_SYSTEM_CA_CERTS=1``.
PUBLIC_URL = os.environ.get(
    "CONFORMANCE_PUBLIC_URL",
    "https://provider:8443/o",
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

# Plan-level variant defaults for plans that REQUIRE specific keys at
# creation time (rather than pre-baking them). The suite's API
# rejects both "key is missing" and "key has been set by user but
# the plan pre-bakes it" with the same 400 status, so the default has
# to be the exact accepted subset for each plan. Probe a new plan via
# trial-and-error against ``/api/plan?planName=<x>&variant=<json>``
# until the suite stops complaining. Plans not listed here default to
# an empty plan-variant; pass ``--plan-variant`` to override.
PLAN_VARIANT_DEFAULTS: dict[str, dict[str, str]] = {
    "oidcc-basic-certification-test-plan": {
        "client_registration": "static_client",
        "server_metadata": "discovery",
    },
}

# Result codes the suite emits. See ConformanceTestResult.java.
# ``ERROR`` is a runner-side pseudo-code emitted when the suite
# refuses to start a module (typically variant mismatch returning a
# 500 from POST /api/runner) — bucketed with FAIL so the operator
# sees it in the denylist and the run exits non-zero.
PASS_RESULTS: frozenset[str] = frozenset({"PASSED", "REVIEW"})
WARN_RESULTS: frozenset[str] = frozenset({"WARNING"})
FAIL_RESULTS: frozenset[str] = frozenset({"FAILED", "SKIPPED", "ERROR"})


@dataclass
class ModuleResult:
    """Per-module outcome reported by the suite."""

    name: str
    test_id: str
    result: str  # PASSED / FAILED / WARNING / REVIEW / SKIPPED
    log_excerpt: list[dict[str, Any]] = field(default_factory=list)


def _host_root(public_url: str) -> str:
    """
    Strip the OIDC path prefix from ``public_url`` to recover the
    Django host root.

    AA's login and consent templates live on the host root (no
    ``/o/`` prefix); the suite's headless browser hits both during
    automation, so we need a clean base URL — not the
    ``rstrip('/o')`` character-set strip, which silently removes
    every trailing ``/`` and ``o`` and breaks on any host whose path
    happens to share those characters.
    """
    parsed = urlparse(public_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_plan_config() -> dict[str, Any]:
    """
    Build the JSON config the suite stores against a plan.

    Mirrors the shape suite plans expect: ``server.discoveryUrl`` plus
    a ``client`` block with our pre-registered credentials. Login
    credentials go under ``resource`` so the suite's browser driver
    can submit AA's standard Django login form.
    """
    host_root = _host_root(PUBLIC_URL)
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
        # ``browser`` drives the suite's headless HtmlUnit. The suite
        # selects a TOP-LEVEL entry by matching the ``goToUrl`` URL it
        # tells the browser to visit. Inside the entry, each TASK has
        # its own ``match`` field that fires against the browser's
        # CURRENT URL after navigation.
        #
        # Flow:
        # 1. Suite ``goToUrl(/o/authorize/...)`` — matches the entry
        #    below.
        # 2. AA middleware 302's an unauthenticated user to
        #    ``LOGIN_URL`` (= ``/admin/login/`` in conformance
        #    settings; AA's stock ``/account/login/`` is EVE-SSO-only
        #    with no fillable form).
        # 3. Login task fires against the admin-login URL — fills
        #    ``id_username`` / ``id_password`` and submits. Django
        #    admin's form uses exactly those IDs.
        # 4. On success, admin redirects to the ``next`` URL
        #    (``/o/authorize/...``).
        # 5. If the seeded app has ``skip_authorization=False``, DOT
        #    renders our consent template; the Authorize task clicks
        #    ``name=allow``. Apps seeded with
        #    ``skip_authorization=True`` (the default in
        #    ``seed.py``) skip the consent screen — DOT 302's
        #    directly to the RP callback. Both tasks are
        #    ``optional: true`` so a single configuration handles
        #    both flows.
        # 6. ``[type=submit]`` (CSS selector) matches both
        #    ``<input type="submit">`` (admin login) and
        #    ``<button type="submit">`` (other forms) — the
        #    previous ``button[type=submit]`` selector missed the
        #    admin form's input element.
        "browser": [
            {
                "match": f"{host_root}/o/authorize*",
                "tasks": [
                    {
                        "task": "Login",
                        "match": f"{host_root}/admin/login*",
                        "optional": True,
                        "commands": [
                            ["text", "id", "id_username", USERNAME],
                            ["text", "id", "id_password", PASSWORD],
                            ["click", "css", "[type=submit]"],
                        ],
                    },
                    {
                        "task": "Authorize",
                        "match": f"{host_root}/o/authorize*",
                        "optional": True,
                        "commands": [
                            ["click", "name", "allow"],
                        ],
                    },
                ],
            },
        ],
    }


def _matches_any(name: str, patterns: set[str]) -> bool:
    """
    Return True if ``name`` matches any glob pattern in ``patterns``.

    Patterns without glob metacharacters degrade to exact equality
    (``fnmatch.fnmatchcase("oidcc-server", "oidcc-server")``), so
    pre-glob callers keep working unchanged.
    """
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


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


def load_expected_failures(path: pathlib.Path) -> dict[str, str]:
    """
    Parse an expected-failures JSON file: name -> reason.

    Modules listed there are treated as known-acknowledged: a
    FAILED/TIMEOUT/ERROR does not influence the run's exit code, and
    a PASSED triggers an UNEXPECTED-PASS alarm so an upstream fix
    doesn't go unnoticed (the file is then stale and needs editing).

    Format::

        {
          "oidcc-userinfo-get":
              "HtmlUnit 4.11.1 NPE in async XHR (upstream issue)",
          "oidcc-prompt-login":
              "RFC 6749 prompt= parameter not yet implemented"
        }

    Mirrors upstream ``run-test-plan.py --expected-failures-file``.
    """
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected JSON object {{module: reason}}, "
            f"got {type(data).__name__}"
        )
    return {str(k): str(v) for k, v in data.items()}


def _filter_modules(
    modules: list[dict[str, Any]],
    *,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """
    Apply allow/deny filters to the plan's module list.

    Plans like ``oidcc-basic-certification-test-plan`` ship ~35
    modules; some hit upstream limitations (HtmlUnit 4.11.1 NPE) that
    poison the run with TIMEOUTs. ``include`` is a hard allow-set —
    only listed names (or globs) execute. ``exclude`` removes named
    modules. Both support ``fnmatch`` glob patterns (``oidcc-userinfo-*``,
    ``oidcc-id-token-*``); a pattern without glob metacharacters
    degrades to exact equality.

    Returns ``(selected, skipped, missing)`` where ``selected`` is the
    subset of plan entries to run, ``skipped`` lists names that were
    filtered out (for the summary), and ``missing`` lists ``include``
    entries that did not match any plan module. ``missing`` is
    surfaced as a warning so a typo (or stale glob) in ``--include``
    does not silently produce an empty run.
    """
    plan_names = {
        (entry.get("testModule") or entry.get("name", "?"))
        for entry in modules
    }
    selected: list[dict[str, Any]] = []
    skipped: list[str] = []
    for entry in modules:
        name = entry.get("testModule") or entry.get("name", "?")
        if include is not None and not _matches_any(name, include):
            skipped.append(name)
            continue
        if exclude and _matches_any(name, exclude):
            skipped.append(name)
            continue
        selected.append(entry)
    if include:
        missing = sorted(
            pat
            for pat in include
            if not any(fnmatch.fnmatchcase(n, pat) for n in plan_names)
        )
    else:
        missing = []
    return selected, skipped, missing


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


def _run_module(
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
) -> int:
    """
    Run every module in a plan and return a process exit code.

    ``plan_variant`` (subset, often empty) is passed at plan creation;
    ``module_variant`` (full set required by each module) is passed at
    module creation. The two-level split matches the suite's API:
    plans pre-bake some variants and reject user-supplied duplicates.
    ``include`` / ``exclude`` filter the plan's module list locally
    (see ``_filter_modules``) — useful for skipping modules that hit
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

    selected, skipped_filtered, missing = _filter_modules(
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
        result = _run_module(
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

    return _emit_summary(
        results,
        skipped_filtered=skipped_filtered,
        strict_warnings=strict_warnings,
        expected_failures=expected_failures or {},
    )


def _emit_summary(
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
    )


if __name__ == "__main__":
    raise SystemExit(main())
