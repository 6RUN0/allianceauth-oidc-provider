"""
Static configuration for the conformance runner.

Splits two concerns:

- Environment-driven endpoints + credentials (``SUITE_URL``,
  ``PUBLIC_URL``, ``CLIENT_ID``, …). Defaults match
  ``docker-compose.yml`` + ``conformance_settings.py``; override via
  env when running against another stack.
- Suite protocol vocabulary (``DEFAULT_VARIANT``,
  ``PLAN_VARIANT_DEFAULTS``, ``PASS_RESULTS`` / ``WARN_RESULTS`` /
  ``FAIL_RESULTS``, ``ModuleResult``). These are tied to the
  conformance-suite REST API shape, not to our deployment.

Other modules import from here rather than restating the constants.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

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
# Failure classification used by the summary layer: ``FAIL_RESULTS``
# plus the runner-side ``"TIMEOUT"`` pseudo-code emitted by
# ``client.poll_module`` when a module never leaves the RUNNING state
# within the deadline. Hoisted out of ``summary._bucket_results`` so
# the value-set lives next to ``FAIL_RESULTS`` and is not rebuilt on
# every summary call.
TERMINAL_FAIL_RESULTS: frozenset[str] = FAIL_RESULTS | frozenset({"TIMEOUT"})


@dataclass
class ModuleResult:
    """Per-module outcome reported by the suite."""

    name: str
    test_id: str
    result: str  # PASSED / FAILED / WARNING / REVIEW / SKIPPED
    log_excerpt: list[dict[str, Any]] = field(default_factory=list)


def module_name(entry: dict[str, Any]) -> str:
    """
    Extract the module name from a plan-catalogue entry.

    Plans returned by ``POST /api/plan`` carry entries of the shape
    ``{"testModule": "oidcc-server", ...}``; older suite revisions
    used ``{"name": ...}`` in the same slot. The fallback to ``"?"``
    preserves the diagnostic value when the suite returns a record
    we cannot label — the literal flows verbatim into log lines /
    summary tables and is visibly wrong on inspection.
    """
    return entry.get("testModule") or entry.get("name") or "?"
