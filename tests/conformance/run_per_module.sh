#!/usr/bin/env bash
# Per-module conformance orchestrator with full stack restart.
#
# Why:
#   HtmlUnit 4.11.1 (bundled in conformance-suite release-v5.1.43)
#   becomes unable to complete second and subsequent browser-driven
#   flows in the same JVM — the JS engine's NPE in the async
#   XMLHttpRequest path poisons the suite-side state. Fresh JVM per
#   module side-steps that.
#
# Cost:
#   Each module pays ~30 seconds of compose up/down. For the full
#   basic-cert plan (~35 modules) the run is ~70-80 minutes versus
#   ~30-50 minutes in shared-stack mode. Use this only when you
#   need a clean PASS/FAIL split unobstructed by HtmlUnit noise —
#   day-to-day iteration should stick with ``nox -s conformance``.
#
# Usage:
#   tests/conformance/run_per_module.sh [--plan PLAN]
#                                       [--results-dir DIR]
#                                       [-- <runner args>]
#
#   Anything after ``--`` is forwarded verbatim to run_plan.py
#   (e.g. ``-- --exclude 'oidcc-userinfo-*'`` to skip a family).

set -euo pipefail

PLAN="oidcc-basic-certification-test-plan"
RESULTS_DIR="tests/conformance/results"
COMPOSE_FILE="tests/conformance/docker-compose.yml"
RUNNER_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan) PLAN="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --) shift; RUNNER_ARGS=("$@"); break ;;
        *)
            echo "unknown option: $1" >&2
            echo "usage: $0 [--plan PLAN] [--results-dir DIR] [-- <runner args>]" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$RESULTS_DIR"

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [discovery] bringing stack up to enumerate plan modules..."
docker compose -f "$COMPOSE_FILE" up -d --wait --build

# Capture the module list from the suite. ``--list-modules`` creates
# a plan instance just to read its module array, prints names line
# by line, exits 0. The plan instance lingers in MongoDB but the
# down -v that follows wipes it.
modules_file="$(mktemp)"
trap 'rm -f "$modules_file"; cleanup' EXIT
uv run python tests/conformance/run_plan.py \
    --plan "$PLAN" --list-modules >"$modules_file"
mapfile -t MODULES <"$modules_file"
echo "==> [discovery] found ${#MODULES[@]} modules"

docker compose -f "$COMPOSE_FILE" down -v >/dev/null

i=0
total=${#MODULES[@]}
for module in "${MODULES[@]}"; do
    i=$((i + 1))
    [[ -z "$module" ]] && continue
    echo
    echo "==> [$i/$total] $module"
    docker compose -f "$COMPOSE_FILE" up -d --wait
    # ``|| true`` so a single module's non-zero exit (FAILED) does
    # not break the loop; the JSON file captures the verdict anyway.
    uv run python tests/conformance/run_plan.py \
        --plan "$PLAN" \
        --include "$module" \
        --summary-json "$RESULTS_DIR/$module.json" \
        "${RUNNER_ARGS[@]}" || true
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null
done

echo
echo "==> [aggregate] combining ${total} per-module summaries"
uv run python tests/conformance/aggregate_summaries.py "$RESULTS_DIR"
