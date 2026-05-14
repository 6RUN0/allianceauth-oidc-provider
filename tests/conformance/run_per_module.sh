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
# ``.artifacts/`` is the project-wide convention for ephemeral
# run-output (gitignored, dockerignored). Keeping source-of-truth
# (``tests/conformance/*.py``, expected_failures.json, README)
# separate from generated zips/JSON makes ``ls tests/conformance/``
# tractable as the file count grows.
RESULTS_DIR=".artifacts/conformance/results"
COMPOSE_FILE="tests/conformance/docker-compose.yml"
EXPECTED_FAILURES="tests/conformance/expected_failures.json"
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

# Auto-inject the baseline expected-failures file so default
# invocation produces a green CI run (XFAIL on known issues, XPASS
# alarm if anything was fixed upstream). Operator can override by
# passing their own ``--expected-failures`` after ``--``.
expected_failures_seen=0
for arg in "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}"; do
    [[ "$arg" == "--expected-failures" ]] && expected_failures_seen=1
done
if [[ -f "$EXPECTED_FAILURES" && "$expected_failures_seen" -eq 0 ]]; then
    RUNNER_ARGS+=("--expected-failures" "$EXPECTED_FAILURES")
fi

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
    # ``${RUNNER_ARGS[@]+...}`` guards against ``set -u`` tripping
    # on an empty array.
    uv run python tests/conformance/run_plan.py \
        --plan "$PLAN" \
        --include "$module" \
        --summary-json "$RESULTS_DIR/$module.json" \
        "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}" || true
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null
done

echo
echo "==> [aggregate] combining ${total} per-module summaries"
aggregate_args=("$RESULTS_DIR")
if [[ -f "$EXPECTED_FAILURES" ]]; then
    aggregate_args+=("--expected-failures" "$EXPECTED_FAILURES")
fi
uv run python tests/conformance/aggregate_summaries.py \
    "${aggregate_args[@]}"
