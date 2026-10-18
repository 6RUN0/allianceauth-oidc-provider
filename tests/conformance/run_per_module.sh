#!/usr/bin/env bash
# Per-module conformance orchestrator with full stack restart.
#
# Why:
#   HtmlUnit 4.11.1 (still bundled via the suite's Spring Boot BOM
#   as of release-v5.1.45) can fail to complete second and subsequent
#   browser-driven flows in the same JVM — the JS engine's NPE in the
#   async XMLHttpRequest path poisons the suite-side state. Fresh JVM
#   per module side-steps that. Since release-v5.1.44 the browser's
#   HTTP client also has a 60s timeout (work item 1827), so a stalled
#   provider connection no longer wedges a WebRunner thread forever.
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
#   (e.g. ``-- --exclude 'oidcc-userinfo-*'`` to skip a family), also
#   to the discovery call; ``--strict-warnings`` and the
#   ``--expected-failures`` ledger also reach the aggregator.
#   Run from the repository root.

set -euo pipefail

# Every path below is repository-relative; from another directory the
# baseline ledger check would be silently false.
repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
if [[ "$(pwd -P)" != "$repo_root" ]]; then
    echo "run from the repository root: cd $repo_root" >&2
    exit 2
fi

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
# passing their own ``--expected-failures`` after ``--``. The ledger
# and ``--strict-warnings`` actually given to run_plan.py are the ones
# the aggregator recomputes the verdict with.
ledger=""
strict_warnings=0
prev_arg=""
for arg in "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}"; do
    case "$arg" in
        --expected-failures=*) ledger="${arg#--expected-failures=}" ;;
        --strict-warnings) strict_warnings=1 ;;
    esac
    [[ "$prev_arg" == "--expected-failures" ]] && ledger="$arg"
    prev_arg="$arg"
done
if [[ -z "$ledger" && -f "$EXPECTED_FAILURES" ]]; then
    ledger="$EXPECTED_FAILURES"
    RUNNER_ARGS+=("--expected-failures" "$ledger")
fi

# Each run writes into its own fresh directory: a JSON left by an
# earlier run must never stand in for a module this run lost. ``mkdir``
# without ``-p`` refuses an existing directory.
mkdir -p "$RESULTS_DIR"
RUN_DIR="$RESULTS_DIR/run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$RUN_DIR"
echo "==> results: $RUN_DIR"
modules_file="$RUN_DIR/modules.txt"
exit_codes_file="$RUN_DIR/exit_codes.tsv"
: >"$exit_codes_file"

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> [discovery] bringing stack up to enumerate plan modules..."
docker compose -f "$COMPOSE_FILE" up -d --wait --build

# Capture the module list from the suite. ``--list-modules`` creates
# a plan instance just to read its module array, prints names line
# by line, exits 0. The plan instance lingers in MongoDB but the
# down -v that follows wipes it. The list doubles as the aggregator's
# expected-module set. The runner args go along so the plan variant
# matches the loop and a broken ledger fails here, not per module.
uv run python tests/conformance/run_plan.py \
    --plan "$PLAN" --list-modules \
    "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}" >"$modules_file"
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
    # ``|| rc=$?`` keeps the loop going past a failing module and
    # records the exit code: the aggregator treats anything but 0/1
    # as a harness crash. ``${RUNNER_ARGS[@]+...}`` guards against
    # ``set -u`` tripping on an empty array.
    rc=0
    uv run python tests/conformance/run_plan.py \
        --plan "$PLAN" \
        --include "$module" \
        --summary-json "$RUN_DIR/$module.json" \
        "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}" || rc=$?
    printf '%s\t%s\n' "$module" "$rc" >>"$exit_codes_file"
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null
done

echo
echo "==> [aggregate] combining ${total} per-module summaries"
aggregate_args=(
    "$RUN_DIR"
    --expected-modules "$modules_file"
    --plan-name "$PLAN"
    --exit-codes "$exit_codes_file"
)
if [[ -n "$ledger" ]]; then
    aggregate_args+=("--expected-failures" "$ledger")
fi
if [[ "$strict_warnings" -eq 1 ]]; then
    aggregate_args+=("--strict-warnings")
fi
uv run python tests/conformance/aggregate_summaries.py \
    "${aggregate_args[@]}"
