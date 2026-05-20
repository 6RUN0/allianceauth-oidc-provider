#!/usr/bin/env bash
# Test-suite hygiene gate.
#
# Encodes conventions surfaced by the 4-agent test review and closed by
# the test-suite refactor batch (2cc1a8e / 953be80 / cbf27e0 / f69cc53 /
# dce24b2). Each rule below is enforced against every file passed on the
# command line (pre-commit passes only changed files, so the gate is fast
# in normal use). Exit code is non-zero if any rule matched at all.
#
# Add a new rule by appending a ``check`` block; each block prints its
# own remediation hint so the failure message points the contributor at
# the helper they should be using.
set -eu

failed=0

# Rule 1 — forbid raw ``json.loads`` on HTTP response bodies. Use
# ``OIDCTestCase.json_body(resp, expected_status=None)`` so the decode
# and status assertion live in one place. The helper lives at
# ``tests/_oidc_testcase.py:json_body`` and is exposed on every test
# class that inherits ``OIDCTestCase``.
if matches=$(grep -H -nE "json\.loads\([a-zA-Z_][a-zA-Z0-9_]*\.content" "$@" 2>/dev/null); then
    echo "[json.loads on response body]"
    printf '%s\n' "$matches"
    echo ""
    echo "Use self.json_body(resp, expected_status=None)"
    echo "(see tests/_oidc_testcase.py:json_body)."
    echo ""
    failed=1
fi

exit "$failed"
