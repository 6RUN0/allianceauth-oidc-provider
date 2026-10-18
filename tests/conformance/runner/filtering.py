"""
Module-list filtering primitives.

Plans like ``oidcc-basic-certification-test-plan`` ship ~35 modules;
the operator usually wants to either drop a known-broken family
(``--exclude oidcc-userinfo-*``) or lock to a known-good subset
(``--include oidcc-server oidcc-id-token-*``). The runner-side
filter and the expected-failures JSON loader both live here because
they share the ``fnmatch``-glob vocabulary.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .config import NON_FAILURE_RESULTS, module_name

if TYPE_CHECKING:
    import pathlib


def _matches_any(name: str, patterns: set[str]) -> bool:
    """
    Return True if ``name`` matches any glob pattern in ``patterns``.

    Patterns without glob metacharacters degrade to exact equality
    (``fnmatch.fnmatchcase("oidcc-server", "oidcc-server")``), so
    pre-glob callers keep working unchanged.
    """
    return any(fnmatch.fnmatchcase(name, pat) for pat in patterns)


def filter_modules(
    modules: list[dict[str, Any]],
    *,
    include: set[str] | None = None,
    exclude: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """
    Apply allow/deny filters to the plan's module list.

    ``include`` is a hard allow-set — only listed names (or globs)
    execute. ``exclude`` removes named modules. Both support
    ``fnmatch`` glob patterns (``oidcc-userinfo-*``,
    ``oidcc-id-token-*``); a pattern without glob metacharacters
    degrades to exact equality.

    Returns ``(selected, skipped, missing)`` where ``selected`` is the
    subset of plan entries to run, ``skipped`` lists names that were
    filtered out (for the summary), and ``missing`` lists ``include``
    entries that did not match any plan module. ``run_plan`` refuses
    to run when ``missing`` is non-empty so a typo (or stale glob) in
    ``--include`` cannot silently shrink the run.
    """
    plan_names = {module_name(entry) for entry in modules}
    selected: list[dict[str, Any]] = []
    skipped: list[str] = []
    for entry in modules:
        name = module_name(entry)
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


@dataclass(frozen=True)
class ExpectedFailure:
    """
    One acknowledged module outcome from the expected-failures file.

    ``result`` is the exact suite result the entry acknowledges; any
    other non-passing result of the module is a real failure.
    """

    result: str
    reason: str


def load_expected_failures(
    path: pathlib.Path,
) -> dict[str, ExpectedFailure]:
    """
    Parse an expected-failures JSON file: name -> pinned result.

    A listed module that finishes with exactly the pinned result is
    reported as XFAIL and does not influence the exit code; any other
    non-passing result stays a real failure, so an acknowledged
    SKIPPED cannot mask a later FAILED. A listed module that does not
    fail triggers an UNEXPECTED-PASS alarm so an upstream fix does not
    go unnoticed (the file is then stale and needs editing).

    Format::

        {
          "oidcc-scope-address": {
            "result": "SKIPPED",
            "reason": "address scope not advertised in discovery"
          }
        }

    A plain-string value (the schema without a pinned result) is
    rejected: it would acknowledge every failure mode of the module.
    Raises ``TypeError`` on a malformed file and ``ValueError`` when
    an entry pins a non-failure result (it could never be an XFAIL);
    ``cli.main`` reports either as a usage error.
    """
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise TypeError(
            f"{path}: expected JSON object "
            f"{{module: {{result, reason}}}}, got {type(data).__name__}"
        )
    ledger: dict[str, ExpectedFailure] = {}
    for name, entry in data.items():
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("result"), str)
            and entry["result"]
            and isinstance(entry.get("reason"), str)
        ):
            raise TypeError(
                f"{path}: entry {name!r} must be an object with "
                f'string "result" and "reason", got {entry!r}'
            )
        if entry["result"] in NON_FAILURE_RESULTS:
            raise ValueError(
                f"{path}: entry {name!r} pins non-failure result "
                f"{entry['result']!r}; only a failing result can be "
                "acknowledged"
            )
        ledger[str(name)] = ExpectedFailure(
            result=entry["result"], reason=entry["reason"]
        )
    return ledger
