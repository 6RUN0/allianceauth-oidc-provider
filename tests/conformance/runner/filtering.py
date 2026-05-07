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
from typing import TYPE_CHECKING, Any

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
        # Type assertion on the deserialised JSON shape — TypeError per
        # TRY004 ("if you check the type, raise TypeError"). The
        # caller (run_plan.py CLI bootstrap) prints the message
        # verbatim, so keep it descriptive.
        raise TypeError(
            f"{path}: expected JSON object {{module: reason}}, "
            f"got {type(data).__name__}"
        )
    return {str(k): str(v) for k, v in data.items()}
