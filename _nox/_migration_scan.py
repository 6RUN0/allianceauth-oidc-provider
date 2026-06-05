"""
Pure AST scan for blocking raw-DDL in Django migrations (MySQL/MariaDB).

Backs the ``migrations_concurrency_check`` nox session in
``_nox/migrations.py`` but imports neither nox nor Django, so its
classification logic runs directly from ``tests/unit`` with no runtime
to boot (mirrors ``_nox/_testing.py``).

Scope — why ``RunSQL`` only:
    On MySQL/MariaDB InnoDB an ORM ``AddIndex`` already runs online
    (``ALGORITHM=INPLACE, LOCK=NONE``), and the genuinely blocking ORM
    operations — a column type change, ``NULL`` -> ``NOT NULL`` — are
    already flagged by ``django-migration-linter`` in the
    ``migrations_check`` session. Re-flagging them here would duplicate
    that gate. The one blind spot the linter cannot reason about is raw
    SQL: a ``migrations.RunSQL`` that issues ``ALTER TABLE`` / ``CREATE
    INDEX`` without an online-DDL clause takes a metadata lock that
    stalls every writer for the table rebuild. This scanner owns exactly
    that niche, so the two gates stay disjoint.

    This is the MySQL re-statement of the Postgres "index creation must
    be ``CONCURRENT``" rule: the operation class differs (InnoDB indexes
    are already online; the risk moved to table-rebuild ``ALTER``), but
    the shape — demand a non-blocking DDL flavour or an explicit, reasoned
    opt-out — is the same.

A ``RunSQL`` operation passes when any of:
    * its SQL carries an online-DDL clause — ``ALGORITHM=INSTANT`` (never
      locks) or ``ALGORITHM=INPLACE`` together with ``LOCK=NONE`` /
      ``LOCK=SHARED``;
    * its SQL performs no blocking DDL at all (a pure DML backfill, or a
      whole-table ``CREATE TABLE`` that has no live rows to lock);
    * it carries the opt-out marker
      ``# allianceauth-oidc: blocking-op-ok - <reason>`` acknowledging a
      reviewed exception (the reason is mandatory).

SQL the scanner cannot read as a literal (built from a name, call, or
f-string) is treated as un-verifiable and must carry the marker.
"""

from __future__ import annotations

import ast
import enum
import re
from dataclasses import dataclass

# Raw-DDL verbs that take a blocking metadata lock or rebuild the table
# on MySQL/MariaDB InnoDB when issued without an online-DDL clause.
# ``CREATE TABLE`` / ``DROP TABLE`` are deliberately absent: a new table
# has no live rows to lock and a drop is an instant metadata change.
_BLOCKING_DDL = re.compile(
    r"\b(?:"
    r"ALTER\s+TABLE"
    r"|CREATE\s+(?:UNIQUE\s+)?INDEX"
    r"|DROP\s+INDEX"
    r"|RENAME\s+TABLE"
    r"|ADD\s+(?:FULLTEXT|SPATIAL)"
    r")\b",
    re.IGNORECASE,
)

# ``ALGORITHM=INSTANT`` never takes a write lock; ``ALGORITHM=INPLACE``
# is online only when paired with a non-exclusive ``LOCK``.
_ALGORITHM_INSTANT = re.compile(r"ALGORITHM\s*=\s*INSTANT", re.IGNORECASE)
_ALGORITHM_INPLACE = re.compile(r"ALGORITHM\s*=\s*INPLACE", re.IGNORECASE)
_LOCK_NON_BLOCKING = re.compile(r"LOCK\s*=\s*(?:NONE|SHARED)", re.IGNORECASE)

# Opt-out marker. The reason after the dash is mandatory: a bare marker
# is itself a finding, so an exception can never be waved through without
# a recorded justification. The dash class accepts hyphen-minus (-) plus
# the en-dash (U+2013) and em-dash (U+2014), written as escapes so the
# source stays pure ASCII while a typographically dashed comment matches.
_OPT_OUT_WITH_REASON = re.compile(
    r"#\s*allianceauth-oidc:\s*blocking-op-ok\s*[-\u2013\u2014]\s*\S"
)
_OPT_OUT_BARE = re.compile(r"#\s*allianceauth-oidc:\s*blocking-op-ok\b")

_MSG_BLOCKING = (
    "RunSQL issues blocking DDL without an online-DDL clause "
    "(ALGORITHM=INPLACE, LOCK=NONE or ALGORITHM=INSTANT) and carries no "
    "opt-out marker"
)
_MSG_DYNAMIC = (
    "RunSQL builds its SQL dynamically, so online DDL cannot be verified "
    "statically — add the online clause or an opt-out marker"
)
_MSG_BARE_MARKER = (
    "opt-out marker is missing its mandatory reason "
    "(# allianceauth-oidc: blocking-op-ok - <reason>)"
)

# Positional slots of ``RunSQL(sql, reverse_sql, ...)``; the trailing
# ``state_operations`` / ``hints`` slots carry no SQL and are ignored.
_SQL_ARG = 0
_REVERSE_SQL_ARG = 1


class _Marker(enum.Enum):
    """State of the opt-out marker within an operation's line span."""

    NONE = enum.auto()
    BARE = enum.auto()
    WITH_REASON = enum.auto()


@dataclass(frozen=True)
class ScanFinding:
    """A blocking-DDL violation located in a migration's source."""

    lineno: int
    reason: str


def _is_runsql(func: ast.expr) -> bool:
    """Return ``True`` if ``func`` names ``RunSQL`` (bare or dotted)."""
    if isinstance(func, ast.Attribute):
        return func.attr == "RunSQL"
    if isinstance(func, ast.Name):
        return func.id == "RunSQL"
    return False


def _arg_sql(node: ast.expr) -> tuple[list[str], bool]:
    """
    Classify one SQL-bearing argument node.

    Returns ``(sql_fragments, is_literal)``. A string constant yields its
    text; a list / tuple recurses (covering a statement list and a
    ``(sql, params)`` pair); an attribute such as ``RunSQL.noop`` and a
    non-string constant carry no SQL but stay literal; anything else — a
    name, call, or f-string — is dynamic and cannot be read statically.
    """
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return [node.value], True
        return [], True
    if isinstance(node, ast.Attribute):
        return [], True
    if isinstance(node, (ast.List, ast.Tuple)):
        fragments: list[str] = []
        is_literal = True
        for elt in node.elts:
            text, elt_literal = _arg_sql(elt)
            fragments.extend(text)
            is_literal = is_literal and elt_literal
        return fragments, is_literal
    return [], False


def _collect_sql(call: ast.Call) -> tuple[str, bool]:
    """
    Pull SQL text out of a ``RunSQL`` call's ``sql`` / ``reverse_sql``.

    Reads only the forward and reverse SQL arguments (positional or
    keyword) — never ``state_operations`` / ``hints`` — and reports
    ``is_literal=False`` when either is built dynamically, so the caller
    can demand an explicit opt-out marker.
    """
    by_keyword = {kw.arg: kw.value for kw in call.keywords if kw.arg}
    nodes: list[ast.expr] = []
    if "sql" in by_keyword:
        nodes.append(by_keyword["sql"])
    elif call.args:
        nodes.append(call.args[_SQL_ARG])
    if "reverse_sql" in by_keyword:
        nodes.append(by_keyword["reverse_sql"])
    elif len(call.args) > _REVERSE_SQL_ARG:
        nodes.append(call.args[_REVERSE_SQL_ARG])

    texts: list[str] = []
    is_literal = True
    for node in nodes:
        fragments, node_literal = _arg_sql(node)
        texts.extend(fragments)
        is_literal = is_literal and node_literal
    return " ".join(texts), is_literal


def _marker_state(lines: list[str], start: int, end: int) -> _Marker:
    """
    Classify the opt-out marker around an operation's source span.

    Scans from the line above ``start`` through ``end`` (1-based,
    inclusive) so a marker placed either on the operation or as a comment
    immediately above it is honoured.
    """
    first = max(start - 1, 1)
    window = lines[first - 1 : end]
    has_bare = False
    for line in window:
        if _OPT_OUT_WITH_REASON.search(line):
            return _Marker.WITH_REASON
        if _OPT_OUT_BARE.search(line):
            has_bare = True
    return _Marker.BARE if has_bare else _Marker.NONE


def _is_online(sql: str) -> bool:
    """Return ``True`` if ``sql`` proves it will not block writers."""
    if _ALGORITHM_INSTANT.search(sql):
        return True
    return bool(
        _ALGORITHM_INPLACE.search(sql) and _LOCK_NON_BLOCKING.search(sql)
    )


def find_blocking_runsql(source: str) -> list[ScanFinding]:
    """
    Return blocking-DDL findings for one migration module's source.

    A pure function of the source text: parses it, inspects every
    ``RunSQL`` operation, and yields a :class:`ScanFinding` per violation
    ordered by line. An empty list means the migration is clear.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    findings: list[ScanFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_runsql(node.func):
            continue
        end = node.end_lineno or node.lineno
        marker = _marker_state(lines, node.lineno, end)
        if marker is _Marker.WITH_REASON:
            continue
        sql, is_literal = _collect_sql(node)
        if is_literal and not _BLOCKING_DDL.search(sql):
            continue
        if is_literal and _is_online(sql):
            continue
        if marker is _Marker.BARE:
            reason = _MSG_BARE_MARKER
        elif is_literal:
            reason = _MSG_BLOCKING
        else:
            reason = _MSG_DYNAMIC
        findings.append(ScanFinding(node.lineno, reason))
    findings.sort(key=lambda finding: finding.lineno)
    return findings
