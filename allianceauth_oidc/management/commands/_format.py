"""
Shared output helpers for OIDC management commands.

Each command renders a list of dict rows; the operator picks the format
via ``--format=table|json|csv``. Centralised here so a future format
addition (e.g. ``--format=yaml``) lands in one place rather than four.
"""

from __future__ import annotations

import csv
import io
import json
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# Public-by-convention; commands import these names.
__all__ = ["FORMAT_CHOICES", "OutputFormat", "render_rows"]


class OutputFormat(str, Enum):
    """
    Allowed values for ``--format``.

    Mixin with ``str`` (instead of stdlib ``StrEnum``, 3.11+ only) keeps
    the floor at Python 3.10 while behaving identically for argparse,
    JSON serialisation, and ``f"{fmt}"``-style interpolation.
    """

    TABLE = "table"
    JSON = "json"
    CSV = "csv"


# Tuple of raw values for ``argparse``'s ``choices=`` parameter, which
# requires hashable comparable items (a list of enum members works on
# 3.11+ but not on 3.10's argparse). Keeps the call sites
# ``parser.add_argument(..., choices=FORMAT_CHOICES)`` unchanged.
FORMAT_CHOICES: tuple[str, ...] = tuple(f.value for f in OutputFormat)


def render_rows(
    rows: Iterable[dict[str, Any]],
    columns: Sequence[str],
    fmt: OutputFormat | str,
) -> str:
    """
    Render ``rows`` in the requested format.

    The ``columns`` order controls both the column order in table/csv
    output and the field set for JSON output (extra keys on row dicts
    are dropped). An empty rows iterable yields a format-appropriate
    empty document.

    ``fmt`` accepts both the ``OutputFormat`` enum and its raw string
    value so legacy callers and ``argparse``-resolved option values both
    work.
    """
    materialised = list(rows)
    fmt_enum = OutputFormat(fmt) if not isinstance(fmt, OutputFormat) else fmt

    if fmt_enum is OutputFormat.JSON:
        return json.dumps(
            [
                {c: _coerce(row.get(c)) for c in columns}
                for row in materialised
            ],
            indent=2,
            sort_keys=False,
        )

    if fmt_enum is OutputFormat.CSV:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(columns), extrasaction="ignore"
        )
        writer.writeheader()
        for row in materialised:
            writer.writerow({c: _coerce(row.get(c)) for c in columns})
        return buf.getvalue()

    # default: aligned table
    if not materialised:
        return "(no rows)"
    widths = {
        c: max(
            len(c),
            max(
                (len(str(_coerce(r.get(c, "")))) for r in materialised),
                default=0,
            ),
        )
        for c in columns
    }
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    sep = "  ".join("-" * widths[c] for c in columns)
    lines = [header, sep]
    for row in materialised:
        lines.append(
            "  ".join(
                str(_coerce(row.get(c, ""))).ljust(widths[c]) for c in columns
            )
        )
    return "\n".join(lines)


def _coerce(value: Any) -> Any:
    """Coerce DB / model values to JSON/CSV-friendly primitives."""
    if value is None:
        return ""
    return value
