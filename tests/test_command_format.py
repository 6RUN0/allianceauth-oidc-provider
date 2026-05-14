"""
Tests for ``manage.py oidc_*`` operator commands.

The commands are thin wrappers around the ORM; tests verify the
contract operators rely on:

* `--dry-run` on destructive commands does not write.
* `--format=json` produces parseable output.
* Idempotent behaviour (re-running a destructive command on a
  cleaned-up subject is a no-op).
"""

from __future__ import annotations

import json

from allianceauth_oidc.management.commands._format import render_rows

from ._oidc_testcase import OIDCTestCase


class TestRenderRowsHelper(OIDCTestCase):
    """Unit tests for the shared format helper — no DB required."""

    def test_table_format_aligns_columns(self) -> None:
        out = render_rows(
            [{"a": "x", "b": "yyyy"}, {"a": "longer", "b": "z"}],
            columns=("a", "b"),
            fmt="table",
        )
        self.assertIn("a", out)
        self.assertIn("longer", out)
        # Column header followed by separator line.
        self.assertIn("\n--", out)

    def test_json_format_is_parseable(self) -> None:
        out = render_rows(
            [{"a": 1, "b": None}],
            columns=("a", "b"),
            fmt="json",
        )
        parsed = json.loads(out)
        self.assertEqual([{"a": 1, "b": ""}], parsed)

    def test_csv_format_has_header_and_row(self) -> None:
        out = render_rows(
            [{"a": "x"}],
            columns=("a",),
            fmt="csv",
        )
        # CSV: header line + value line.
        lines = out.strip().splitlines()
        self.assertEqual(["a", "x"], lines)

    def test_empty_rows_yield_explicit_marker(self) -> None:
        self.assertEqual(
            "(no rows)",
            render_rows([], columns=("a",), fmt="table"),
        )

    def test_json_uses_two_space_indent(self) -> None:
        # ``json.dumps(..., indent=2, ...)`` pins exactly two spaces
        # of indentation per nested level. ``NumberReplacer`` flips
        # the literal to 1 / 3 (or 0 which yields a single-line
        # document — observable here as the absence of newlines).
        # Operator habit: parse pipelines tab-complete on a stable
        # indent so a flip silently breaks awk/grep filters.
        #
        # Output shape for one row: ``[\n  {\n    "a": 1\n  }\n]``
        # — top-level array gets 2 spaces, nested object key gets 4.
        out = render_rows([{"a": 1}], columns=("a",), fmt="json")
        # Top-level array element indented by exactly 2 spaces.
        self.assertIn("[\n  {", out)
        # Three-space indent (NumberReplacer 2 -> 3) would render
        # ``[\n   {``.
        self.assertNotIn("[\n   {", out)
        # Single-space indent (2 -> 1) would render ``[\n {``.
        self.assertNotIn("[\n {", out)

    def test_json_preserves_column_order(self) -> None:
        # ``sort_keys=False`` in ``json.dumps`` keeps the per-row
        # dict iteration order intact, so columns appear in the
        # caller-specified order regardless of alphabet. Flipping
        # ``False`` to ``True`` (``ReplaceFalseWithTrue``) would
        # sort keys alphabetically and silently reorder every
        # admin / CSV-tooling expectation.
        out = render_rows(
            [{"z": 1, "a": 2, "m": 3}],
            columns=("z", "a", "m"),  # NOT alphabetical
            fmt="json",
        )
        # Sub-string positions: ``"z"`` appears before ``"a"``,
        # which appears before ``"m"``. With sort_keys=True the
        # ``"a"`` key would land first.
        z_pos = out.index('"z"')
        a_pos = out.index('"a"')
        m_pos = out.index('"m"')
        self.assertLess(z_pos, a_pos)
        self.assertLess(a_pos, m_pos)

    def test_enum_dispatch_distinguishes_csv_from_json(self) -> None:
        # ``fmt_enum is OutputFormat.CSV`` carries an ``Is_LtE``
        # mutant. ``OutputFormat`` inherits from ``str`` so member
        # comparison falls back to string lex order:
        #   ``"csv" <= "json"`` is True (``c`` < ``j``).
        # Original branch (``is``): for CSV input, ``fmt_enum is
        # OutputFormat.JSON`` is False, then ``fmt_enum is
        # OutputFormat.CSV`` is True → CSV branch.
        # Mutated branch (``<=``): for CSV input, ``fmt_enum <=
        # OutputFormat.JSON`` is True → JSON branch fires first,
        # returning the JSON document instead of CSV.
        out = render_rows(
            [{"a": "x"}],
            columns=("a",),
            fmt="csv",
        )
        # CSV-specific shape: header line + value line, no
        # bracket/brace tokens.
        self.assertNotIn("[", out)
        self.assertNotIn("{", out)
        self.assertIn("a\r\n", out)  # csv.writer line terminator
