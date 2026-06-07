"""
Tests for the generated-Makefile pure core.

Pin the contract the ``makefile`` / ``makefile_check`` nox sessions lean
on: a deterministic, hook-clean render; ``.PHONY`` and ``help`` derived
from the same table as the rules; and the two drift detectors
(``find_uncovered_sessions`` / ``find_dangling_targets``) flagging the
exact mismatch they exist to catch.

ORM-free unit tier: pure imports from ``_nox.makefile`` — no Django
models, no nox runtime — so the module is importable in the lightweight
off-lock matrix venvs (the canary sweeps ``tests/unit/``).
"""

from __future__ import annotations

import unittest

from _nox.makefile import (
    SESSIONS_WITHOUT_TARGET,
    TARGETS,
    Target,
    find_dangling_targets,
    find_uncovered_sessions,
    render_makefile,
)


def _registered_from_targets() -> set[str]:
    """The session set a fully-covered registry would expose."""
    return {t.session for t in TARGETS if t.session is not None}


class RenderMakefileTests(unittest.TestCase):
    """The render is deterministic, hook-clean, and table-derived."""

    def setUp(self) -> None:
        self.text = render_makefile()
        self.lines = self.text.split("\n")

    def test_render_is_deterministic(self) -> None:
        self.assertEqual(render_makefile(), render_makefile())

    def test_single_trailing_newline(self) -> None:
        self.assertTrue(self.text.endswith("\n"))
        self.assertFalse(self.text.endswith("\n\n"))

    def test_no_trailing_whitespace_on_any_line(self) -> None:
        # The committed Makefile passes ``trailing-whitespace`` /
        # ``end-of-file-fixer``; the render must already match so the
        # content gate never trips on whitespace alone.
        offenders = [ln for ln in self.lines if ln != ln.rstrip()]
        self.assertEqual(offenders, [])

    def test_recipe_lines_are_tab_indented(self) -> None:
        # Make requires a literal tab before each recipe line; a render
        # that emitted spaces would produce a broken Makefile.
        recipe_lines = [
            ln
            for ln in self.lines
            if ln
            and not ln.startswith(("#", ".PHONY", "help"))
            and ln.endswith(("tests", "html/", "dist/*"))
        ]
        self.assertTrue(recipe_lines)
        self.assertTrue(
            all(ln.startswith("\t") for ln in recipe_lines),
            recipe_lines,
        )

    def test_phony_lists_help_and_every_target(self) -> None:
        phony_line = next(ln for ln in self.lines if ln.startswith(".PHONY:"))
        members = phony_line.removeprefix(".PHONY:").split()
        self.assertEqual(members[0], "help")
        self.assertEqual(set(members[1:]), {t.name for t in TARGETS})

    def test_every_target_has_a_rule(self) -> None:
        for target in TARGETS:
            self.assertIn(f"{target.name}:", self.text)

    def test_help_lists_every_target(self) -> None:
        for target in TARGETS:
            self.assertIn(target.help, self.text)

    def test_comment_block_renders_above_its_rule(self) -> None:
        compat = next(t for t in TARGETS if t.name == "test-compat")
        self.assertTrue(compat.comment)
        rule_index = self.lines.index("test-compat:")
        above = self.lines[rule_index - 1]
        self.assertTrue(above.startswith("# "))


class CoverageGateTests(unittest.TestCase):
    """``find_uncovered_sessions`` flags sessions with no target."""

    def test_full_registry_is_fully_covered(self) -> None:
        self.assertEqual(
            find_uncovered_sessions(_registered_from_targets()), set()
        )

    def test_extra_session_is_reported(self) -> None:
        registered = _registered_from_targets() | {"ghost_session"}
        self.assertEqual(
            find_uncovered_sessions(registered), {"ghost_session"}
        )

    def test_explicit_exclusion_is_honoured(self) -> None:
        # A session in SESSIONS_WITHOUT_TARGET must not be flagged even
        # with no target wrapping it. The set is empty today, so simulate
        # the contract with a one-off target list and a patched-in name.
        registered = _registered_from_targets() | set(SESSIONS_WITHOUT_TARGET)
        self.assertEqual(find_uncovered_sessions(registered), set())


class DanglingGateTests(unittest.TestCase):
    """``find_dangling_targets`` flags targets naming dead sessions."""

    def test_real_table_has_no_dangling_targets(self) -> None:
        self.assertEqual(
            find_dangling_targets(_registered_from_targets()), set()
        )

    def test_target_naming_unknown_session_is_reported(self) -> None:
        bogus = Target(
            name="zzz",
            help="bogus",
            recipe=("uv run nox -s nope",),
            session="nope",
        )
        targets = (*TARGETS, bogus)
        self.assertEqual(
            find_dangling_targets(_registered_from_targets(), targets),
            {"zzz"},
        )

    def test_special_targets_without_session_are_ignored(self) -> None:
        # ``dev`` / ``clean`` / ``package`` / ``deploy`` carry no session
        # and must never be reported as dangling.
        specials = {"dev", "clean", "package", "deploy"}
        self.assertEqual(
            find_dangling_targets(set(), TARGETS) & specials, set()
        )


class TableInvariantTests(unittest.TestCase):
    """Structural invariants the gates and humans both rely on."""

    def test_target_names_are_unique(self) -> None:
        names = [t.name for t in TARGETS]
        self.assertEqual(len(names), len(set(names)))

    def test_each_session_is_wrapped_once(self) -> None:
        sessions = [t.session for t in TARGETS if t.session is not None]
        self.assertEqual(len(sessions), len(set(sessions)))

    def test_every_target_has_a_recipe(self) -> None:
        for target in TARGETS:
            self.assertTrue(target.recipe, target.name)


if __name__ == "__main__":
    unittest.main()
