"""
Golden parity tests for the Django-test argv builder.

Pin the exact token sequence :func:`build_django_test_argv` emits for
each provisioning mode (in-venv, AA-group off-lock, pin off-lock) so a
future refactor cannot silently reorder ``uv`` flags or drop the
AA-selector. The argv order is load-bearing: ``uv`` parses its own
flags before ``python``, Django parses positional labels only at the
very end, and the ``--group`` / ``--with`` selectors must precede
``--isolated``.

ORM-free unit tier: pure imports from ``_nox._testing`` — no Django
models, no nox runtime. The module is importable in the lightweight
off-lock matrix venvs (the canary sweeps ``tests/unit/``).
"""

from __future__ import annotations

import unittest

from _nox._testing import (
    MARIADB_SMOKE_PYTHON,
    TEST_ARGS_BASE,
    TestPlan,
    build_canary_argv,
    build_django_test_argv,
    resolve_test_labels,
)


def _contains_subsequence(haystack: list[str], needle: list[str]) -> bool:
    """Return ``True`` when ``needle`` appears contiguously in order."""
    if not needle:
        return True
    span = len(needle)
    for start in range(len(haystack) - span + 1):
        if haystack[start : start + span] == needle:
            return True
    return False


class BuildDjangoTestArgvTests(unittest.TestCase):
    """Token-level parity for every ``build_django_test_argv`` mode."""

    def test_in_venv_has_no_uv_prefix(self) -> None:
        argv = build_django_test_argv(TestPlan(labels=()))
        self.assertEqual(
            argv[:5], ["python", "-m", "django", "test", TEST_ARGS_BASE[0]]
        )
        self.assertNotIn("uv", argv)
        self.assertIn("--parallel=auto", argv)
        self.assertEqual(argv[-1], "tests")

    def test_aa5_activates_group_before_isolated(self) -> None:
        argv = build_django_test_argv(
            TestPlan(python="3.12", aa_group="aa5", parallel="1")
        )
        self.assertEqual(argv[:4], ["uv", "run", "--python", "3.12"])
        self.assertTrue(
            _contains_subsequence(
                argv,
                ["--no-default-groups", "--group", "aa5", "--isolated"],
            )
        )
        self.assertIn("--parallel=1", argv)
        self.assertNotIn("--parallel=auto", argv)

    def test_aa4_selects_aa4_group_not_aa5(self) -> None:
        argv = build_django_test_argv(
            TestPlan(python="3.10", aa_group="aa4", parallel="1")
        )
        self.assertTrue(
            _contains_subsequence(argv, ["--group", "aa4", "--isolated"])
        )
        self.assertNotIn("aa5", argv)

    def test_compat_injects_pin_with_no_group(self) -> None:
        argv = build_django_test_argv(
            TestPlan(python="3.13", pin="allianceauth==5.0.1", parallel="1")
        )
        self.assertTrue(
            _contains_subsequence(
                argv,
                ["--no-default-groups", "--with", "allianceauth==5.0.1"],
            )
        )
        self.assertNotIn("--group", argv)
        self.assertNotIn("aa5", argv)
        self.assertNotIn("aa4", argv)

    def test_extra_deps_threaded_as_with_before_isolated(self) -> None:
        argv = build_django_test_argv(
            TestPlan(
                python="3.13",
                aa_group="aa5",
                extra_deps=("fakeredis>=2.33", "jwcrypto"),
                parallel="1",
            )
        )
        # ``--group aa5`` precedes the ``--with`` extras, which precede
        # the terminating ``--isolated``; uv must see all of these
        # before the ``python`` it execs.
        self.assertTrue(
            _contains_subsequence(
                argv,
                [
                    "--group",
                    "aa5",
                    "--with",
                    "fakeredis>=2.33",
                    "--with",
                    "jwcrypto",
                    "--isolated",
                    "python",
                ],
            )
        )

    def test_canary_shares_prefix_targets_canary_script(self) -> None:
        plan = TestPlan(python="3.12", aa_group="aa4", parallel="1")
        canary = build_canary_argv(plan)
        run = build_django_test_argv(plan)
        prefix_len = canary.index("python")
        # Both commands share the identical uv prefix so the canary and
        # the suite resolve to the same cached off-lock environment.
        self.assertEqual(canary[:prefix_len], run[:prefix_len])
        self.assertEqual(canary[-1], "_nox/_canary_imports.py")

    def test_axes_table(self) -> None:
        # One golden row per mode: (plan, required subsequences,
        # forbidden tokens). Each row asserts the builder kept the
        # load-bearing order and the right selector.
        cases: list[tuple[str, TestPlan, list[list[str]], list[str]]] = [
            (
                "in-venv tests",
                TestPlan(labels=()),
                [["python", "-m", "django", "test"], ["--parallel=auto"]],
                ["uv", "--isolated"],
            ),
            (
                "aa5 matrix",
                TestPlan(python="3.13", aa_group="aa5", parallel="1"),
                [["uv", "run", "--python", "3.13"], ["--group", "aa5"]],
                ["aa4", "--with"],
            ),
            (
                "aa4 matrix",
                TestPlan(python="3.12", aa_group="aa4", parallel="1"),
                [["--group", "aa4", "--isolated"]],
                ["aa5"],
            ),
            (
                "compat pin",
                TestPlan(python="3.13", pin="allianceauth==5.0.1"),
                [["--with", "allianceauth==5.0.1"]],
                ["--group", "aa5", "aa4"],
            ),
        ]
        for name, plan, required, forbidden in cases:
            with self.subTest(case=name):
                argv = build_django_test_argv(plan)
                for needle in required:
                    self.assertTrue(
                        _contains_subsequence(argv, needle),
                        f"{needle!r} missing from {argv!r}",
                    )
                for token in forbidden:
                    self.assertNotIn(token, argv)

    def test_mariadb_smoke_python_is_newest(self) -> None:
        # The DB-backed smoke matrix pins one interpreter; it must be a
        # real, supported version string the builder can feed to uv.
        plan = TestPlan(python=MARIADB_SMOKE_PYTHON, aa_group="aa5")
        argv = build_django_test_argv(plan)
        self.assertEqual(argv[3], MARIADB_SMOKE_PYTHON)


class ResolveTestLabelsTests(unittest.TestCase):
    """
    Pin the current label-resolution behaviour as-is.

    Documents existing behaviour — including the quirk that a bare
    ``["--parallel", "1"]`` (no positional label) is forwarded verbatim
    WITHOUT a default ``tests`` label, because the ``"1"`` token does
    not start with ``-`` and reads as a label.
    """

    def test_label_resolution_table(self) -> None:
        cases: list[tuple[str, tuple[str, ...], list[str]]] = [
            ("empty posargs defaults to tests", (), ["tests"]),
            (
                "flag-only forwards under default tests label",
                ("--keepdb",),
                ["tests", "--keepdb"],
            ),
            (
                "explicit label passes through verbatim",
                ("tests.test_token",),
                ["tests.test_token"],
            ),
            (
                "parallel value reads as a label (documented quirk)",
                ("--parallel", "1"),
                ["--parallel", "1"],
            ),
        ]
        for name, posargs, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(resolve_test_labels(posargs), expected)


if __name__ == "__main__":
    unittest.main()
