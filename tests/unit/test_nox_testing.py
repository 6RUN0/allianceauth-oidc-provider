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

import pathlib
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 — tomllib is 3.11+
    tomllib = None  # type: ignore[assignment]

from _nox._canary_imports import django_version_mismatch
from _nox._testing import (
    MARIADB_SMOKE_PYTHON,
    TEST_ARGS_BASE,
    TestPlan,
    build_canary_argv,
    build_django_test_argv,
    resolve_test_labels,
)
from _nox.shared import AA_GROUP_DJANGO_MAJOR, TEST_RUNTIME_GROUP


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


class ExtraGroupsTests(unittest.TestCase):
    """
    Off-lock runtime deps must resolve as a dependency *group*.

    Threading them as ``--with`` overlays is the bug these tests pin:
    a ``uv run --with`` overlay is resolved outside the project's
    constraints, so ``--with django-prometheus`` pulled an
    unconstrained Django 5.2 into the overlay, which shadowed the
    ``aa4`` group's ``django<5`` base venv on ``sys.path``. A group
    joins the single locked resolution instead, so the AA selector's
    Django pin binds every runtime dep.
    """

    def test_extra_groups_follow_aa_selector_before_isolated(self) -> None:
        argv = build_django_test_argv(
            TestPlan(
                python="3.12",
                aa_group="aa4",
                extra_groups=(TEST_RUNTIME_GROUP,),
                extra_deps=("mysqlclient>=2.2",),
                parallel="1",
            )
        )
        self.assertTrue(
            _contains_subsequence(
                argv,
                [
                    "--group",
                    "aa4",
                    "--group",
                    TEST_RUNTIME_GROUP,
                    "--with",
                    "mysqlclient>=2.2",
                    "--isolated",
                ],
            ),
            argv,
        )

    def test_extra_groups_available_in_pin_mode(self) -> None:
        argv = build_django_test_argv(
            TestPlan(
                python="3.13",
                pin="allianceauth==5.0.1",
                extra_groups=(TEST_RUNTIME_GROUP,),
            )
        )
        self.assertTrue(
            _contains_subsequence(
                argv,
                [
                    "--with",
                    "allianceauth==5.0.1",
                    "--group",
                    TEST_RUNTIME_GROUP,
                    "--isolated",
                ],
            ),
            argv,
        )

    @unittest.skipIf(tomllib is None, "tomllib requires Python 3.11+")
    def test_pyproject_declares_test_runtime_group(self) -> None:
        # Drift gate: the group the sessions select must exist in
        # pyproject and carry every third-party package the suite
        # imports directly (see the canary sweep). A dep dropped from
        # the group resurfaces here before it breaks an off-lock CI
        # cell.
        pyproject = (
            pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"
        )
        with pyproject.open("rb") as fh:
            groups = tomllib.load(fh)["dependency-groups"]
        self.assertIn(TEST_RUNTIME_GROUP, groups)
        names = {
            requirement.split(">")[0].split("=")[0].split("[")[0].strip()
            for requirement in groups[TEST_RUNTIME_GROUP]
        }
        self.assertLessEqual(
            {
                "fakeredis",
                "parameterized",
                "jwcrypto",
                "requests",
                "django-prometheus",
                "hypothesis",
            },
            names,
        )

    @unittest.skipIf(tomllib is None, "tomllib requires Python 3.11+")
    def test_django_major_map_matches_pyproject_groups(self) -> None:
        # The canary's Django-major expectation is keyed off the AA
        # group; this pins the map against the actual ``django``
        # specifiers in pyproject so neither can drift alone.
        pyproject = (
            pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"
        )
        with pyproject.open("rb") as fh:
            groups = tomllib.load(fh)["dependency-groups"]
        self.assertEqual({"aa4": "4", "aa5": "5"}, AA_GROUP_DJANGO_MAJOR)
        self.assertIn("django<5", groups["aa4"])
        self.assertIn("django>=5.2,<6", groups["aa5"])


class DjangoVersionGuardTests(unittest.TestCase):
    """
    The canary refuses to bless a venv whose Django major is wrong.

    Regression guard for the ``--with`` overlay shadowing bug: had the
    canary checked ``django.get_version()`` against the cell's
    expectation, the aa4 matrix silently running Django 5.2 would have
    failed on the first run instead of surfacing only on the MariaDB
    cell via an AA check crash.
    """

    def test_mismatch_reports_both_versions(self) -> None:
        message = django_version_mismatch("4", "5.2.14")
        self.assertIsNotNone(message)
        self.assertIn("5.2.14", message)
        self.assertIn("4", message)

    def test_matching_major_passes(self) -> None:
        self.assertIsNone(django_version_mismatch("4", "4.2.30"))

    def test_no_expectation_passes(self) -> None:
        # ``tests_compat`` (arbitrary AA_PIN) has no fixed Django
        # major; the guard must stay silent when no expectation is
        # threaded through the environment.
        self.assertIsNone(django_version_mismatch(None, "5.2.14"))
        self.assertIsNone(django_version_mismatch("", "5.2.14"))


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
