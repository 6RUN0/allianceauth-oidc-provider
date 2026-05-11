"""
Tests for the cosmic-ray PEP 604 annotation filter.

The filter lives in ``_nox/cr_filter_annotations.py`` and runs
between ``cosmic-ray init`` and ``cosmic-ray exec`` to drop
mutations that would never produce an observable runtime change —
specifically ``BinOp(BitOr())`` nodes inside type annotations under
``from __future__ import annotations``.

These tests cover the AST-scanning core, ``_annotation_binop_spots``.
The wider ``filter_session`` path operates on a live
``cosmic_ray.work_db.WorkDB`` and is exercised end-to-end by
``nox -s mutation`` (the only meaningful failure mode is mismatched
coordinates, which the scan tests pin down).

The filter file lives outside ``allianceauth_oidc/`` so we drop
``_nox/`` onto ``sys.path`` here rather than packaging it.
"""

from __future__ import annotations

import pathlib
import sys

from django.test import SimpleTestCase

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "_nox"))

from cr_filter_annotations import _annotation_binop_spots  # noqa: E402


class TestAnnotationBinOpSpots(SimpleTestCase):
    """
    ``_annotation_binop_spots`` must locate the ``|`` token itself.

    cosmic-ray records mutation positions operator-centric (column of
    the ``|``), not expression-centric (column of the BinOp's left
    operand). A column-off-by-N regression here silently drops to
    zero matches and the filter becomes a no-op — exactly the bug
    that surfaced during initial wiring.
    """

    def test_finds_pipe_in_function_return_annotation(self) -> None:
        src = "def f() -> int | None:\n    return None\n"
        spots = _annotation_binop_spots(src)
        # ``int`` occupies cols 11-13, space at 14, pipe at 15.
        self.assertEqual(spots, {(1, 15)})

    def test_finds_pipe_in_arg_annotation(self) -> None:
        src = "def f(x: int | None) -> None:\n    pass\n"
        spots = _annotation_binop_spots(src)
        # ``int`` occupies cols 9-11, space at 12, pipe at 13.
        self.assertEqual(spots, {(1, 13)})

    def test_finds_pipe_in_ann_assign(self) -> None:
        src = "x: int | None = None\n"
        spots = _annotation_binop_spots(src)
        # ``int`` at cols 3-5, space at 6, pipe at 7.
        self.assertEqual(spots, {(1, 7)})

    def test_finds_pipe_in_nested_generic_annotation(self) -> None:
        src = "def f() -> list[int | None]:\n    return []\n"
        spots = _annotation_binop_spots(src)
        # Inside ``list[...]`` the pipe sits at col 20.
        self.assertEqual(spots, {(1, 20)})

    def test_handles_no_whitespace_around_pipe(self) -> None:
        src = "def f() -> int|None:\n    return None\n"
        spots = _annotation_binop_spots(src)
        # ``int`` at cols 11-13, pipe immediately at 14.
        self.assertEqual(spots, {(1, 14)})

    def test_handles_extra_whitespace_around_pipe(self) -> None:
        src = "def f() -> int   |   None:\n    return None\n"
        spots = _annotation_binop_spots(src)
        # ``int`` at 11-13, three spaces, pipe at 17.
        self.assertEqual(spots, {(1, 17)})

    def test_ignores_expression_level_bitwise_or(self) -> None:
        # The critical correctness property: real bitwise OR (the
        # canonical case is ``os.O_WRONLY | os.O_CREAT | os.O_EXCL``)
        # must NOT appear in the skip set, or mutations on POSIX flag
        # composition would be silently dropped.
        src = "import os\nflags = os.O_WRONLY | os.O_CREAT | os.O_EXCL\n"
        spots = _annotation_binop_spots(src)
        self.assertEqual(spots, set())

    def test_handles_async_function_returns(self) -> None:
        src = "async def f() -> int | None:\n    return None\n"
        spots = _annotation_binop_spots(src)
        self.assertEqual(spots, {(1, 21)})

    def test_handles_multiple_arg_annotations(self) -> None:
        src = (
            "def f(\n"
            "    a: int | None,\n"
            "    b: str | bytes,\n"
            ") -> bool | None:\n"
            "    return None\n"
        )
        spots = _annotation_binop_spots(src)
        # Three distinct pipes: arg ``a`` (line 2, col 11), arg ``b``
        # (line 3, col 11), return (line 4, col 10).
        self.assertEqual(spots, {(2, 11), (3, 11), (4, 10)})

    def test_handles_vararg_and_kwarg_annotations(self) -> None:
        src = "def f(*args: int | None, **kwargs: str | int) -> None:\n    pass\n"
        spots = _annotation_binop_spots(src)
        # ``*args`` pipe at col 17, ``**kwargs`` pipe at col 39.
        self.assertEqual(spots, {(1, 17), (1, 39)})

    def test_handles_module_with_no_annotations(self) -> None:
        src = "def f(x):\n    return x + 1\n"
        spots = _annotation_binop_spots(src)
        self.assertEqual(spots, set())

    def test_handles_non_bitor_binop_in_annotation(self) -> None:
        # Synthetic but legal Python: an annotation that uses a
        # non-``|`` BinOp (this would be exotic but ast-parseable as
        # an annotation value). The current implementation collects
        # any BinOp inside an annotation and reports the position of
        # the operator token *if* a ``|`` is found between left and
        # right. Other operators yield no match — the filter only
        # cares about BitOr.
        src = "x: 'placeholder' = 1\n"
        spots = _annotation_binop_spots(src)
        self.assertEqual(spots, set())
