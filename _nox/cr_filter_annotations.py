"""
Cosmic-ray filter that skips ``BinOp(BitOr)`` mutations inside
PEP 604 type-annotation contexts.

``cosmic-ray``'s AST-based mutators treat ``int | None`` (a PEP 604
union) as an ordinary ``BinOp(BitOr())`` and mutates it like any
other binary operator. Under ``from __future__ import annotations``
(PEP 563, in use across this package), the annotation is stored as a
string at runtime and never evaluated, so mutating
``UserLike | None`` → ``UserLike + None`` yields semantically
identical runtime behaviour and the mutant always survives.

These survivors are pure noise: they don't reflect real test-suite
gaps but inflate the survivor count, shifting the mutation score
from a truthful ~76% to a misleading ~52% and masking real gaps.

This filter parses each mutated module's AST and collects the
``(lineno, col_offset)`` of every ``BinOp`` lying inside an
annotation context. Matching pending mutants are marked
``WorkerOutcome.SKIPPED`` so ``cosmic-ray exec`` never executes them.

Annotation contexts covered:

* ``FunctionDef.returns`` and ``AsyncFunctionDef.returns``
* ``args.{args, kwonlyargs, posonlyargs}[*].annotation``
* ``args.{vararg, kwarg}.annotation``
* ``AnnAssign.annotation``

Crucially, real bitwise OR in expressions — e.g.
``os.O_WRONLY | os.O_CREAT | os.O_EXCL`` in ``oidc_jwks_rotate`` —
is *not* in any annotation context and is left untouched. Its
mutations still need to be killed by tests.

The filter only touches pending work items, so re-running it on an
already-executed session is a no-op.

Invoked from ``_nox/mutation.py`` between ``cosmic-ray init`` and
``cosmic-ray exec``. Can also be run standalone::

    uv run python _nox/cr_filter_annotations.py mutation.sqlite

The ``--project-root`` flag (default: cwd) controls the base path
used to resolve ``module_path`` entries from the session DB to files
on disk.
"""

from __future__ import annotations

import argparse
import ast
import logging
import pathlib
import sys

# cosmic_ray is only needed by the WorkDB transport path
# (``filter_session``). The AST core (``_annotation_binop_spots``) has
# no runtime dependency on it, and is exercised by tests that run on
# every CI matrix — including matrices that do not install cosmic_ray
# (the ``mutation`` nox session installs it; the regular ``tests``
# session does not). Importing cosmic_ray at module top-level made
# test discovery itself fail with ``ModuleNotFoundError`` on those
# matrices; moving the import into ``filter_session`` keeps the AST
# helper importable everywhere and surfaces the missing dependency
# only when the mutation path is actually invoked.

_BITOR_PREFIX = "core/ReplaceBinaryOperator_BitOr_"

log = logging.getLogger("cr_filter_annotations")


def _annotation_binop_spots(source: str) -> set[tuple[int, int]]:
    """
    Return ``{(lineno, op_col), ...}`` for BinOp operators in annotations.

    The coordinate is the column of the **operator token** itself
    (e.g. the ``|`` in ``str | None``), not the BinOp expression's
    starting column. ``cosmic-ray`` records mutation positions
    operator-centric, so the filter must compare against the
    operator's location. ``ast.BinOp.left.col_offset`` would point at
    the left operand instead and produce zero matches.

    To recover the operator column we read the source between
    ``left.end_col_offset`` and ``right.col_offset`` and locate the
    first ``|`` character. This works regardless of surrounding
    whitespace (``str | None``, ``str|None``, ``str  |  None``).

    ``ast.lineno`` is 1-indexed and ``col_offset`` is 0-indexed,
    matching the format ``cosmic-ray`` records in
    ``mutation_specs.start_pos``.
    """
    lines = source.splitlines()
    tree = ast.parse(source)
    spots: set[tuple[int, int]] = set()

    def collect_binops(annotation: ast.AST | None) -> None:
        if annotation is None:
            return
        # ``ast.walk`` recurses, so nested annotations like
        # ``list[int | None]`` (a ``Subscript`` containing a
        # ``BinOp``) are picked up as well.
        for sub in ast.walk(annotation):
            if not isinstance(sub, ast.BinOp):
                continue
            # Guard against multi-line BinOps (PEP 604 unions
            # virtually never span lines, but defensive against
            # exotic formatting).
            if sub.left.end_lineno != sub.right.lineno:
                continue
            line_idx = sub.left.end_lineno - 1
            if line_idx >= len(lines):
                continue
            line = lines[line_idx]
            left_end = sub.left.end_col_offset or 0
            right_start = sub.right.col_offset
            segment = line[left_end:right_start]
            pipe_offset = segment.find("|")
            if pipe_offset == -1:
                continue
            spots.add((sub.left.end_lineno, left_end + pipe_offset))

    class Visitor(ast.NodeVisitor):
        def _visit_fn(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            collect_binops(node.returns)
            args = node.args
            for arg in (*args.args, *args.kwonlyargs, *args.posonlyargs):
                collect_binops(arg.annotation)
            for arg in (args.vararg, args.kwarg):
                if arg is not None:
                    collect_binops(arg.annotation)
            self.generic_visit(node)

        # ast dispatches by exact class name; both function flavours
        # share the same annotation surface, so one handler covers
        # both. The mixedCase names are forced by ast.NodeVisitor's
        # dispatch contract — N815 does not apply here.
        visit_FunctionDef = _visit_fn  # noqa: N815
        visit_AsyncFunctionDef = _visit_fn  # noqa: N815

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            collect_binops(node.annotation)
            self.generic_visit(node)

    Visitor().visit(tree)
    return spots


def filter_session(
    session_path: pathlib.Path,
    project_root: pathlib.Path,
) -> tuple[int, int]:
    """Mark PEP 604 BinOp mutants as SKIPPED. Return ``(skipped, scanned)``."""
    from cosmic_ray.work_db import use_db
    from cosmic_ray.work_item import WorkerOutcome, WorkResult

    cache: dict[str, set[tuple[int, int]]] = {}
    skipped = 0
    scanned = 0

    with use_db(str(session_path)) as db:
        # ``pending_work_items`` is an iterator over rows the WorkDB
        # has no result for yet — exactly what filters are supposed
        # to mutate.
        for item in db.pending_work_items:
            scanned += 1
            for mutation in item.mutations:
                if not mutation.operator_name.startswith(_BITOR_PREFIX):
                    continue
                module_path = str(mutation.module_path)
                if module_path not in cache:
                    full = project_root / module_path
                    if not full.is_file():
                        log.warning(
                            "Module path %s does not resolve under %s; "
                            "skipping its annotation scan",
                            module_path,
                            project_root,
                        )
                        cache[module_path] = set()
                    else:
                        cache[module_path] = _annotation_binop_spots(
                            full.read_text(encoding="utf-8")
                        )
                if tuple(mutation.start_pos) in cache[module_path]:
                    db.set_result(
                        item.job_id,
                        WorkResult(
                            output="Filtered: PEP 604 annotation BinOp",
                            worker_outcome=WorkerOutcome.SKIPPED,
                        ),
                    )
                    skipped += 1
                    # WorkItem can hold multiple mutations (combined
                    # operators), but cosmic-ray runs them atomically
                    # — one filter hit kills the whole item.
                    break

    return skipped, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Skip PEP 604 type-annotation BinOp mutants in a "
            "cosmic-ray session."
        )
    )
    parser.add_argument(
        "session", help="Path to the cosmic-ray session SQLite database."
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help=(
            "Directory the relative module paths in the session "
            "are resolved against (default: current directory)."
        ),
    )
    parser.add_argument(
        "--verbosity",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.verbosity))

    project_root = pathlib.Path(args.project_root).resolve()
    session_path = pathlib.Path(args.session).resolve()
    if not session_path.is_file():
        log.error("Session file not found: %s", session_path)
        return 2

    skipped, scanned = filter_session(session_path, project_root)
    log.info(
        "Skipped %d / %d pending work items as PEP 604 annotation noise",
        skipped,
        scanned,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
