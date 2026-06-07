"""
Single source of truth for the project ``Makefile``.

The ``Makefile`` is a thin convenience shim: nearly every target is one
``uv run nox -s <session>`` line. Hand-maintaining it drifts from the
nox session registry — a session gets added with no ``make`` target, or
a target keeps pointing at a renamed session. This module makes the
table the source of truth and renders the ``Makefile`` from it, so three
drift gates (in ``noxfile.py``'s ``makefile_check`` session) can keep the
two honest:

#. **content** — the committed ``Makefile`` byte-matches
   :func:`render_makefile`.
#. **coverage** — every registered nox session is wrapped by some target
   (:func:`find_uncovered_sessions`), modulo :data:`SESSIONS_WITHOUT_TARGET`.
#. **dangling** — every target that names a session names a *real* one
   (:func:`find_dangling_targets`).

This module is deliberately free of any ``import nox`` so the off-lock
test venvs (which carry no dev tooling) can still import it: the pure
render / diff logic is unit-tested in ``tests/unit/test_nox_makefile.py``
under the ``tests/unit/`` tier the import canary sweeps. The nox
*sessions* that drive it (``makefile`` / ``makefile_check``) live in
``noxfile.py`` and pass the live ``nox.registry`` set into the pure
functions here.

The render is intentionally hook-clean — every line right-stripped, a
single trailing newline — so the generated text matches what
``end-of-file-fixer`` / ``trailing-whitespace`` leave on the committed
file, and the content gate never trips on whitespace alone.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

__all__ = [
    "SESSIONS_WITHOUT_TARGET",
    "TARGETS",
    "Target",
    "find_dangling_targets",
    "find_uncovered_sessions",
    "render_makefile",
]

_TEMPLATE_PATH = pathlib.Path(__file__).parent / "Makefile.tmpl"


@dataclass(frozen=True)
class Target:
    """
    One ``make`` target.

    ``name`` is the hyphenated target; ``session`` is the underscore nox
    session it wraps (``None`` for the handful of special targets like
    ``dev`` / ``clean`` that run raw shell, not a session). ``recipe``
    is the verbatim command line(s) emitted under the rule (each
    tab-indented on render); ``comment`` is an optional explanatory block
    rendered as ``#`` lines above the rule, carried here so the prose
    lives next to the target instead of drifting in a hand-edited file.
    """

    name: str
    help: str
    recipe: tuple[str, ...]
    session: str | None = None
    comment: tuple[str, ...] = field(default_factory=tuple)


# Sessions that intentionally have no ``make`` target. Empty today: the
# table below wraps every registered session. Kept as an explicit knob
# so a future session that genuinely should not be surfaced as a target
# (a private helper session, say) can be excluded loudly rather than by
# silently weakening the coverage gate.
SESSIONS_WITHOUT_TARGET: frozenset[str] = frozenset()


# Order here is the order rules appear in the rendered Makefile and the
# order the ``help`` target lists them. Grouped: bootstrap, test family,
# quality gates, i18n, migrations, diagrams, conformance, mutation,
# Makefile self-management, packaging.
TARGETS: tuple[Target, ...] = (
    Target(
        name="dev",
        help="sync dev dependencies (uv sync + pre-commit install)",
        recipe=("uv sync", "uv run pre-commit install"),
    ),
    Target(
        name="test",
        help="run Django test suite (nox -s tests)",
        recipe=("uv run nox -s tests",),
        session="tests",
    ),
    Target(
        name="test-all",
        help="run tests on every supported Python (nox -s tests_matrix)",
        recipe=("uv run nox -s tests_matrix",),
        session="tests_matrix",
    ),
    Target(
        name="test-aa4",
        help=(
            "run AA 4.x compatibility matrix "
            "(nox -s tests_aa4; 3.10/3.11/3.12, off-lock)"
        ),
        recipe=("uv run nox -s tests_aa4",),
        session="tests_aa4",
    ),
    Target(
        name="test-compat",
        help=(
            "run tests against AA_PIN='<PEP 508 spec>' "
            "(nox -s tests_compat; ad-hoc probe)"
        ),
        recipe=("AA_PIN='$(AA_PIN)' uv run nox -s tests_compat",),
        session="tests_compat",
        comment=(
            "``tests_compat`` is parametrised across every supported "
            "Python and",
            "requires ``AA_PIN`` to be set to a PEP 508 requirement. Typical",
            "invocations:",
            "  make test-compat AA_PIN='allianceauth==5.1rc1'",
            "  AA_PIN='allianceauth>=5.0,<5.1' make test-compat",
            "Pass ``-- --python=3.12`` (or run nox directly) to narrow the",
            "matrix to a single interpreter when probing an "
            "interpreter-specific",
            "upstream behaviour.",
        ),
    ),
    Target(
        name="mariadb",
        help=(
            "run the suite against a real MariaDB "
            "(nox -s tests_mariadb; testcontainers / CI service)"
        ),
        recipe=("uv run nox -s tests_mariadb",),
        session="tests_mariadb",
        comment=(
            "DB-backed smoke against the MySQL-family backend. Uses a "
            "throwaway",
            "``testcontainers`` MariaDB (needs Docker) or an external "
            "server via",
            "``AA_OIDC_TEST_DB_HOST``; skips cleanly when neither is "
            "available.",
            "See docs/MARIADB.md.",
        ),
    ),
    Target(
        name="timing",
        help="report the slowest test cases (nox -s tests_timing)",
        recipe=("uv run nox -s tests_timing",),
        session="tests_timing",
        comment=(
            "Single-process run with ``--durations``; ``N`` comes from the",
            "``OIDC_TIMING_DURATIONS`` env var (default 25, 0 for all):",
            "  OIDC_TIMING_DURATIONS=50 make timing",
        ),
    ),
    Target(
        name="integration",
        help=(
            "run wire-level mock-RP integration tests "
            "(nox -s integration; LiveServerTestCase)"
        ),
        recipe=("uv run nox -s integration",),
        session="integration",
    ),
    Target(
        name="preflight",
        help="lint + typecheck + tests + migration gates (nox -s preflight)",
        recipe=("uv run nox -s preflight",),
        session="preflight",
    ),
    Target(
        name="lint",
        help="run pre-commit on all files (nox -s lint)",
        recipe=("uv run nox -s lint",),
        session="lint",
    ),
    Target(
        name="lint-md",
        help="lint Markdown via rumdl + lychee + vale (nox -s markdown_lint)",
        recipe=("uv run nox -s markdown_lint",),
        session="markdown_lint",
    ),
    Target(
        name="lint-actions",
        help=(
            "lint GitHub Actions workflows via actionlint + zizmor "
            "(nox -s actions_lint)"
        ),
        recipe=("uv run nox -s actions_lint",),
        session="actions_lint",
    ),
    Target(
        name="typecheck",
        help="run mypy + basedpyright (nox -s typecheck)",
        recipe=("uv run nox -s typecheck",),
        session="typecheck",
    ),
    Target(
        name="coverage",
        help="run tests with coverage report (nox -s coverage)",
        recipe=("uv run nox -s coverage",),
        session="coverage",
    ),
    Target(
        name="audit",
        help="pip-audit dependencies (nox -s audit)",
        recipe=("uv run nox -s audit",),
        session="audit",
    ),
    Target(
        name="messages",
        help="extract translatable strings (nox -s makemessages)",
        recipe=("uv run nox -s makemessages",),
        session="makemessages",
    ),
    Target(
        name="messages-check",
        help="check .po/.pot/.mo catalogue integrity (nox -s messages_check)",
        recipe=("uv run nox -s messages_check",),
        session="messages_check",
    ),
    Target(
        name="compilemessages",
        help="compile .po -> .mo (nox -s compilemessages)",
        recipe=("uv run nox -s compilemessages",),
        session="compilemessages",
    ),
    Target(
        name="makemigrations",
        help="generate Django migrations (nox -s makemigrations)",
        recipe=("uv run nox -s makemigrations",),
        session="makemigrations",
    ),
    Target(
        name="migrations-check",
        help=(
            "verify migrations are in sync and free of unsafe ops "
            "(nox -s migrations_check)"
        ),
        recipe=("uv run nox -s migrations_check",),
        session="migrations_check",
    ),
    Target(
        name="migrations-ddl-check",
        help=(
            "scan raw RunSQL migrations for blocking DDL "
            "(nox -s migrations_concurrency_check)"
        ),
        recipe=("uv run nox -s migrations_concurrency_check",),
        session="migrations_concurrency_check",
    ),
    Target(
        name="diagrams",
        help="render assets/diagrams/*.d2 to SVG via d2 (nox -s diagrams)",
        recipe=("uv run nox -s diagrams",),
        session="diagrams",
    ),
    Target(
        name="conformance",
        help=(
            "run the OpenID conformance suite "
            "(nox -s conformance; docker compose)"
        ),
        recipe=("uv run nox -s conformance",),
        session="conformance",
    ),
    Target(
        name="conformance-basic",
        help=(
            "run the basic OpenID conformance profile "
            "(nox -s conformance_basic)"
        ),
        recipe=("uv run nox -s conformance_basic",),
        session="conformance_basic",
    ),
    Target(
        name="mutation",
        help=(
            "mutation testing via cosmic-ray "
            "(nox -s mutation; multi-hour pre-release gate)"
        ),
        recipe=("uv run nox -s mutation",),
        session="mutation",
    ),
    Target(
        name="mutation-parallel",
        help=(
            "parallel cosmic-ray sweep via N isolated workers "
            "(N=4 default; resumes mutation.sqlite)"
        ),
        recipe=("uv run nox -s mutation_parallel -- $(N)",),
        session="mutation_parallel",
        comment=(
            "``mutation-parallel`` resumes an existing "
            "``mutation.sqlite`` using",
            "N isolated worker copies; pass N via the make var or env:",
            "``make mutation-parallel N=8`` or the ``CR_PARALLEL_N`` env var.",
            "See ``_nox/mutation.py::mutation_parallel`` and",
            "``docs/mutation-testing.md`` for the orchestration details.",
        ),
    ),
    Target(
        name="mutation-html",
        help="cosmic-ray HTML report under html/ (nox -s mutation_html)",
        recipe=("uv run nox -s mutation_html",),
        session="mutation_html",
    ),
    Target(
        name="mutation-check",
        help=(
            "gate on mutation survival rate "
            "(nox -s mutation_check; MUTATION_MAX_SURVIVAL=35.0 default)"
        ),
        recipe=("uv run nox -s mutation_check",),
        session="mutation_check",
        comment=(
            "``mutation-check`` reads the existing ``mutation.sqlite`` "
            "and fails",
            "when the cosmic-ray survival rate exceeds "
            "``MUTATION_MAX_SURVIVAL``",
            "(default ``35.0`` — i.e. require >= 65 % killed). Override:",
            "  MUTATION_MAX_SURVIVAL=25.0 make mutation-check    # tighter",
            "  MUTATION_MAX_SURVIVAL=50.0 make mutation-check    # looser",
        ),
    ),
    Target(
        name="makefile",
        help="regenerate ./Makefile from _nox/makefile.py (nox -s makefile)",
        recipe=("uv run nox -s makefile",),
        session="makefile",
    ),
    Target(
        name="makefile-check",
        help="check Makefile matches _nox/makefile.py (nox -s makefile_check)",
        recipe=("uv run nox -s makefile_check",),
        session="makefile_check",
    ),
    Target(
        name="clean",
        help="remove build artifacts",
        recipe=("rm -rf dist/* mutation.sqlite mutation.sqlite-* html/",),
    ),
    Target(
        name="package",
        help="build distributions (uv build)",
        recipe=("uv build",),
    ),
    Target(
        name="verify-wheel",
        help=(
            "audit wheel inventory for required + forbidden patterns "
            "(nox -s verify_wheel)"
        ),
        recipe=("uv run nox -s verify_wheel",),
        session="verify_wheel",
    ),
    Target(
        name="deploy",
        help="upload distributions to PyPI (uv publish)",
        recipe=("uv publish dist/*",),
    ),
)


def find_uncovered_sessions(
    registered: set[str],
    targets: tuple[Target, ...] = TARGETS,
) -> set[str]:
    """
    Return registered sessions that no target wraps.

    The coverage drift gate: a session present in ``registered`` (the
    live ``nox.registry`` keys) but named by no target's ``session``
    field — and not explicitly excused via
    :data:`SESSIONS_WITHOUT_TARGET` — is a session someone added without
    a ``make`` entry.
    """
    covered = {t.session for t in targets if t.session is not None}
    return set(registered) - covered - SESSIONS_WITHOUT_TARGET


def find_dangling_targets(
    registered: set[str],
    targets: tuple[Target, ...] = TARGETS,
) -> set[str]:
    """
    Return target names whose ``session`` is not a registered session.

    The dangling drift gate: a target wrapping ``nox -s X`` where ``X``
    is no longer a registered session (renamed / removed) — ``make X``
    would fail at the call site, so flag it at lint time instead.
    """
    return {
        t.name
        for t in targets
        if t.session is not None and t.session not in registered
    }


def _render_help(targets: tuple[Target, ...]) -> str:
    """Render the ``help`` rule, listing every target and its blurb."""
    width = max(len("help"), *(len(t.name) for t in targets))
    lines = [
        "help:",
        '\t@echo "Available targets (all run via uv):"',
    ]
    lines += [f'\t@echo "  {t.name:<{width}}  {t.help}"' for t in targets]
    return "\n".join(lines)


def _render_target(target: Target) -> str:
    """Render one target's optional comment block plus its rule."""
    lines = [("# " + line).rstrip() for line in target.comment]
    lines.append(f"{target.name}:")
    lines += [f"\t{line}" for line in target.recipe]
    return "\n".join(lines)


def render_makefile(targets: tuple[Target, ...] = TARGETS) -> str:
    """
    Render the full ``Makefile`` text from the template and the table.

    Fills the template's ``{phony}`` (the ``.PHONY`` member list, with
    ``help`` first) and ``{body}`` (the ``help`` rule followed by one
    rule per target). The output is normalised hook-clean — every line
    right-stripped, exactly one trailing newline — so it matches the
    committed file byte-for-byte after pre-commit has run.
    """
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    phony = " ".join(["help", *(t.name for t in targets)])
    blocks = [_render_help(targets), *(_render_target(t) for t in targets)]
    body = "\n\n".join(blocks)
    rendered = template.replace("{phony}", phony).replace("{body}", body)
    cleaned = "\n".join(line.rstrip() for line in rendered.split("\n"))
    return cleaned.rstrip("\n") + "\n"
