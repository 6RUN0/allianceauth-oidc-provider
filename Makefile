.PHONY: help clean dev test test-all test-aa4 test-compat integration preflight lint lint-md lint-actions typecheck coverage audit messages compilemessages makemigrations migrations-check diagrams mutation mutation-parallel mutation-html mutation-check package verify-wheel deploy

help:
	@echo "Available targets (all run via uv):"
	@echo "  dev              sync dev dependencies (uv sync + pre-commit install)"
	@echo "  test             run Django test suite (nox -s tests)"
	@echo "  test-all         run tests on every supported Python (nox -s tests_matrix)"
	@echo "  test-aa4         run AA 4.x compatibility matrix (nox -s tests_aa4; 3.10/3.11/3.12, off-lock)"
	@echo "  test-compat      run tests against AA_PIN='<PEP 508 spec>' (nox -s tests_compat; ad-hoc probe)"
	@echo "  integration      run wire-level mock-RP integration tests (nox -s integration; LiveServerTestCase)"
	@echo "  preflight        run lint + typecheck + tests + migrations_check (nox -s preflight)"
	@echo "  lint             run pre-commit on all files (nox -s lint)"
	@echo "  lint-md          lint Markdown via rumdl + lychee + vale (nox -s markdown_lint)"
	@echo "  lint-actions     lint GitHub Actions workflows via actionlint + zizmor (nox -s actions_lint)"
	@echo "  typecheck        run mypy + basedpyright (nox -s typecheck)"
	@echo "  coverage         run tests with coverage report (nox -s coverage)"
	@echo "  audit            pip-audit dependencies (nox -s audit)"
	@echo "  messages         extract translatable strings (nox -s makemessages)"
	@echo "  compilemessages  compile .po -> .mo (nox -s compilemessages)"
	@echo "  makemigrations   generate Django migrations (nox -s makemigrations)"
	@echo "  migrations-check verify migrations are in sync and free of unsafe ops (nox -s migrations_check)"
	@echo "  diagrams         render assets/diagrams/*.d2 to SVG via d2 (nox -s diagrams)"
	@echo "  mutation         mutation testing via cosmic-ray (nox -s mutation; multi-hour pre-release gate)"
	@echo "  mutation-parallel  parallel cosmic-ray sweep via N isolated workers (N=4 default; resumes mutation.sqlite)"
	@echo "  mutation-html    render cosmic-ray HTML report under html/ (nox -s mutation_html)"
	@echo "  mutation-check   gate on mutation survival rate (nox -s mutation_check; MUTATION_MAX_SURVIVAL=35.0 default)"
	@echo "  clean            remove build artifacts"
	@echo "  package          build distributions (uv build)"
	@echo "  verify-wheel     audit wheel inventory for required + forbidden patterns (nox -s verify_wheel)"
	@echo "  deploy           upload distributions to PyPI (uv publish)"

dev:
	uv sync
	uv run pre-commit install

test:
	uv run nox -s tests

test-all:
	uv run nox -s tests_matrix

test-aa4:
	uv run nox -s tests_aa4

# ``tests_compat`` is parametrised across every supported Python and
# requires ``AA_PIN`` to be set to a PEP 508 requirement. Typical
# invocations:
#   make test-compat AA_PIN='allianceauth==5.1rc1'
#   AA_PIN='allianceauth>=5.0,<5.1' make test-compat
# Pass ``-- --python=3.12`` (or run nox directly) to narrow the
# matrix to a single interpreter when probing an interpreter-specific
# upstream behaviour.
test-compat:
	AA_PIN='$(AA_PIN)' uv run nox -s tests_compat

integration:
	uv run nox -s integration

preflight:
	uv run nox -s preflight

lint:
	uv run nox -s lint

lint-md:
	uv run nox -s markdown_lint

lint-actions:
	uv run nox -s actions_lint

typecheck:
	uv run nox -s typecheck

coverage:
	uv run nox -s coverage

audit:
	uv run nox -s audit

messages:
	uv run nox -s makemessages

compilemessages:
	uv run nox -s compilemessages

makemigrations:
	uv run nox -s makemigrations

migrations-check:
	uv run nox -s migrations_check

diagrams:
	uv run nox -s diagrams

mutation:
	uv run nox -s mutation

# ``mutation-parallel`` resumes an existing ``mutation.sqlite`` using
# N isolated worker copies; pass N via the make var or env:
# ``make mutation-parallel N=8`` or the ``CR_PARALLEL_N`` env var.
# See ``_nox/mutation.py::mutation_parallel`` and
# ``docs/mutation-testing.md`` for the orchestration details.
mutation-parallel:
	uv run nox -s mutation_parallel -- $(N)

mutation-html:
	uv run nox -s mutation_html

# ``mutation-check`` reads the existing ``mutation.sqlite`` and fails
# when the cosmic-ray survival rate exceeds ``MUTATION_MAX_SURVIVAL``
# (default ``35.0`` — i.e. require ≥ 65 % killed). Override:
#   MUTATION_MAX_SURVIVAL=25.0 make mutation-check    # tighter
#   MUTATION_MAX_SURVIVAL=50.0 make mutation-check    # looser
mutation-check:
	uv run nox -s mutation_check

clean:
	rm -rf dist/* mutation.sqlite mutation.sqlite-* html/

package:
	uv build

verify-wheel:
	uv run nox -s verify_wheel

deploy:
	uv publish dist/*
