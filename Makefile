.PHONY: help clean dev test test-all lint lint-md lint-actions typecheck coverage audit messages compilemessages makemigrations diagrams mutation mutation-parallel mutation-html package deploy

help:
	@echo "Available targets (all run via uv):"
	@echo "  dev              sync dev dependencies (uv sync + pre-commit install)"
	@echo "  test             run Django test suite (nox -s tests)"
	@echo "  test-all         run tests on every supported Python (nox -s tests_matrix)"
	@echo "  lint             run pre-commit on all files (nox -s lint)"
	@echo "  lint-md          lint Markdown via rumdl + lychee + vale (nox -s markdown_lint)"
	@echo "  lint-actions     lint GitHub Actions workflows via actionlint + zizmor (nox -s actions_lint)"
	@echo "  typecheck        run mypy + basedpyright (nox -s typecheck)"
	@echo "  coverage         run tests with coverage report (nox -s coverage)"
	@echo "  audit            pip-audit dependencies (nox -s audit)"
	@echo "  messages         extract translatable strings (nox -s makemessages)"
	@echo "  compilemessages  compile .po -> .mo (nox -s compilemessages)"
	@echo "  makemigrations   generate Django migrations (nox -s makemigrations)"
	@echo "  diagrams         render assets/diagrams/*.d2 to SVG via d2 (nox -s diagrams)"
	@echo "  mutation         mutation testing via cosmic-ray (nox -s mutation; multi-hour pre-release gate)"
	@echo "  mutation-parallel  parallel cosmic-ray sweep via N isolated workers (N=4 default; resumes mutation.sqlite)"
	@echo "  mutation-html    render cosmic-ray HTML report under html/ (nox -s mutation_html)"
	@echo "  clean            remove build artifacts"
	@echo "  package          build distributions (flit)"
	@echo "  deploy           upload distributions to PyPI (uv publish)"

dev:
	uv sync
	uv run pre-commit install

test:
	uv run nox -s tests

test-all:
	uv run nox -s tests_matrix

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

clean:
	rm -rf dist/* mutation.sqlite mutation.sqlite-* html/

package:
	uv run --with flit flit build

deploy:
	uv publish dist/*
