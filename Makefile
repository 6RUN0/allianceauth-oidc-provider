.PHONY: help clean dev test test-all lint lint-md lint-actions typecheck coverage audit messages compilemessages makemigrations package deploy

help:
	@echo "Available targets (all run via uv):"
	@echo "  dev              sync dev dependencies (uv sync --all-groups + pre-commit install)"
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
	@echo "  clean            remove build artifacts"
	@echo "  package          build distributions (flit)"
	@echo "  deploy           upload distributions to PyPI (twine)"

dev:
	uv sync --all-groups
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

clean:
	rm -rf dist/*

package:
	uv run --with flit flit build

deploy:
	uv run --with twine twine upload dist/*
