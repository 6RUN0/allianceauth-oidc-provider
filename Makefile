.PHONY: help clean dev test lint typecheck coverage audit package deploy

help:
	@echo "Available targets (all run via uv):"
	@echo "  dev        sync dev dependencies (uv sync --all-groups + pre-commit install)"
	@echo "  test       run Django test suite (nox -s tests)"
	@echo "  lint       run pre-commit on all files (nox -s lint)"
	@echo "  typecheck  run mypy + basedpyright (nox -s typecheck)"
	@echo "  coverage   run tests with coverage report (nox -s coverage)"
	@echo "  audit      pip-audit dependencies (nox -s audit)"
	@echo "  clean      remove build artifacts"
	@echo "  package    build distributions (flit)"
	@echo "  deploy     upload distributions to PyPI (twine)"

dev:
	uv sync --all-groups
	uv run pre-commit install

test:
	uv run nox -s tests

lint:
	uv run nox -s lint

typecheck:
	uv run nox -s typecheck

coverage:
	uv run nox -s coverage

audit:
	uv run nox -s audit

clean:
	rm -rf dist/*

package:
	uv run --with flit flit build

deploy:
	uv run --with twine twine upload dist/*
