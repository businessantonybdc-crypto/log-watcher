.PHONY: dev lint test scan

dev:
	python3 -m pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .
	shellcheck install.sh

test:
	python3 -m pytest -q

scan: ## try it on the sample log
	PYTHONPATH=src python3 -m logwarden.cli --scan tests/fixtures/auth.log
