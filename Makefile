.PHONY: all install test lint format benchmark clean run-lab run-backend run-frontend

PYTHON ?= python

all: lint test

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest tests/ --cov=backend --cov=lab --cov-report=term-missing

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

benchmark:
	$(PYTHON) -m benchmarks.run_all

clean:
	rm -rf .pytest_cache .coverage htmlcov __pycache__ *.egg-info

