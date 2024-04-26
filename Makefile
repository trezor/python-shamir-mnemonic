PYTHON=python3
POETRY=poetry


build:
	$(POETRY) build

install:
	$(POETRY) install

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

test:
	pytest

style_check:
	isort --check-only shamir_mnemonic/ *.py
	black shamir_mnemonic/ *.py --check

style:
	black shamir_mnemonic/ *.py
	isort shamir_mnemonic/ *.py


.PHONY: clean clean-build clean-pyc clean-test test style_check style
