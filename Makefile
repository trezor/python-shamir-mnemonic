PYTHON=python3
SETUP=$(PYTHON) setup.py


build:
	$(SETUP) build

install:
	$(SETUP) install

dist: clean
	$(SETUP) sdist
	$(SETUP) bdist_wheel

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
	isort --check-only --recursive shamir_mnemonic/ *.py
	black shamir_mnemonic/ *.py --check

style:
	black shamir_mnemonic/ *.py
	isort -y --recursive shamir_mnemonic/ *.py


.PHONY: dist clean clean-build clean-pyc clean-test test style_check style
