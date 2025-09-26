SHELL		:= /bin/bash

PYTHON		?= $(shell python3 --version >/dev/null 2>&1 && echo python3 || echo python )

# Ensure $(PYTHON), $(VENV) are re-evaluated at time of expansion, when target 'python' and 'poetry' are known to be available
PYTHON_V	= $(shell $(PYTHON) -c "import sys; print('-'.join((('venv' if sys.prefix != sys.base_prefix else next(iter(filter(None,sys.base_prefix.split('/'))))),sys.platform,sys.implementation.cache_tag)))" 2>/dev/null )

VERSION		= $(shell poetry version -s 2>/dev/null)
VENV		= $(CURDIR)-$(VERSION)-$(PYTHON_V)

# Force export of variables that might be set from command line
export VENV_OPTS	?=
export POETRY		?= poetry
export PYTEST		?= pytest
export PYTEST_OPTS	?= # -vv --capture=no --mypy


build:
	$(POETRY) build

install:
	$(POETRY) install

install-dev:
	$(POETRY) install --with dev

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
	$(PYTEST) $(PYTEST_OPTS)

# Run all tests with names matching the target string
unit-%:
	$(PYTEST) $(PYTEST_OPTS) -k $*

style_check:
	isort --check-only shamir_mnemonic/ *.py
	black shamir_mnemonic/ *.py --check

analyze: style_check
	$(PYTHON) -m flake8 --color never -j 1 \
	  --ignore=W503,E501,E741 \
	  shamir_mnemonic test_shamir.py

style:
	black shamir_mnemonic/ *.py
	isort shamir_mnemonic/ *.py

# 
# Nix and VirtualEnv build, install and activate
#
#     Create, start and run commands in "interactive" shell with a python venv's activate init-file.
# Doesn't allow recursive creation of a venv with a venv-supplied python.  Alters the bin/activate
# to include the user's .bashrc (eg. Git prompts, aliases, ...).  Use to run Makefile targets in a
# proper context, for example to obtain a Nix environment containing the proper Python version,
# create a python venv with the current Python environment.
#
#     make nix-venv-build
#
nix-%:
	@if [ -r flake.nix ]; then \
	    nix develop $(NIX_OPTS) --command make $*; \
        else \
	    nix-shell $(NIX_OPTS) --run "make $*"; \
	fi

venv-%:			$(VENV)
	@echo; echo "*** Running in $< VirtualEnv: make $*"
	@bash --init-file $</bin/activate -ic "make $*"

venv:			$(VENV)
	@echo; echo "*** Activating $< VirtualEnv for Interactive $(SHELL)"
	@bash --init-file $</bin/activate -i

$(VENV):
	@[[ "$(PYTHON_V)" =~ "^venv" ]] && ( echo -e "\n\n!!! $@ Cannot start a venv within a venv"; false ) || true
	@echo; echo "*** Building $@ VirtualEnv..."
	@rm -rf $@ && $(PYTHON) -m venv $(VENV_OPTS) $@ && sed -i -e '1s:^:. $$HOME/.bashrc\n:' $@/bin/activate \
	    && source $@/bin/activate \
	    && make install-dev

print-%:
	@echo $* = $($*)
	@echo $*\'s origin is $(origin $*)


.PHONY: clean clean-build clean-pyc clean-test test style_check style venv
