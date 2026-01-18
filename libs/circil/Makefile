VIRTUALENV=.venv
PYTHON=$(VIRTUALENV)/bin/python3
BLACK=$(VIRTUALENV)/bin/black
FLAKE8=$(VIRTUALENV)/bin/flake8
ISORT=$(VIRTUALENV)/bin/isort
PYRIGHT=$(VIRTUALENV)/bin/pyright
PYTEST=$(VIRTUALENV)/bin/pytest

DEFAULT_GOAL: help
.PHONY: clean venv install-dev check format help

$(VIRTUALENV):
	python3 -m venv $(VIRTUALENV)

$(PYTHON): $(VIRTUALENV)
	make install-dev

$(BLACK): $(VIRTUALENV)
	make install-dev

$(FLAKE8): $(VIRTUALENV)
	make install-dev

$(ISORT): $(VIRTUALENV)
	make install-dev

$(PYRIGHT): $(VIRTUALENV)
	make install-dev

$(PYTEST): $(VIRTUALENV)
	make install-dev

venv: $(VIRTUALENV)

clean:
	rm -rf $(VIRTUALENV)

install-dev: $(VIRTUALENV)
	$(PYTHON) -m pip install -r pip-requirements.txt
	$(PYTHON) -m pip install -r dev-requirements.txt

make test: $(PYTEST)
	$(PYTEST) -v

check: $(BLACK) $(FLAKE8) $(ISORT) $(PYRIGHT)
	$(BLACK) --check .
	$(FLAKE8) .
	$(ISORT) --check-only .
	$(PYRIGHT) .

format: $(BLACK) $(ISORT)
	$(BLACK) .
	$(ISORT) .

help:
	@echo "== Makefile for formatting and analysis =="
	@echo ""
	@echo "- To run all kinds of checks type:"
	@echo "    %> make check"
	@echo ""
	@echo "- To apply formatting type:"
	@echo "    %> make format"
	@echo ""
	@echo "- To execute all unit-tests type:"
	@echo "    %> make test"
	@echo "==========================================="