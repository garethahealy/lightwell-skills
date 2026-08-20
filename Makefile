PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
TEST_DIR := tests
SHARED := plugins/lightwell/skills/lightwell-shared/scripts
SHELL := bash

.DEFAULT_GOAL := test-unit

.PHONY: install lint test test-unit test-live

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check plugins/lightwell/skills tests
	$(PYTHON) -m ruff format --check plugins/lightwell/skills tests
	$(PYTHON) -m mypy

test-unit:
	$(PYTEST) $(TEST_DIR) -m "not live"

test-live:
	@if [ -z "$$LIGHTWELL_USERNAME" ] || [ -z "$$LIGHTWELL_TOKEN" ]; then \
		set -a; \
		. "$(SHARED)/_load-creds.sh"; \
		set +a; \
	fi; \
	$(PYTEST) $(TEST_DIR) -m live --no-cov

test: test-unit test-live
