.PHONY: help install install-dev run test lint clean uninstall

PY       ?= python3
VENV     := .venv
BIN      := $(VENV)/bin
BIN_DIR  ?= $(HOME)/.local/bin

help:
	@echo "pwnsh — make targets:"
	@echo "  install      create .venv + editable install + symlink in $(BIN_DIR)"
	@echo "  install-dev  install + pytest + ruff (dev extras)"
	@echo "  run          launch the TUI (PORT=9090 BIND=0.0.0.0)"
	@echo "  test         run pytest"
	@echo "  lint         run ruff check"
	@echo "  clean        remove .venv, __pycache__, build artefacts"
	@echo "  uninstall    remove the $(BIN_DIR)/pwnsh symlink"

install:
	@./install.sh

install-dev: install
	$(BIN)/pip install --quiet '.[dev]'
	@echo "[pwnsh] dev extras installed (pytest, ruff)"

run:
	$(BIN)/pwnsh $(if $(PORT),-p $(PORT)) $(if $(BIND),-b $(BIND))

test:
	$(BIN)/pytest -q

lint:
	$(BIN)/ruff check src tests

clean:
	rm -rf $(VENV) dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +

uninstall:
	rm -f $(BIN_DIR)/pwnsh
	@echo "[pwnsh] removed $(BIN_DIR)/pwnsh (venv left alone — rm -rf .venv to finish)"
