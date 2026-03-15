# Secure Zeph — Makefile
# Cross-platform targets (use with GNU Make or nmake on Windows)

.PHONY: help install dev test lint serve eval triage clean

PYTHON = .venv/Scripts/python.exe
PIP = .venv/Scripts/pip.exe
PYTEST = .venv/Scripts/pytest.exe
UVICORN = .venv/Scripts/uvicorn.exe
RUFF = .venv/Scripts/ruff.exe

help: ## Show this help
	@echo Available targets:
	@echo   install    - Install production dependencies
	@echo   dev        - Install dev dependencies
	@echo   test       - Run all tests
	@echo   lint       - Run ruff linter
	@echo   serve      - Start gateway server
	@echo   eval       - Run all experiments
	@echo   triage     - Run triage on latest run
	@echo   clean      - Remove caches and build artifacts

install: ## Install production dependencies
	$(PIP) install -r requirements.txt

dev: ## Install dev + production dependencies
	$(PIP) install -e ".[dev]"

test: ## Run all tests with pytest
	set PYTHONPATH=. && $(PYTEST) -v --tb=short

lint: ## Run ruff linter
	$(RUFF) check .

serve: ## Start gateway API server
	set PYTHONPATH=. && $(UVICORN) apps.gateway.app.main:app --host 127.0.0.1 --port 8000 --reload

eval: ## Run all experiments
	set PYTHONPATH=. && $(PYTHON) scripts/run_experiment.py --all

triage: ## Run triage on latest experiment run
	set PYTHONPATH=. && $(PYTHON) scripts/run_triage.py --latest

clean: ## Remove caches and build artifacts
	@if exist __pycache__ rmdir /s /q __pycache__
	@if exist .pytest_cache rmdir /s /q .pytest_cache
	@if exist .ruff_cache rmdir /s /q .ruff_cache
	@for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
