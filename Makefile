.PHONY: help install dev test test-cov lint format typecheck clean docker run

help:
	@echo ""
	@echo "  Canary - Honeypot Aggregation & Threat Correlation"
	@echo "  =================================================="
	@echo ""
	@echo "  make install     Install the package"
	@echo "  make dev         Install in development mode"
	@echo "  make test        Run tests"
	@echo "  make test-cov    Run tests with coverage"
	@echo "  make lint        Run linter (ruff)"
	@echo "  make format      Format code (ruff)"
	@echo "  make typecheck   Run type checker (mypy)"
	@echo "  make clean       Remove build artifacts"
	@echo "  make docker      Build Docker image"
	@echo "  make run         Start the ingestion API (canary serve)"
	@echo ""

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ -v --tb=short --cov=canary --cov-report=term-missing

lint:
	ruff check canary/ tests/

format:
	ruff format canary/ tests/

typecheck:
	mypy canary/ --ignore-missing-imports

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

docker:
	docker build -t canary:latest .

run:
	canary serve
