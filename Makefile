.PHONY: lint format format-check test test-unit test-integration test-perf install docs

# Default target
all: lint test duvet

# Install dependencies
install:
	uv venv
	uv pip install -e ".[dev,test]"

# Run linting checks
lint:
	uv run ruff check src/
	uv run ruff check test/ || true

# Check formatting (no changes, just verify)
format-check:
	uv run ruff format --check src/ test/

# Format code
format:
	uv run ruff format src/ test/
	uv run ruff check --fix src/ test/

# Run all tests with combined coverage
test: test-unit test-integration test-examples

# Run unit tests with coverage
test-unit:
	uv run pytest test/ --ignore=test/integration/ --ignore=test/performance/ --verbose --cov=src/s3_encryption --cov-report=term-missing --cov-fail-under=89

# Run integration tests with separate coverage
test-integration:
	uv run pytest test/integration/ --verbose --cov=src/s3_encryption --cov-report=term-missing --cov-fail-under=83

# Run performance tests
test-perf:
	uv run pytest test/performance/ --verbose -x

test-examples:
	uv run pytest examples/test/ -v

# Clean up cache files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .coverage -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .duvet/reports/ .duvet/requirements/

duvet: | clean duvet-report

duvet-report:
	duvet report

duvet-view-report-mac:
	open .duvet/reports/report.html


# Build docs locally
docs:
	uv pip install -e ".[docs]"
	uv run sphinx-build -b html docs/ docs/_build/html
	@echo "Docs built at docs/_build/html/index.html"

docs-open: docs
	open docs/_build/html/index.html
