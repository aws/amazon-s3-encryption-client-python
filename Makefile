.PHONY: lint format test test-unit test-integration install

# Default target
all: lint test duvet

# Install dependencies
install:
	uv venv
	uv pip install -e ".[dev,test]"

# Run linting checks
lint:
	uv run black --check src/ test/
	# Enforce ruff checks on src/ but allow test/ to fail
	uv run ruff check src/
	uv run ruff check test/ || true

# Format code with Black and Ruff
format:
	uv run black src/ test/
	uv run ruff check --fix src/ test/

# Run all tests with combined coverage
test: test-unit test-integration test-examples

# Run unit tests with coverage
test-unit:
	uv run pytest test/ --ignore=test/integration/ --verbose --cov=src/s3_encryption --cov-report=term-missing --cov-fail-under=89

# Run integration tests with separate coverage
test-integration:
	uv run pytest test/integration/ --verbose --cov=src/s3_encryption --cov-report=term-missing --cov-fail-under=83

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

