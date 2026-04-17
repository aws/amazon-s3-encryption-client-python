.PHONY: lint format test test-unit test-integration test-perf install

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

# Run unit tests (creates .coverage report)
test-unit:
	uv run pytest test/ --ignore=test/integration/ --ignore=test/performance/ --verbose --cov=src/s3_encryption --cov-report=term-missing

# Run integration tests (appends to .coverage report from test-unit)
test-integration:
	uv run pytest test/integration/ --verbose --cov=src/s3_encryption --cov-append --cov-report=term-missing

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

