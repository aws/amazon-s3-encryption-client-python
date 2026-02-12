.PHONY: lint format test test-unit test-integration install

# Default target
all: lint test

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

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	uv run pytest test/ --ignore=test/integration/ --verbose

# Run integration tests
test-integration:
	uv run pytest test/integration/ --verbose

# Clean up cache files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .coverage -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
