.PHONY: lint format test test-unit test-integration install

# Default target
all: lint test

# Install dependencies
install:
	poetry install

# Run linting checks
lint:
	poetry run black --check .
	poetry run isort --check .
	# Allow flake8 to fail for now as we're gradually adopting linting standards
	poetry run flake8 src/ test/ || true

# Format code with Black and isort
format:
	poetry run black .
	poetry run isort .

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	poetry run pytest test/ --verbose

# Run integration tests
test-integration:
	poetry run pytest test/integration/ --verbose

# Clean up cache files
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .coverage -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
