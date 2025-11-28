# Makefile for S3 Encryption Client .NET migration Example

# Default target
.PHONY: all install clean run help

# Default arguments for running the example
# Override these when calling make run
BUCKET_NAME ?= s3ec-test-server-github-bucket
KMS_KEY_ID ?= arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key

all: install

# Install dependencies using .NET modules
install:
	@echo "[NET migration] Installing .NET dependencies..."
	dotnet restore
	@echo "[NET migration] Dependencies installed successfully!"

# Clean .NET artifacts
clean:
	@echo "[NET migration] Cleaning .NET artifacts..."
	dotnet clean
	@echo "[NET migration] Clean completed!"

# Run the example with default arguments
run: install
	@echo "[NET migration] Running S3 Encryption Client .NET Migration example..."
	@export MigrationExample_S3_BUCKET=$(BUCKET_NAME) && export MigrationExample_KMS_KEY_ARN=$(KMS_KEY_ID) && dotnet test

# Run with custom arguments
# Usage: make run-custom BUCKET_NAME=my-bucket OBJECT_KEY=my-key KMS_KEY_ID=my-kms-key AWS_REGION=my-region
run-custom: install
	@export MigrationExample_S3_BUCKET=$(BUCKET_NAME) && export MigrationExample_KMS_KEY_ARN=$(KMS_KEY_ID) && dotnet test

# Show help
help:
	@echo "S3 Encryption Client .NET migration Example Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Install .NET dependencies using .NET modules"
	@echo "  run        - Install dependencies and run the example with default parameters"
	@echo "  run-custom - Install dependencies and run with custom parameters"
	@echo "  clean      - Remove .NET artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Supported .NET framework installed on the system. See https://www.nuget.org/packages/Amazon.Extensions.S3.Encryption for supported one."
	@echo "  - AWS credentials configured (AWS CLI, environment variables, or IAM role)"
	@echo "  - Valid S3 bucket and KMS key with appropriate permissions"