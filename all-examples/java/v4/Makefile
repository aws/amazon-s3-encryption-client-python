# Makefile for S3 Encryption Client Java v4 Example

# Default target
.PHONY: all install clean run help build

# Variables
GRADLE = ./gradlew

# Default arguments for running the example
# Override these when calling make run
BUCKET_NAME ?= avp-21638
OBJECT_KEY ?= s3ec-java-v4
KMS_KEY_ID ?= arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01
AWS_REGION ?= us-east-2

all: build

# Install dependencies and build the project
install: build

# Build the project using Gradle
build:
	@echo "Building S3 Encryption Client Java v4 example..."
	@chmod +x $(GRADLE)
	@$(GRADLE) clean build
	@echo "Build completed successfully!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@$(GRADLE) clean
	@echo "Clean completed!"

# Run the example with default arguments
run: install
	@echo "Running S3 Encryption Client v4 Java example..."
	@echo "Bucket: $(BUCKET_NAME)"
	@echo "Object Key: $(OBJECT_KEY)"
	@echo "KMS Key ID: $(KMS_KEY_ID)"
	@echo "Region: $(AWS_REGION)"
	@echo ""
	@$(GRADLE) run --args="$(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID) $(AWS_REGION)"

# Run with custom arguments
# Usage: make run-custom BUCKET_NAME=my-bucket OBJECT_KEY=my-key KMS_KEY_ID=my-kms-key AWS_REGION=my-region
run-custom: install
	@$(GRADLE) run --args="$(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID) $(AWS_REGION)"

# Show help
help:
	@echo "S3 Encryption Client Java v4 Example Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Build the project using Gradle"
	@echo "  build      - Build the project using Gradle"
	@echo "  run        - Build and run the example with default parameters"
	@echo "  run-custom - Build and run with custom parameters"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Default parameters:"
	@echo "  BUCKET_NAME = $(BUCKET_NAME)"
	@echo "  OBJECT_KEY  = $(OBJECT_KEY)"
	@echo "  KMS_KEY_ID  = $(KMS_KEY_ID)"
	@echo "  AWS_REGION  = $(AWS_REGION)"
	@echo ""
	@echo "To run with custom parameters:"
	@echo "  make run BUCKET_NAME=your-bucket OBJECT_KEY=your-key KMS_KEY_ID=your-kms-key AWS_REGION=your-region"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Java 11+ installed on the system"
	@echo "  - AWS credentials configured (AWS CLI, environment variables, or IAM role)"
	@echo "  - Valid S3 bucket and KMS key with appropriate permissions"
	@echo "  - S3 Encryption Client v4 library installed in local Maven repository"
	@echo "    (Install by running: cd s3ec-staging && mvn install)"
