# Makefile for S3 Encryption Client C++ v3 Example

# Default target
.PHONY: all build clean run help

# Variables
BUILD_DIR = build
EXECUTABLE = $(BUILD_DIR)/s3ec-example

# Default arguments for running the example
# Override these when calling make run
BUCKET_NAME ?= avp-21638
OBJECT_KEY ?= s3ec-cpp-v3
KMS_KEY_ID ?= arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01
AWS_REGION ?= us-east-2

all: build

# Build the project using CMake
build:
	@echo "Building S3 Encryption Client v3 example..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && make
	@echo "Build completed successfully!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean completed!"

# Run the example with default or provided arguments
run: build
	@echo "Running S3 Encryption Client v3 example..."
	@echo "Bucket: $(BUCKET_NAME)"
	@echo "Object Key: $(OBJECT_KEY)"
	@echo "KMS Key ID: $(KMS_KEY_ID)"
	@echo ""
	@$(EXECUTABLE) $(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID)

# Run with custom arguments
# Usage: make run-custom BUCKET_NAME=my-bucket OBJECT_KEY=my-key KMS_KEY_ID=my-kms-key
run-custom: build
	@$(EXECUTABLE) $(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID)

# Show help
help:
	@echo "S3 Encryption Client C++ v3 Example Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build the example using CMake"
	@echo "  run        - Build and run the example with default parameters"
	@echo "  run-custom - Build and run with custom parameters"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Default parameters:"
	@echo "  BUCKET_NAME = $(BUCKET_NAME)"
	@echo "  OBJECT_KEY  = $(OBJECT_KEY)"
	@echo "  KMS_KEY_ID  = $(KMS_KEY_ID)"
	@echo ""
	@echo "To run with custom parameters:"
	@echo "  make run BUCKET_NAME=your-bucket OBJECT_KEY=your-key KMS_KEY_ID=your-kms-key"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - AWS SDK for C++ must be installed on the system"
	@echo "  - AWS credentials configured (AWS CLI, environment variables, or IAM role)"
	@echo "  - CMake 3.16+ and C++17 compatible compiler"
	@echo "  - Valid S3 bucket and KMS key"
	@echo ""
	@echo "Version differences:"
	@echo "  - v3 uses enhanced security profiles and stricter validation"
	@echo "  - v3 may have different API patterns compared to v2"
	@echo "  - v3 focuses on modern cryptographic standards"
