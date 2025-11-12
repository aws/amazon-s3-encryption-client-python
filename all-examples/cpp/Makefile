# Makefile for S3 Encryption Client C++ Example

.PHONY: all install clean run help

# Default arguments for running the example
# Override these when calling make run
VERSION ?= V3
BUCKET_NAME ?= avp-21638
OBJECT_KEY ?= s3ec-cpp-test
KMS_KEY_ID ?= arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01
AWS_REGION ?= us-east-2

all: run

install: build/s3ec-test

aws-sdk-cpp:
	git clone --recurse-submodules -b fire-egg-dev https://github.com/awslabs/aws-sdk-cpp-staging.git aws-sdk-cpp

build/s3ec-test: aws-sdk-cpp
	mkdir -p build && cd build && cmake .. && make

clean:
	rm -rf build

# Run the example with default arguments
run: build/s3ec-test
	@echo "Running S3 Encryption Client C++ example..."
	@echo "Version: $(VERSION)"
	@echo "Bucket: $(BUCKET_NAME)"
	@echo "Object Key: $(OBJECT_KEY)"
	@echo "KMS Key ID: $(KMS_KEY_ID)"
	@echo "Region: $(AWS_REGION)"
	@echo ""
	./build/s3ec-test $(VERSION) $(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID) $(AWS_REGION)

# Show help
help:
	@echo "S3 Encryption Client C++ Example Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Install Go dependencies using Go modules"
	@echo "  run        - Install dependencies and run the example"
	@echo "  clean      - Remove C++ artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Default parameters:"
	@echo "  VERSION = $(VERSION) (must be V2 or V3)"
	@echo "  BUCKET_NAME = $(BUCKET_NAME)"
	@echo "  OBJECT_KEY  = $(OBJECT_KEY)"
	@echo "  KMS_KEY_ID  = $(KMS_KEY_ID)"
	@echo "  AWS_REGION  = $(AWS_REGION)"
	@echo ""
	@echo "To run with custom parameters:"
	@echo "  make run VERSION=your-version BUCKET_NAME=your-bucket OBJECT_KEY=your-key KMS_KEY_ID=your-kms-key AWS_REGION=your-region"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Read access to https://github.com/awslabs/aws-sdk-cpp-staging.git"
	@echo "  - AWS credentials configured (AWS CLI, environment variables, or IAM role)"
	@echo "  - Valid S3 bucket and KMS key with appropriate permissions"
