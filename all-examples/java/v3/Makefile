# Makefile for S3 Encryption Client Java v3 Example

# Default target
.PHONY: all install clean run help s3ec-staging

# Default arguments for running the example
# Override these when calling make run
BUCKET_NAME ?= avp-21638
OBJECT_KEY ?= s3ec-java-v3
KMS_KEY_ID ?= arn:aws:kms:us-east-2:648638458147:key/a47079da-17e4-45a5-b82e-2bac101cad01
AWS_REGION ?= us-east-2

all: install

# Install S3 Encryption Client library from source
s3ec-staging:
	@echo "[JAVA V3] Installing S3 Encryption Client library from source..."
	@cd s3ec-staging && mvn -B -ntp install -DskipTests
	@echo "[JAVA V3] S3 Encryption Client library installed successfully!"

# Install dependencies using Gradle
install: s3ec-staging
	@echo "[JAVA V3] Installing Java dependencies..."
	@chmod +x ./gradlew
	@./gradlew build
	@echo "[JAVA V3] Dependencies installed successfully!"

# Clean Gradle artifacts
clean:
	@echo "[JAVA V3] Cleaning Gradle artifacts..."
	@./gradlew clean
	@echo "[JAVA V3] Clean completed!"

# Run the example with default arguments
run: install
	@echo "[JAVA V3] Running S3 Encryption Client v3 Java example..."
	@echo "[JAVA V3] Bucket: $(BUCKET_NAME)"
	@echo "[JAVA V3] Object Key: $(OBJECT_KEY)"
	@echo "[JAVA V3] KMS Key ID: $(KMS_KEY_ID)"
	@echo "[JAVA V3] Region: $(AWS_REGION)"
	@echo ""
	@./gradlew run --args="$(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID) $(AWS_REGION)"

# Run with custom arguments
# Usage: make run-custom BUCKET_NAME=my-bucket OBJECT_KEY=my-key KMS_KEY_ID=my-kms-key AWS_REGION=my-region
run-custom: install
	@./gradlew run --args="$(BUCKET_NAME) $(OBJECT_KEY) $(KMS_KEY_ID) $(AWS_REGION)"

# Show help
help:
	@echo "S3 Encryption Client Java v3 Example Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  s3ec-staging - Install S3 Encryption Client library from source"
	@echo "  install    - Install Java dependencies using Gradle"
	@echo "  run        - Install dependencies and run the example with default parameters"
	@echo "  run-custom - Install dependencies and run with custom parameters"
	@echo "  clean      - Remove Gradle artifacts"
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
	@echo "  - S3 Encryption Client v3 library installed in local Maven repository"
	@echo "    (Install by running: cd s3ec-staging && mvn install)"
