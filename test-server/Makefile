# Makefile for S3 Encryption Client Testing

.PHONY: all start-servers run-tests stop-servers clean ci check-env help

# Default target
all: start-servers run-tests

# CI target for GitHub Actions
ci: start-servers run-tests stop-servers

SERVER_DIRS := $(shell find . -maxdepth 1 -type d -name '*-server' | sed 's|^\./||' | sort)

# Start all servers in parallel
start-servers:
	@echo "Starting all servers..."
	@for dir in $(SERVER_DIRS); do \
		if [ -f $$dir/Makefile ]; then \
			echo "Starting server in $$dir..."; \
			$(MAKE) -C $$dir start-server; \
		else \
			echo "❌ Error: no Makefile found in $$dir"; \
			exit 1; \
		fi; \
	done;
	@echo "Waiting for servers to start..."
	@for dir in $(SERVER_DIRS); do \
		echo "Waiting for server in $$dir..."; \
		$(MAKE) -C $$dir wait-for-server; \
	done


# Run the Java tests
run-tests:
	@echo "Running Java tests..."
	@echo "Exporting environment variables from servers to tests..."
	@# Extract AWS environment variables from the current shell and pass them to the tests
	cd java-tests && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./gradlew --build-cache --rerun-tasks --parallel integ
	@echo "Tests completed successfully"

# Stop the servers
stop-servers:
	@echo "Stopping servers..."
	@for dir in $(SERVER_DIRS); do \
		echo "Starting server in $$dir..."; \
		$(MAKE) -C $$dir stop-server; \
	done
	@echo "Servers stopped"

# Help target
help:
	@echo "Available targets:"
	@echo "  all                     : Start servers and run tests (default, output to stdout)"
	@echo "  ci                      : Run in CI mode (start servers, run tests, stop servers)"
	@echo "  start-servers           : Start all servers in parallel"
	@echo "  run-tests               : Run Java tests"
	@echo "  stop-servers            : Stop running servers"
	@echo "  check-env               : Check if required environment variables are set"
	@echo "  help                    : Show this help message"

# Check if required environment variables are set
check-env:
	@echo "Checking required environment variables..."
	@if [ -z "$$AWS_ACCESS_KEY_ID" ]; then echo "AWS_ACCESS_KEY_ID is not set"; else echo "AWS_ACCESS_KEY_ID is set"; fi
	@if [ -z "$$AWS_SECRET_ACCESS_KEY" ]; then echo "AWS_SECRET_ACCESS_KEY is not set"; else echo "AWS_SECRET_ACCESS_KEY is set"; fi
	@if [ -z "$$AWS_SESSION_TOKEN" ]; then echo "AWS_SESSION_TOKEN is not set"; else echo "AWS_SESSION_TOKEN is set"; fi
	@if [ -z "$$AWS_REGION" ]; then echo "AWS_REGION is not set (will use us-west-2 as default)"; else echo "AWS_REGION is set to $$AWS_REGION"; fi

TIMEOUT := 360

wait-for-port:
	@if [ -z "$(PORT)" ]; then \
		echo "❌ Error: PORT is required"; \
		exit 1; \
	fi
	@for i in $$(seq 1 $(TIMEOUT)); do \
		if nc -z localhost $$PORT; then \
			echo "Ports are open, waiting for servers to initialize..."; \
			sleep 5; \
			echo "Server at $$PORT is ready!"; \
			break; \
		fi; \
		if [ $$i -eq $(TIMEOUT) ]; then \
			echo "Timeout waiting for $$PORT start"; \
			exit 1; \
		fi; \
		echo "Waiting for $$PORT to start ($$i/$(TIMEOUT))..."; \
		sleep 1; \
	done
