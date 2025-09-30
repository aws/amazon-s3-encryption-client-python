# Makefile for S3 Encryption Client Testing

.PHONY: all start-servers run-tests stop-servers clean ci check-env help

# Default target
all: start-servers run-tests

# CI target for GitHub Actions
ci: start-servers run-tests stop-servers

SERVER_DIRS := $(shell find . -maxdepth 1 -type d -name '*-server' | sed 's|^\./||' | $(if $(FILTER),grep $(FILTER),cat) | sort)
# SERVER_DIRS := cpp-v3-server

START_SERVER_TARGETS := $(addprefix start-, $(SERVER_DIRS))
WAIT_SERVER_TARGETS := $(addprefix wait-, $(SERVER_DIRS))

# Start all servers in parallel
start-servers:
	@echo "Starting all servers..."
	$(MAKE) start-all-servers
	@echo "Waiting for servers to start..."
	@for dir in $(SERVER_DIRS); do \
		echo "Waiting for server in $$dir..."; \
		$(MAKE) -C $$dir wait-for-server; \
	done

start-all-servers: $(START_SERVER_TARGETS)

$(START_SERVER_TARGETS): start-%:
	@if [ -f $*/Makefile ]; then \
		echo "Starting server in $*..."; \
		$(MAKE) -C $* start-server; \
	else \
		echo "❌ Error: no Makefile found in $*"; \
		exit 1; \
	fi; \

wait-all-servers: $(WAIT_SERVER_TARGETS)

$(WAIT_SERVER_TARGETS): wait-%:
	@if [ -f $*/Makefile ]; then \
		echo "Waiting server in $*..."; \
		$(MAKE) -C $* wait-for-server; \
	else \
		echo "❌ Error: no Makefile found in $*"; \
		exit 1; \
	fi; \


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
	./gradlew --build-cache --info --parallel integ -Dtest.filter.servers="$(FILTER)"
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
		sleep 3; \
	done

# Here are some helpful curl commands
# that you can use to test specific test servers:
test-create-client:
	@echo $(PORT)
	@curl -X POST \
		-H "Content-Type: application/json" \
		-H "User-Agent: smithy-java/0.0.3 ua/2.1 os/macos#15.5 lang/java#23.0.2" \
		-d '{"config":{"enableLegacyUnauthenticatedModes":false,"enableDelayedAuthenticationMode":false,"enableLegacyWrappingAlgorithms":false,"keyMaterial":{"kmsKeyId":"arn:aws:kms:us-west-2:370957321024:alias/S3EC-Test-Server-Github-KMS-Key"}}}' \
		http://localhost:$(PORT)/client
