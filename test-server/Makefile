# Makefile for S3 Encryption Client Testing

.PHONY: all start-servers run-tests stop-servers clean ci check-env help

# Default target
all: start-servers run-tests

# CI target for GitHub Actions
ci: start-servers run-tests stop-servers

# Start both servers in background with output to stdout (default for debugging)
start-servers:
	@echo "Starting Python server..."
	cd python-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	poetry install --no-interaction && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	poetry run python src/main.py & echo $$! > ../python-server.pid
	@echo "Starting Java server..."
	cd java-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./gradlew run & echo $$! > ../java-server.pid
	@echo "Waiting for servers to be ready..."
	@for i in $$(seq 1 60); do \
		if nc -z localhost 8080 && nc -z localhost 8081; then \
			echo "Ports are open, waiting for servers to initialize..."; \
			sleep 5; \
			echo "Both servers are ready!"; \
			break; \
		fi; \
		if [ $$i -eq 60 ]; then \
			echo "Timeout waiting for servers to start"; \
			exit 1; \
		fi; \
		echo "Waiting for servers to start ($$i/60)..."; \
		sleep 1; \
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
	./gradlew integ
	@echo "Tests completed successfully"

# Stop the servers
stop-servers:
	@echo "Stopping servers..."
	@if [ -f python-server.pid ]; then \
		kill $$(cat python-server.pid) 2>/dev/null || true; \
		rm python-server.pid; \
	fi
	@if [ -f java-server.pid ]; then \
		kill $$(cat java-server.pid) 2>/dev/null || true; \
		rm java-server.pid; \
	fi
	@echo "Servers stopped"

# Clean up logs and pid files
clean: stop-servers
	@echo "Cleaning up..."
	@rm -f python-server.log java-server.log
	@echo "Cleanup complete"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          : Start servers and run tests (default, output to stdout)"
	@echo "  ci           : Run in CI mode (start servers, run tests, stop servers)"
	@echo "  start-servers: Start Python and Java servers (output to stdout)"
	@echo "  run-tests    : Run Java tests"
	@echo "  stop-servers : Stop running servers"
	@echo "  clean        : Stop servers and clean up logs"
	@echo "  check-env    : Check if required environment variables are set"
	@echo "  help         : Show this help message"

# Check if required environment variables are set
check-env:
	@echo "Checking required environment variables..."
	@if [ -z "$$AWS_ACCESS_KEY_ID" ]; then echo "AWS_ACCESS_KEY_ID is not set"; else echo "AWS_ACCESS_KEY_ID is set"; fi
	@if [ -z "$$AWS_SECRET_ACCESS_KEY" ]; then echo "AWS_SECRET_ACCESS_KEY is not set"; else echo "AWS_SECRET_ACCESS_KEY is set"; fi
	@if [ -z "$$AWS_SESSION_TOKEN" ]; then echo "AWS_SESSION_TOKEN is not set"; else echo "AWS_SESSION_TOKEN is set"; fi
	@if [ -z "$$AWS_REGION" ]; then echo "AWS_REGION is not set (will use us-west-2 as default)"; else echo "AWS_REGION is set to $$AWS_REGION"; fi
