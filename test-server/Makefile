# Makefile for S3 Encryption Client Testing

.PHONY: all start-servers start-python-server start-java-server start-go-server run-tests stop-servers clean ci check-env help

# Default target
all: start-servers run-tests

# CI target for GitHub Actions
ci: start-servers run-tests stop-servers


# Start Python server in background
start-python-server:
	@echo "Starting Python server..."
	cd python-server && \
	python -m venv .venv && \
	.venv/bin/python -m ensurepip && \
	.venv/bin/python -m pip install -e . && \
	.venv/bin/python -m pip install -e ../.. && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	.venv/bin/python src/main.py & echo $$! > ../python-server.pid
	@echo "Python server starting..."

# Start Java server in background
start-java-server:
	@echo "Starting Java server..."
	cd java-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./gradlew --build-cache --parallel run & echo $$! > ../java-server.pid
	@echo "Java server starting..."

# Start Go server in background
start-go-server:
	@echo "Starting Go server..."
	cd go-server && \
	go mod tidy && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	go run . & echo $$! > ../go-server.pid
	@echo "Go server starting..."

# Start all servers in parallel
start-servers:
	@echo "Starting servers in parallel..."
	@$(MAKE) -j3 start-python-server start-java-server start-go-server
	@echo "Waiting for servers to be ready..."
	@for i in $$(seq 1 360); do \
		if nc -z localhost 8080 && nc -z localhost 8081 && nc -z localhost 8082; then \
			echo "Ports are open, waiting for servers to initialize..."; \
			sleep 5; \
			echo "All servers are ready!"; \
			break; \
		fi; \
		if [ $$i -eq 360 ]; then \
			echo "Timeout waiting for servers to start"; \
			exit 1; \
		fi; \
		echo "Waiting for servers to start ($$i/360)..."; \
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
	./gradlew --build-cache --parallel -i integ
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
	@if [ -f go-server.pid ]; then \
		kill $$(cat go-server.pid) 2>/dev/null || true; \
		rm go-server.pid; \
	fi
	@echo "Servers stopped"

# Clean up logs and pid files
clean: stop-servers
	@echo "Cleaning up..."
	@rm -f python-server.log java-server.log go-server.log
	@echo "Cleanup complete"

# Help target
help:
	@echo "Available targets:"
	@echo "  all                : Start servers and run tests (default, output to stdout)"
	@echo "  ci                 : Run in CI mode (start servers, run tests, stop servers)"
	@echo "  start-servers      : Start Python, Java, and Go servers in parallel (output to stdout)"
	@echo "  start-python-server: Start only the Python server"
	@echo "  start-java-server  : Start only the Java server"
	@echo "  start-go-server    : Start only the Go server"
	@echo "  run-tests          : Run Java tests"
	@echo "  stop-servers       : Stop running servers"
	@echo "  clean              : Stop servers and clean up logs"
	@echo "  check-env          : Check if required environment variables are set"
	@echo "  help               : Show this help message"

# Check if required environment variables are set
check-env:
	@echo "Checking required environment variables..."
	@if [ -z "$$AWS_ACCESS_KEY_ID" ]; then echo "AWS_ACCESS_KEY_ID is not set"; else echo "AWS_ACCESS_KEY_ID is set"; fi
	@if [ -z "$$AWS_SECRET_ACCESS_KEY" ]; then echo "AWS_SECRET_ACCESS_KEY is not set"; else echo "AWS_SECRET_ACCESS_KEY is set"; fi
	@if [ -z "$$AWS_SESSION_TOKEN" ]; then echo "AWS_SESSION_TOKEN is not set"; else echo "AWS_SESSION_TOKEN is set"; fi
	@if [ -z "$$AWS_REGION" ]; then echo "AWS_REGION is not set (will use us-west-2 as default)"; else echo "AWS_REGION is set to $$AWS_REGION"; fi
