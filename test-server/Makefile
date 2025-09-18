# Makefile for S3 Encryption Client Testing

.PHONY: all start-servers start-python-v3-server start-java-v3-server start-go-v3-server run-tests stop-servers clean ci check-env help

# Default target
all: start-servers run-tests

# CI target for GitHub Actions
ci: start-servers run-tests stop-servers


# Start Python server in background
start-python-v3-server:
	@echo "Starting Python V3 server..."
	cd python-v3-server && \
	python -m venv .venv && \
	.venv/bin/python -m ensurepip && \
	.venv/bin/python -m pip install -e . && \
	.venv/bin/python -m pip install -e ../.. && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	.venv/bin/python src/main.py & echo $$! > ../python-v3-server.pid
	@echo "Python server starting..."

# Start Java server in background
start-java-v3-server:
	@echo "Starting Java V3 server..."
	cd java-v3-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./gradlew --build-cache --parallel run & echo $$! > ../java-v3-server.pid
	@echo "Java server starting..."

# Start Go server in background
start-go-v3-server:
	@echo "Starting Go V3 server..."
	cd go-v3-server && \
	go mod tidy && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	go run . & echo $$! > ../go-v3-server.pid
	@echo "Go server starting..."

# Start all servers in parallel
start-servers:
	@echo "Starting servers in parallel..."
	@$(MAKE) -j3 start-python-v3-server start-java-v3-server start-go-v3-server
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
	./gradlew --build-cache --rerun-tasks --parallel integ
	@echo "Tests completed successfully"

# Stop the servers
stop-servers:
	@echo "Stopping servers..."
	@if [ -f python-v3-server.pid ]; then \
		kill $$(cat python-v3-server.pid) 2>/dev/null || true; \
		rm python-v3-server.pid; \
	fi
	@if [ -f java-v3-server.pid ]; then \
		kill $$(cat java-v3-server.pid) 2>/dev/null || true; \
		rm java-v3-server.pid; \
	fi
	@if [ -f go-v3-server.pid ]; then \
		kill $$(cat go-v3-server.pid) 2>/dev/null || true; \
		rm go-v3-server.pid; \
	fi
	@echo "Servers stopped"

install-cpp-dependencies:
	brew install libmicrohttpd nlohmann-json ossp-uuid aws-sdk-cpp

start-cpp-v2-server:
	cd cpp-v2-server && mkdir -p build && cd build && cmake .. && make && ./s3ec-server

# Clean up logs and pid files
clean: stop-servers
	@echo "Cleaning up..."
	@rm -f python-v3-server.log java-v3-server.log go-v3-server.log
	@echo "Cleanup complete"

# Help target
help:
	@echo "Available targets:"
	@echo "  all                     : Start servers and run tests (default, output to stdout)"
	@echo "  ci                      : Run in CI mode (start servers, run tests, stop servers)"
	@echo "  start-servers           : Start all servers in parallel"
	@echo "  start-python-v3-server  : Start only the Python V3 server"
	@echo "  start-java-v3-server    : Start only the Java V3 server"
	@echo "  start-go-v3-server      : Start only the Go V3 server"
	@echo "  start-cpp-v2-server     : Start only the C++ V2 server"
	@echo "  install-cpp-dependencies: use brew to install things necessary for start-cpp-v2-server"
	@echo "  run-tests               : Run Java tests"
	@echo "  stop-servers            : Stop running servers"
	@echo "  clean                   : Stop servers and clean up logs"
	@echo "  check-env               : Check if required environment variables are set"
	@echo "  help                    : Show this help message"

# Check if required environment variables are set
check-env:
	@echo "Checking required environment variables..."
	@if [ -z "$$AWS_ACCESS_KEY_ID" ]; then echo "AWS_ACCESS_KEY_ID is not set"; else echo "AWS_ACCESS_KEY_ID is set"; fi
	@if [ -z "$$AWS_SECRET_ACCESS_KEY" ]; then echo "AWS_SECRET_ACCESS_KEY is not set"; else echo "AWS_SECRET_ACCESS_KEY is set"; fi
	@if [ -z "$$AWS_SESSION_TOKEN" ]; then echo "AWS_SESSION_TOKEN is not set"; else echo "AWS_SESSION_TOKEN is set"; fi
	@if [ -z "$$AWS_REGION" ]; then echo "AWS_REGION is not set (will use us-west-2 as default)"; else echo "AWS_REGION is set to $$AWS_REGION"; fi
