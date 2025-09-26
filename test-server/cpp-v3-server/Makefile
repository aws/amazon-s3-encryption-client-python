# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8085

build/s3ec-server: 
	brew install libmicrohttpd nlohmann-json ossp-uuid
	git clone --recurse-submodules -b fire-egg-dev git@github.com:awslabs/aws-sdk-cpp-staging.git aws-sdk-cpp
	cd  aws-sdk-cpp
	mkdir -p build && cd build && cmake ..

start-server: | build/s3ec-server
	@echo "Starting Cpp V2 server..."
	cd build && make && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./s3ec-server & echo $$! > $(PID_FILE)
	@echo "Cpp V2 server starting..."

stop-server:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm $(PID_FILE); \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)
