# Makefile for S3 Encryption Client Testing

.PHONY: build-server start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8097

build/s3ec-server: 
	mkdir -p build && cd build && cmake ..

build-server: | build/s3ec-server
	@echo "Building Cpp transition server..."
	cd build && $(MAKE)

start-server:
	@echo "Starting Cpp transition server..."
	cd build && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./s3ec-server > server.log 2>&1 & echo $$! > ../$(PID_FILE)
	@echo "Cpp transition server starting..."

stop-server:
	@echo "Stopping server on port $(PORT)..."
	@lsof -ti:$(PORT) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE) ]; then \
		pkill -P $$(cat $(PID_FILE)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm -f $(PID_FILE); \
	fi
	@rm -f build/server.log
	@echo "Server stopped"

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)
