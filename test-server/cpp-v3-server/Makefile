# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8091

build/s3ec-server: 
	mkdir -p build && cd build && cmake ..

start-server: | build/s3ec-server
	@echo "Building Cpp V3 server..."
	cd build && make
	@echo "Starting Cpp V3 server..."
	cd build && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./s3ec-server > server.log 2>&1 & echo $$! > ../$(PID_FILE)
	@echo "Cpp V3 server starting..."

stop-server:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm $(PID_FILE); \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
