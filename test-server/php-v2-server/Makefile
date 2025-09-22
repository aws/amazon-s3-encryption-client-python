# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8087

start-server:
	@echo "Starting PHP V2 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	composer run start & echo $$! > $(PID_FILE)
	@echo "PHP V2 server starting..."

stop-server:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm $(PID_FILE); \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)
