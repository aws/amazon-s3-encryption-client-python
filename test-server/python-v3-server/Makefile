# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8081

start-server:
	@echo "Starting Python V3 server..."
	python -m venv .venv
	.venv/bin/python -m ensurepip
	.venv/bin/python -m pip install -e .
	.venv/bin/python -m pip install -e ../..
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	.venv/bin/python src/main.py & echo $$! > $(PID_FILE)
	@echo "Python V3 server starting..."

stop-server:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm $(PID_FILE); \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)
