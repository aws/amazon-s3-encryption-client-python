# Makefile for S3 Encryption Client Testing

.PHONY: build-server start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8098

build-server:
	@echo "Building Ruby V2 server..."
	bundle install

start-server:
	@if [ -f $(PID_FILE) ]; then \
		echo "❌ Error: Server already running. Stop before starting."; \
		exit 1; \
	fi;
	@echo "Starting Ruby V2 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	PORT=$(PORT) bundle exec ruby app.rb > server.log 2>&1 & echo $$! > $(PID_FILE)
	@echo "Ruby V2 server starting..."

stop-server:
	@echo "Stopping server on port $(PORT)..."
	@lsof -ti:$(PORT) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE) ]; then \
		pkill -P $$(cat $(PID_FILE)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm -f $(PID_FILE); \
	fi
	@rm -f server.log
	@echo "Server stopped"

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
