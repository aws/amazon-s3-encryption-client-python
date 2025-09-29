# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE := server.pid
PORT := 8086

start-server:
	@if [ -f $(PID_FILE) ]; then \
		echo "❌ Error: Server already running. Stop before starting."; \
		exit 1; \
	fi;
	@echo "Starting Ruby V2 server..."
	bundle install
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	bundle exec ruby app.rb & echo $$! > server.pid
	@echo "Ruby V2 server starting..."

stop-server:
	@if [ -f server.pid ]; then \
		kill $$(cat server.pid) 2>/dev/null || true; \
		rm server.pid; \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=8086

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
