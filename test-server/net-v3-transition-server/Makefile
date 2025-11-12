# Makefile for S3 Encryption Client .NET Testing

.PHONY: build-server start-server stop-server wait-for-server

PID_FILE_NET_V3_TRANSITION := net-v3-transition-server.pid
PORT_NET_V3_TRANSITION := 8100

build-server:
	@echo "Building .NET V3 transition server..."
	dotnet build

start-server:
	$(MAKE) start-net-v3-transition-server

stop-server:
	@echo "Stopping .NET V3 Transition server on port $(PORT_NET_V3_TRANSITION)..."
	@lsof -ti:$(PORT_NET_V3_TRANSITION) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE_NET_V3_TRANSITION) ]; then \
		pkill -P $$(cat $(PID_FILE_NET_V3_TRANSITION)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE_NET_V3_TRANSITION)) 2>/dev/null || true; \
		rm -f $(PID_FILE_NET_V3_TRANSITION); \
	fi
	@rm -f server.log
	@echo "Server stopped"

# Start .NET V3 transition server in background
start-net-v3-transition-server:
	@echo "Starting .NET V3 transition server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	dotnet run > server.log 2>&1 & echo $$! > net-v3-transition-server.pid
	@echo ".NET V3 transition server starting..."

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V3_TRANSITION)

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
