# Makefile for S3 Encryption Client .NET Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE_NET_V4 := net-V4-server.pid
PORT_NET_V4 := 8090

build-server:
	@echo "Building .NET V4 improved server..."
	dotnet build

start-server:
	$(MAKE) start-net-V4-server; 

stop-server:
	@echo "Stopping .NET V4 Improved server on port $(PORT_NET_V4)..."
	@lsof -ti:$(PORT_NET_V4) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE_NET_V4) ]; then \
		pkill -P $$(cat $(PID_FILE_NET_V4)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE_NET_V4)) 2>/dev/null || true; \
		rm -f $(PID_FILE_NET_V4); \
	fi
	@rm -f server.log
	@echo "Server stopped"

# Start .NET V4 server in background
# This builds first into bin/V4 and runs through dll 
# to avoid simultaneous dotnet run conflict
start-net-V4-server:
	@echo "Starting .NET V4 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	dotnet run & echo $! > $(PID_FILE_NET_V4)
	@echo ".NET V4 server starting..."

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V4) 

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
