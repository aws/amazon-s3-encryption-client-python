# Makefile for S3 Encryption Client .NET Testing

.PHONY: build-server start-server stop-server wait-for-server

PID_FILE_NET_V2 := net-v2-server.pid
PID_FILE_NET_V3 := net-v3-server.pid
PORT_NET_V2 := 8083
PORT_NET_V3 := 8084

build-server:
	@echo "Building .NET V2 and V3 servers..."
	rm -rf obj/v2 bin/v2 obj/v3 bin/v3
	dotnet build -p:S3EncryptionVersion=v2 -o bin/v2 -p:BaseIntermediateOutputPath=obj/v2/
	dotnet build -p:S3EncryptionVersion=v3 -o bin/v3 -p:BaseIntermediateOutputPath=obj/v3/

start-server:
	$(MAKE) start-net-v2-server; \
	$(MAKE) start-net-v3-server;

stop-server:
	@echo "Stopping .NET V2 server on port $(PORT_NET_V2)..."
	@lsof -ti:$(PORT_NET_V2) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE_NET_V2) ]; then \
		pkill -P $$(cat $(PID_FILE_NET_V2)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE_NET_V2)) 2>/dev/null || true; \
		rm -f $(PID_FILE_NET_V2); \
	fi
	@rm -f net-v2-server.log
	@echo "Stopping .NET V3 server on port $(PORT_NET_V3)..."
	@lsof -ti:$(PORT_NET_V3) | xargs kill -9 2>/dev/null || true
	@if [ -f $(PID_FILE_NET_V3) ]; then \
		pkill -P $$(cat $(PID_FILE_NET_V3)) 2>/dev/null || true; \
		kill -9 $$(cat $(PID_FILE_NET_V3)) 2>/dev/null || true; \
		rm -f $(PID_FILE_NET_V3); \
	fi
	@rm -f net-v3-server.log
	@echo "Servers stopped"

# Start .NET V2 server in background
start-net-v2-server:
	@echo "Starting .NET V2 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	dotnet bin/v2/NetV2V3Server.dll > net-v2-server.log 2>&1 & echo $$! > net-v2-server.pid
	@echo ".NET V2 server starting..."

# Start .NET V3 server in background
start-net-v3-server:
	@echo "Starting .NET V3 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	dotnet bin/v3/NetV2V3Server.dll > net-v3-server.log 2>&1 & echo $$! > net-v3-server.pid
	@echo ".NET V3 server starting..."

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V2)
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V3)

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
