# Makefile for S3 Encryption Client .NET Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE_NET_V2 := net-v2-server.pid
PID_FILE_NET_V3 := net-v3-server.pid
PORT_NET_V2 := 8083
PORT_NET_V3 := 8084

start-server:
	$(MAKE) start-net-v2-server; \
	$(MAKE) start-net-v3-server;

stop-server:
	@if [ -f $(PID_FILE_NET_V2) ]; then \
		kill $$(cat $(PID_FILE_NET_V2)) 2>/dev/null || true; \
		rm $(PID_FILE_NET_V2); \
	fi
	@if [ -f $(PID_FILE_NET_V3) ]; then \
		kill $$(cat $(PID_FILE_NET_V3)) 2>/dev/null || true; \
		rm $(PID_FILE_NET_V3); \
	fi

# Start .NET V2 server in background
# This builds first into bin/v2 and runs through dll 
# to avoid simultaneous dotnet run conflict
start-net-v2-server:
	@echo "Starting .NET V2 server..."
	cd net-v2-v3-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	rm -rf obj/v2 bin/v2 && \
	dotnet build -p:S3EncryptionVersion=v2 -o bin/v2 -p:BaseIntermediateOutputPath=obj/v2/ && \
	dotnet bin/v2/NetV2V3Server.dll > ../net-v2-server.log 2>&1 & echo $$! > net-v2-server.pid
	@echo ".NET V2 server starting..."


# Start .NET V3 server in background
# This builds first into bin/v3 and runs through dll 
# to avoid simultaneous dotnet run conflict
start-net-v3-server:
	@echo "Starting .NET V3 server..."
	cd net-v2-v3-server && \
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	rm -rf obj/v3 bin/v3 && \
	dotnet build -p:S3EncryptionVersion=v3 -o bin/v3 -p:BaseIntermediateOutputPath=obj/v3/ && \
	dotnet bin/v3/NetV2V3Server.dll > ../net-v3-server.log 2>&1 & echo $$! > net-v3-server.pid
	@echo ".NET V3 server starting..."


wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V2) \
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V3)