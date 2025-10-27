# Makefile for S3 Encryption Client .NET Testing

.PHONY: start-server stop-server wait-for-server

PID_FILE_NET_V3_TRANSITION := net-v3-transition-server.pid
PORT_NET_V3_TRANSITION := 8100

start-server:
	$(MAKE) start-net-v3-transition-server

stop-server:
	@if [ -f $(PID_FILE_NET_V3_TRANSITION) ]; then \
		kill $$(cat $(PID_FILE_NET_V3_TRANSITION)) 2>/dev/null || true; \
		rm $(PID_FILE_NET_V3_TRANSITION); \
	fi

# Start .NET V3 transition server in background
start-net-v3-transition-server:
	@echo "Starting .NET V3 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	dotnet run
	@echo ".NET V3 server starting..."

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT_NET_V3_TRANSITION)

duvet:
	duvet report

view-report-mac:
	open .duvet/reports/report.html
