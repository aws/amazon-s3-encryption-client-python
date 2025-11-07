# Makefile for S3 Encryption Client Testing

.PHONY: start-server stop-server wait-for-server build-s3ec

PID_FILE := server.pid
PORT := 8088

build-s3ec:
	@echo "Building S3EC from source..."
	cd s3ec-staging && mvn --batch-mode -no-transfer-progress clean compile && mvn -B -ntp install -DskipTests
	@echo "S3EC build completed."

start-server: build-s3ec
	@echo "Starting Java V4 server..."
	AWS_ACCESS_KEY_ID="$$AWS_ACCESS_KEY_ID" \
	AWS_SECRET_ACCESS_KEY="$$AWS_SECRET_ACCESS_KEY" \
	AWS_SESSION_TOKEN="$$AWS_SESSION_TOKEN" \
	AWS_REGION="us-west-2" \
	./gradlew --build-cache --parallel run & echo $$! > $(PID_FILE)
	@echo "Java V4 server starting..."

stop-server:
	@if [ -f $(PID_FILE) ]; then \
		kill $$(cat $(PID_FILE)) 2>/dev/null || true; \
		rm $(PID_FILE); \
	fi

wait-for-server:
	$(MAKE) -C .. wait-for-port PORT=$(PORT)

duvet: | duvet_extract duvet_report

duvet_extract:
	rm -rf .duvet
	$(foreach file, $(shell find specification/s3-encryption -name '*.md' ! -path "*/materials/*"), duvet extract -o .duvet/requirements -f MARKDOWN $(file);)

duvet_report:
	duvet \
		report \
		--spec-pattern ".duvet/requirements/**/*.toml" \
		--source-pattern "s3ec-staging/src/**/*.java" \
		--source-pattern "s3ec-staging/compliance_exceptions/*.txt" \
		--html .duvet/reports/report.html

view-report-mac:
	open .duvet/reports/report.html