# Go Server Makefile

.PHONY: build run clean test deps

# Default target
all: build

# Build the Go server
build:
	go build -o bin/go-server .

# Run the server
run: build
	./bin/go-server

# Install dependencies
deps:
	go mod tidy
	go mod download

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Run tests (when we add them)
test:
	go test ./...

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Development server with auto-reload (requires air)
dev:
	air

# Check for security vulnerabilities
security:
	gosec ./...

# Generate coverage report
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Help
help:
	@echo "Available targets:"
	@echo "  build     - Build the Go server"
	@echo "  run       - Build and run the server"
	@echo "  deps      - Install dependencies"
	@echo "  clean     - Clean build artifacts"
	@echo "  test      - Run tests"
	@echo "  fmt       - Format code"
	@echo "  vet       - Vet code"
	@echo "  lint      - Run linter"
	@echo "  dev       - Run development server with auto-reload"
	@echo "  security  - Check for security vulnerabilities"
	@echo "  coverage  - Generate test coverage report"
	@echo "  help      - Show this help message"
