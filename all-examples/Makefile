# Makefile for S3 Encryption Client Examples
# Runs make commands across all language/version directories

# Default target
.PHONY: all install clean run help list-examples

# Find all directories with Makefiles
EXAMPLE_DIRS := $(shell find . -name Makefile -not -path "./Makefile" | xargs dirname | sed 's|^\./||' | $(if $(FILTER),grep -E "$$(echo '$(FILTER)' | sed 's/,/|/g')",cat) | sort)

all: install

# Install dependencies for all examples
install:
	@echo "Installing dependencies for all examples..."
	@failed=0; \
	for dir in $(EXAMPLE_DIRS); do \
		echo ""; \
		echo "=== Installing dependencies in $$dir ==="; \
		if (cd $$dir && $(MAKE) install); then \
			echo "✓ Successfully installed dependencies in $$dir"; \
		else \
			echo "✗ Failed to install dependencies in $$dir"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		echo "All dependencies installed successfully!"; \
	else \
		echo "$$failed example(s) failed to install dependencies"; \
		exit 1; \
	fi

# Clean all examples
clean:
	@echo "Cleaning all examples..."
	@failed=0; \
	for dir in $(EXAMPLE_DIRS); do \
		echo ""; \
		echo "=== Cleaning $$dir ==="; \
		if (cd $$dir && $(MAKE) clean); then \
			echo "✓ Successfully cleaned $$dir"; \
		else \
			echo "✗ Failed to clean $$dir"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		echo "All examples cleaned successfully!"; \
	else \
		echo "$$failed example(s) failed to clean"; \
		exit 1; \
	fi

# Run all examples with default parameters
run:
	@echo "Running all examples with default parameters..."
	@failed=0; \
	for dir in $(EXAMPLE_DIRS); do \
		echo ""; \
		echo "=== Running example in $$dir ==="; \
		if (cd $$dir && $(MAKE) run); then \
			echo "✓ Successfully ran example in $$dir"; \
		else \
			echo "✗ Failed to run example in $$dir"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	echo ""; \
	if [ $$failed -eq 0 ]; then \
		echo "All examples completed successfully!"; \
	else \
		echo "$$failed example(s) failed to run"; \
		exit 1; \
	fi

# List all available examples
list-examples:
	@echo "Available S3 Encryption Client examples:"
	@for dir in $(EXAMPLE_DIRS); do \
		echo "  $$dir"; \
	done

# Show help
help:
	@echo "S3 Encryption Client Examples Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install dependencies for all examples"
	@echo "  run           - Run all examples with default parameters"
	@echo "  clean         - Clean all examples"
	@echo "  list-examples - List all available example directories"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Filtering examples:"
	@echo "  Use FILTER to run commands on specific examples:"
	@echo "  make install FILTER=go        # Only Go examples"
	@echo "  make run FILTER=v4            # Only v4 examples"
	@echo "  make clean FILTER=go/v3,ruby  # Go v3 and Ruby examples"
	@echo ""
	@echo "Individual example usage:"
	@echo "  To work with a specific example, cd into its directory and use its Makefile:"
	@echo "  cd go/v4 && make run"
	@echo "  cd ruby/v2 && make install"
	@echo ""
	@echo "Available examples:"
	@for dir in $(EXAMPLE_DIRS); do \
		echo "  $$dir"; \
	done
