# Test Server Performance Optimizations

This document describes the performance optimizations implemented to speed up the test-server CI process.

## Overview

The test-server CI process involves starting both Python and Java servers, then running Java tests against them. The original implementation was taking over 5 minutes to run, with most of the time spent on Gradle/Java setup rather than the actual tests.

## Optimizations Implemented

### 1. Parallel Server Startup

- Added a new `start-servers-parallel` target in the Makefile that starts both Python and Java servers concurrently
- Created a new `ci-fast` target that uses parallel server startup

### 2. Gradle Performance Optimizations

- Added Gradle build caching
- Enabled parallel execution of Gradle tasks
- Configured the Gradle daemon for faster startup
- Optimized JVM memory settings
- Added incremental compilation
- Configured parallel test execution

### 3. CI Workflow Optimizations

- Added caching for Gradle dependencies and build outputs
- Added caching for Poetry dependencies
- Set environment variables to ensure Gradle optimizations are used

## Configuration Files

The following files were modified or created:

1. `test-server/Makefile`: Added new targets for parallel execution
2. `.github/workflows/test.yml`: Added caching and updated to use the optimized CI target
3. `test-server/java-server/gradle.properties` and `test-server/java-tests/gradle.properties`: Added performance settings
4. `test-server/gradle.init`: Added global Gradle settings for all projects

## Usage

### Local Development

For local development and testing, you can use the optimized targets:

```bash
# Run the optimized CI process
cd test-server && make ci-fast

# Start servers in parallel
cd test-server && make start-servers-parallel

# Run tests with optimized Gradle settings
cd test-server/java-tests && ./gradlew --build-cache --parallel integ
```

### CI Environment

The GitHub Actions workflow has been updated to use the optimized CI process automatically.

## Performance Impact

The optimizations are expected to significantly reduce the CI execution time by:

1. Running server startup in parallel (saves time equal to the slower of the two servers)
2. Caching Gradle and Poetry dependencies (saves download and resolution time)
3. Optimizing Gradle execution (reduces build time)
4. Enabling incremental compilation (reduces compilation time on subsequent runs)

## Troubleshooting

If you encounter issues with the optimized CI process:

1. Try running the original `ci` target: `make ci`
2. Check Gradle daemon logs: `cat ~/.gradle/daemon/*/daemon-*.out.log`
3. Disable specific optimizations by modifying the relevant configuration files
