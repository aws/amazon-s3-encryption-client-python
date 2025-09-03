# S3EC Generalized Robust Test Framework Machine

Or G-RTFM. Or something. 

## What?

This is a write-once, run-multiple test server. 

## How? 

Use Smithy Java roughly as it is intended. 
That is, generate a client and a server which share a common model. 
Then, write more servers, either using the server codegen or parsing the JSON blobject by "hand".

## Running Tests

A Makefile is provided to simplify running the servers and tests. The Makefile handles starting both the Python and Java servers, running the tests, and cleaning up.

### Available Commands

```bash
# Start servers and run tests (default)
make

# Run in CI mode (start servers in parallel, run tests, stop servers)
make ci

# Start Python and Java servers in parallel
make start-servers

# Start only the Python server
make start-python-server

# Start only the Java server
make start-java-server

# Run Java tests
make run-tests

# Stop running servers
make stop-servers

# Stop servers and clean up logs
make clean

# Show help message
make help
```

The `ci` target is specifically designed for GitHub Actions workflows, ensuring that servers are properly started in parallel, tests are run, and resources are cleaned up afterward.

## Performance Optimizations

Performance optimizations have been implemented to speed up the test-server CI process, which was previously taking over 5 minutes to run. These optimizations include:

- Parallel server startup
- Gradle build caching and parallel execution
- Dependency caching in CI
- JVM optimizations

For detailed information about the optimizations, see [OPTIMIZATION.md](./OPTIMIZATION.md).
