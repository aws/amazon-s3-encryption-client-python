# S3EC Generalized Robust Test Framework Machine

Or G-RTFM. Or something. 

## What?

This is an attempt at writing a write-once, run-multiple test server. 

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

# Run in CI mode (start servers, run tests, stop servers)
make ci

# Start Python and Java servers
make start-servers

# Run Java tests
make run-tests

# Stop running servers
make stop-servers

# Stop servers and clean up logs
make clean

# Show help message
make help
```

The `ci` target is specifically designed for GitHub Actions workflows, ensuring that servers are properly started, tests are run, and resources are cleaned up afterward.
