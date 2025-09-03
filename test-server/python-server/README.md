# Python Server

A FastAPI-based Python server implementation.

## Setup

1. Install uv (if not already installed):
```bash
pip install uv
```

2. Create a virtual environment and install dependencies:
```bash
uv venv
source .venv/bin/activate
uv pip install -e .
uv pip install -e ../..
```

## Development

- Source code is in the `src` directory
- Tests are in the `tests` directory
- Use `source .venv/bin/activate` to activate the virtual environment
- Use `uv pip install {package}` to add new dependencies
- Use `uv pip install {package} --dev` to add new development dependencies

## Running the Server

```bash
.venv/bin/python src/main.py
```

The server will start on `http://localhost:8081`.

## Running Tests

```bash
.venv/bin/python -m pytest
```
