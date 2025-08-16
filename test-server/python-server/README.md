# Python Server

A FastAPI-based Python server implementation.

## Setup

1. Install Poetry (if not already installed):
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

2. Install dependencies:
```bash
poetry install
```

## Development

- Source code is in the `src` directory
- Tests are in the `tests` directory
- Use `poetry shell` to activate the virtual environment
- Use `poetry add {package}` to add new dependencies
- Use `poetry add -D {package}` to add new development dependencies

## Running the Server

```bash
poetry run python src/main.py
```

The server will start on `http://localhost:8080` with the following endpoints:
- `GET /` - Welcome message
- `POST /get-beer` - Get a beer with specified ID
  - Request body: `{"Id": "string"}`
  - Response: `{"beer": "beer{Id}"}`
- `GET /docs` - Interactive API documentation (provided by Swagger UI)
- `GET /redoc` - Alternative API documentation (provided by ReDoc)

## Running Tests

```bash
poetry run pytest
