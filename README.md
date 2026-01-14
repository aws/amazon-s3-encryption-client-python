# Amazon S3 Encryption Client Python

This library provides an S3 client that supports client-side encryption.

## Development

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) for package and project management

### Setup

Install dependencies:

```bash
make install
```

### Testing

Run all tests:

```bash
make test
```

Run unit tests only:

```bash
make test-unit
```

Run integration tests only:

```bash
make test-integration
```

### Code Quality

This project uses [Black](https://black.readthedocs.io/) for code formatting, [isort](https://pycqa.github.io/isort/) for import sorting, and [Flake8](https://flake8.pycqa.org/) for linting.

Check code quality:

```bash
make lint
```

Format code with Black and isort:

```bash
make format
```

Clean up cache files:

```bash
make clean
```

#### Linting Standards

The project is configured with Black, isort, and Flake8 to enforce consistent code style and quality. Currently, Flake8 is set to report issues but not fail the build, allowing for gradual adoption of linting standards.

Common Flake8 issues in the codebase include:

- **Missing docstrings** (D100-D104): Add docstrings to modules, classes, and functions
- **Docstring formatting** (D200, D212, D415): Follow Google docstring style
- **Line length** (E501): Keep lines under 100 characters
- **Unused imports** (F401): Remove unused imports
- **Unused variables** (F841): Remove or use assigned variables
- **Code complexity** (C901): Refactor complex functions

When contributing to this project, please try to fix linting issues in the files you modify.

### Pull Request Command
While this project is in development,
it is useful to use `gh pr` to create the pull-requests,
so they can be associated with the GitHub project,
as compared to the FireEgg event.

```sh
gh pr create -B staging -p "S3EC-Python" -f 
```

