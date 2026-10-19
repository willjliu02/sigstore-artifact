# Contributing

## Development Setup
Install the Python version required by the `pyproject.toml` and Poetry, then run:

`poetry install`

## Issues
For bugs, include reproduction steps, expected behavior, actual behavior, and your Python version.

For feature requests, explain the use case.

## Pull Requests
Create a branch, keep changes focused, and reference the relevant issue.

Describe the changes and how they were tested.

## Code Style and Checks
Format code with Ruff and run the checks before making your request:

```
poetry run ruff format .
poetry run ruff check .
poetry run mypy src/sscs_hw
poetry run bandit -r src scripts
```

## Tests
Add or update tests for behavior changes. Run:

```
poetry run pytest --cov=sscs_hw --cov-report=term-missin --cov-fail-under=75
```

Tests must pass, and overall coverage must remain at least 75%.