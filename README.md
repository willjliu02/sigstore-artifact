# Python Rekor Monitor Template

Verify artifact signatures and Rekor transparency log inclusion and consistency
proofs. This project is coursework for NYU CS-GY 9223 Software Supply Chain Security.

## Installation

Install Python 3.14 or later and Poetry, then run from the repository root:

```bash
poetry install --with dev
```

## Usage

```bash
# Show all options.
poetry run python -m sscs_hw.main --help

# Fetch the latest Rekor checkpoint.
poetry run python -m sscs_hw.main -c

# Verify an artifact using its Rekor log index.
poetry run python -m sscs_hw.main --inclusion LOG_INDEX --artifact PATH_TO_ARTIFACT

# Check consistency against a previous checkpoint.
poetry run python -m sscs_hw.main --consistency --tree-id TREE_ID --tree-size TREE_SIZE --root-hash ROOT_HASH
```

Replace the uppercase placeholders with your values. Add `--debug` for diagnostic
output. Rekor queries require an internet connection.

## Development

Install TruffleHog locally, then enable the pre-commit secret scan:

```bash
poetry run pre-commit install
```

Run formatting, static analysis, and the offline tests before submitting changes:

```bash
poetry run ruff format .
poetry run ruff check .
poetry run mypy src/sscs_hw
poetry run bandit -r src tests scripts
poetry run pytest --cov=sscs_hw --cov-report=term-missing --cov-fail-under=75
```

Tests mock Rekor HTTP responses and must maintain at least 75% coverage.
See CONTRIBUTING.md for contribution guidelines and SECURITY.md for reporting
vulnerabilities.
