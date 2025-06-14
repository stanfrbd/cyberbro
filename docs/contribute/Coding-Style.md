# Coding Style Policy

This document outlines the coding style and quality guidelines for this project. Adhering to these standards ensures consistency, readability, and security across the codebase.

## General Formatting

- **Line Length**: Limit all lines to a maximum of 120 characters.
- **Indentation**: Use 4 spaces per indentation level. Tabs are not allowed.
- **String Quotes**: Use double quotes (`"`) for all strings.
- **Line Endings**: Use `LF` line endings for cross-platform compatibility.

Formatting is enforced to align with [Black](https://black.readthedocs.io/en/stable/) conventions, including the use of spaces for indentation and double quotes for strings.

## Linting and Static Analysis

We use [Ruff](https://docs.astral.sh/ruff/) as the primary linter, configured via `.ruff.toml`, to enforce the following rules:

- **Pycodestyle Errors (`E`)**: Enforce PEP 8 style guidelines.
- **Pyflakes (`F`)**: Detect unused imports, variables, and other common issues.
- **Pywicked (`W`)**: Additional style checks.
- **Flake8-Bugbear (`B`)**: Catch potential bugs and design issues.
- **Flake8-Comprehensions (`C4`)**: Improve list, set, and dictionary comprehensions.
- **Isort (`I`)**: Ensure imports are sorted and organized.
- **PEP8-Naming (`N`)**: Enforce consistent naming conventions.
- **Flake8-Pygments (`PGH`)**: Highlight syntax issues.
- **Flake8-Pytest-Helper (`PTH`)**: Enforce pytest-specific best practices.
- **Flake8-Return (`RET`)**: Ensure consistent return statements (except `RET501` which is ignored).
- **Ruff-Specific Rules (`RUF`)**: Additional rules specific to Ruff.
- **Flake8-Simplify (`SIM`)**: Simplify redundant code patterns.
- **Flake8-Pyupgrade (`UP`)**: Modernize Python syntax.
- **Flake8-2020 (`YTT`)**: Handle Python 2/3 compatibility issues.

### Exclusions

The following directories are excluded from linting and static analysis:

- `tests/**`
- `__pycache__/**`
- `docs/`
- `migrations/`

### Security Scanning

We use [Bandit](https://bandit.readthedocs.io/en/latest/) for static application security testing (SAST), configured via `.bandit.yml`. Bandit is set up to:

- Skip specific tests: `B101` (assert_used), `B113` (request_without_timeout)
- Exclude directories: `tests/`, `docs/`, `migrations/`
- Only scan `.py` files

## Pre-Commit Hooks

Automated checks are enforced using [pre-commit](https://pre-commit.com/), configured in `.pre-commit-config.yaml`. The following hooks are enabled:

- **trailing-whitespace**: Remove trailing whitespace
- **end-of-file-fixer**: Ensure files end with a newline
- **check-yaml**: Validate YAML files
- **ruff**: Lint Python files with Ruff (auto-fix enabled)
- **ruff-format**: Format Python files with Ruff
- **bandit**: Run Bandit for security checks

Some files and directories (e.g., `tests/`, `__version__.py`) are excluded from pre-commit checks.

## Setup Instructions

1. **Install development dependencies:**

    ```sh
    pip install -r requirements-dev.txt
    ```

2. **Install pre-commit hooks:**

    ```sh
    pre-commit install
    ```

    This ensures that Ruff, Bandit, and other checks run automatically on staged files before each commit.

3. **Run all pre-commit hooks manually (optional):**

    ```sh
    pre-commit run --all-files
    ```

## References

- [Ruff pre-commit integration](https://github.com/astral-sh/ruff-pre-commit)
- [Bandit documentation](https://bandit.readthedocs.io/en/latest/)
- [pre-commit documentation](https://pre-commit.com/)

By following these guidelines and using the provided tooling, we ensure our codebase remains clean, consistent, and secure.
