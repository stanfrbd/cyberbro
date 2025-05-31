# Coding Style Policy
This document outlines the coding style guidelines for this project. 
Adhering to these standards ensures consistency and readability across the codebase.

## General Formatting

- **Line Length**: Limit all lines to a maximum of 120 characters.
- **Indentation**: Use 4 spaces per indentation level. Tabs are not allowed.
- **String Quotes**: Use double quotes (`"`) for all strings.
- **Line Endings**: Use `LF` line endings for cross-platform compatibility.

## Linting Rules

The following linting rules are enforced to maintain code quality:

- **Pycodestyle Errors (`E`)**: Enforce PEP 8 style guidelines.
- **Pyflakes (`F`)**: Detect unused imports, variables, and other common issues.
- **Pywicked (`W`)**: Additional style checks.
- **Flake8-Bugbear (`B`)**: Catch potential bugs and design issues.
- **Flake8-Comprehensions (`C4`)**: Improve list, set, and dictionary comprehensions.
- **Isort (`I`)**: Ensure imports are sorted and organized.
- **PEP8-Naming (`N`)**: Enforce consistent naming conventions.
- **Flake8-Pygments (`PGH`)**: Highlight syntax issues.
- **Flake8-Pytest-Helper (`PTH`)**: Enforce pytest-specific best practices.
- **Flake8-Return (`RET`)**: Ensure consistent return statements.
- **Ruff-Specific Rules (`RUF`)**: Additional rules specific to Ruff.
- **Flake8-Simplify (`SIM`)**: Simplify redundant code patterns.
- **Flake8-Pyupgrade (`UP`)**: Modernize Python syntax.
- **Flake8-2020 (`YTT`)**: Handle Python 2/3 compatibility issues.

## Exclusions

The following directories are excluded from linting:

- `tests/**`
- `__pycache__/**`

## Tools and Configuration

- **Ruff**: Used as the primary linter to enforce the above rules.
- **Black**: Formatting is aligned with Black's conventions, including the use of spaces for indentation and double quotes for strings.

By following these guidelines, we'll try our best to make good and readable code.

## Pre-Commit Configuration - Work in Progress

Setting up a pre-commit hook to ensure Ruff checks are applied before committing code is currently on our to-do list.  
We will provide the necessary `.pre-commit-config.yaml` configuration in the future. Once available, this configuration will help automatically run Ruff on staged files, preventing commits that violate the linting rules.

To try: https://github.com/astral-sh/ruff-pre-commit




