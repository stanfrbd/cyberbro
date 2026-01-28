# AI Agent Instructions (AGENTS.md)

## 1. Project Context

**Goal:** A cybersecurity tool that extracts IoCs from garbage input and checks their reputation using multiple CTI services. This project aims to provide a simple and efficient way to check the reputation of observables using multiple services, without having to deploy a complex solution.
**Nature:** A python web application
**Key Operations:** Data input validation, data processing, data output

## 2. Tech Stack & Libraries

Use these specific libraries for their designated purposes. Do not introduce alternatives.

| Library               | Purpose                                                         |
| :-------------------- | :-------------------------------------------------------------- |
| **requests**          | HTTP client. Use for all API networking.                        |
| **tenacity**          | Retry logic for network requests.                               |
| **pydantic**          | Data validation and settings management.                        |
| **pydantic-settings** | Configuration management (.env loading).                        |
| **pytest**            | Testing framework. Use for unit testing.                        |
| **responses**         | Testing framework. Use for mocking API responses during testing |
| **flask**             | Web framework. Use for the web application.                     |
| **flask-sqlalchemy**  | ORM for database interactions.                                  |
| **gunicorn**          | WSGI HTTP server for running Flask applications.                |
| **beautifulsoup4**    | HTML parsing. Use for web scraping.                             |
| **Enum**              | (Stdlib) Use for values restricted to known subsets.            |

## 3. Tooling & Compliance

- **Linter/Formatter:** `ruff`. Ensure code passes default Ruff checks. Following the settings the ruff config file
- **Type Checker:** `basedpyright`. All code must be strictly typed.
- **Testing:** `pytest`.
- **venv:** Use `uv` to manage Python environments. Ensure all dependencies are installed in the virtual environment.
- **Requirements:** Use `requirements-dev.txt` for libraries that are only needed for development and testing.

## 4. Coding Standards

### Typing & Data Modeling

- **Strict Typing:** All variables, functions, and class methods **must** include type hints. Return types are mandatory.
- **Pydantic dataclasses:** All API payloads and internal data structures must be defined as Pydantic dataclasses or `BaseModel`.
- **Enums:** If a field has a known set of valid values (e.g., bookmark status, tags), explicitly define a Python `Enum`.
- **System States:** If an object has a known set of system stats, an Enum.Flag object should be defined and used throughout.

### Architecture & Style

- **Engine Design:** Cyberbro engines, located in the `engine/` directory, should be classes. Use the `crtsh` engine as an example.
- **Class modules:** Functions that only work with class members or operates on a shared state should be included in the Class as methods.
  - _Anti-pattern:_ Do not create a "Manager" class that only contains a single `run()` method. Make it a function.
  - _Anti-pattern:_ Do not inherit from `BaseModel` if creating a pydantic `@dataclass`.
- **Dependency Injection:** Inject dependencies (like API clients or config objects) into functions/classes rather than instantiating them inside. This simplifies mocking.
- **Single Responsibility:** A function should perform exactly one task. Break complex logic into smaller, composed functions.

### Logging & Output

- Use `logging` for application logs (debugging, info).

## 5. Testing Guidelines

- **Coverage:** Generate `pytest` test cases to cover at least 80% of a class and/or functions.
- **Focus:** Ensure tests cover critical paths and edge cases, and include coverage for valid and invalid inputs and consistent outputs.
- **Mocking:** Use `responses` to mock API responses when testing `requests` calls.
- **Fixtures:** Use Pytest fixtures for creating dummy Pydantic models or API clients.
- **Performance:** Use `@pytest.mark.parametrize` to test multiple scenarios.
- **Bugs:** When reviewing code for test development, if a bug or possible bug is identified in the source code, call it out in the prompt for evaluation and possible paths to resolution.
- **Ruff:** Run `ruff format` before running tests. This should help remove duplicate test runs.

## 6. Anti-Patterns (DO NOT DO)

- Do not use `typing.Any`.
- Do not use `print`; use `logging`.
- Do not write "god functions" that handle API fetching, parsing, and saving in one block.
