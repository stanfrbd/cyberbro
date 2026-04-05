#!/usr/bin/env python3
"""Convert secrets.json to .env using a simple uppercase-key mapping.

Rules:
- keys from secrets.json are converted to uppercase env keys
- booleans are written as lowercase true/false
- gui_enabled_engines is written as a comma-separated list
- empty values are omitted from generated .env entries
- values containing '#', surrounding whitespace, backslashes, or newlines
  are double-quoted for safe round-tripping with python-dotenv
- output keeps only a minimal header comment block
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path

LOGGER = logging.getLogger(__name__)
ENV_ASSIGNMENT_RE = re.compile(r"^(?P<indent>\s*)#?\s*(?P<key>[A-Z0-9_]+)\s*=.*$")
NEEDS_QUOTING_RE = re.compile(r"[#\n\r\\\"']|^\s|\s$")

JsonPrimitive = str | int | float | bool | None
JsonValue = JsonPrimitive | list[JsonPrimitive]
JsonObject = dict[str, JsonValue]


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(description="Convert secrets.json into a .env file.")
    parser.add_argument("--secrets", type=Path, default=Path("secrets.json"))
    parser.add_argument("--env-sample", type=Path, default=Path(".env.sample"))
    parser.add_argument("--output", type=Path, default=Path(".env"))
    return parser.parse_args()


def load_json_object(path: Path) -> JsonObject:
    """Load a JSON object from disk and ensure it is a dictionary."""

    with path.open(encoding="utf-8") as handle:
        data: object = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"Top-level JSON in {path} must be an object.")

    result: JsonObject = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise ValueError(f"Invalid non-string key found in {path}.")
        result[key] = value
    return result


def quote_env_value(value: str) -> str:
    """Wrap a .env value in double quotes when necessary for safe round-tripping.

    python-dotenv treats unquoted '#' as a comment delimiter and strips
    surrounding whitespace from unquoted values. Values containing those
    characters, embedded quotes, backslashes, or newlines are double-quoted
    with proper escaping.
    """
    if not value or not NEEDS_QUOTING_RE.search(value):
        return value
    escaped = (
        value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    )
    return f'"{escaped}"'


def stringify_value(key: str, value: JsonValue) -> str:
    """Render JSON value to .env string."""

    if value is None:
        return ""
    if key == "GUI_ENABLED_ENGINES":
        if not isinstance(value, list):
            return ""
        return ",".join("" if item is None else str(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join("" if item is None else str(item) for item in value)
    return str(value)


def build_env_values(secrets: JsonObject) -> dict[str, str]:
    """Map secrets.json keys to uppercase environment variable names."""

    env_values: dict[str, str] = {}
    for key, value in secrets.items():
        env_key: str = key.upper()
        env_values[env_key] = stringify_value(env_key, value)
    return env_values


def extract_ordered_template_keys(template_lines: list[str]) -> list[str]:
    """Extract ordered env keys from .env.sample."""

    ordered_keys: list[str] = []
    seen: set[str] = set()
    for line in template_lines:
        match: re.Match[str] | None = ENV_ASSIGNMENT_RE.match(line)
        if not match:
            continue
        key: str = match.group("key")
        if key not in seen:
            ordered_keys.append(key)
            seen.add(key)
    return ordered_keys


def render_env_lines(ordered_keys: list[str], env_values: dict[str, str]) -> list[str]:
    """Render .env lines with minimal comments and template-based key ordering."""

    rendered: list[str] = [
        "# Docs: https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment/",
        "# Production security: avoid storing clear-text secrets on disk;",
        "# prefer secure environment variable injection.",
        "",
    ]
    used_keys: set[str] = set()

    for key in ordered_keys:
        value: str | None = env_values.get(key)
        if value is None or value == "":
            continue
        rendered.append(f"{key}={quote_env_value(value)}")
        used_keys.add(key)

    extra_keys: list[str] = sorted(set(env_values) - used_keys)
    for key in extra_keys:
        if env_values[key] == "":
            continue
        rendered.append(f"{key}={quote_env_value(env_values[key])}")

    return rendered


def main() -> int:
    """Entry point."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args: argparse.Namespace = parse_args()

    secrets: JsonObject = load_json_object(args.secrets)
    env_sample_lines: list[str] = args.env_sample.read_text(encoding="utf-8").splitlines()

    env_values: dict[str, str] = build_env_values(secrets)
    ordered_keys: list[str] = extract_ordered_template_keys(env_sample_lines)
    rendered_lines: list[str] = render_env_lines(ordered_keys, env_values)
    args.output.write_text("\n".join(rendered_lines) + "\n", encoding="utf-8")

    LOGGER.info("Generated %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
