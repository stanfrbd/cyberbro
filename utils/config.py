import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


class QueryError(Exception):
    pass


@dataclass
class Secrets:
    """Dataclass to hold the secrets for the application."""

    abuseipdb: str = ""
    api_cache_timeout: int = 86400  # Default to 1 day
    api_prefix: str = "api"
    alienvault: str = ""
    criminalip_api_key: str = ""
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_falcon_base_url: str = "https://falcon.crowdstrike.com"
    dfir_iris_url: str = ""
    dfir_iris_api_key: str = ""
    flask_debug: bool = False
    flask_port: int = 5000
    flask_host: str = "127.0.0.1"
    google_cse_cx: str = ""
    google_cse_key: str = ""
    google_safe_browsing: str = ""
    gui_cache_timeout: int = 1800
    gui_enabled_engines: list[str] = field(default_factory=list)
    hister_base_url: str = ""
    hister_token: str = ""
    ipapi: str = ""
    ipinfo: str = ""
    max_form_memory_size: int = 1_048_576
    mde_client_id: str = ""
    mde_client_secret: str = ""
    mde_tenant_id: str = ""
    misp_api_key: str = ""
    misp_url: str = ""
    misp_feedback_server_url: str = ""
    misp_feedback_token: str = ""
    opencti_api_key: str = ""
    opencti_url: str = ""
    proxy_url: str = ""
    ransomware_live_api_key: str = ""
    rl_analyze_url: str = ""
    rl_analyze_api_key: str = ""
    rosti_api_key: str = ""
    shodan: str = ""
    spur_us: str = ""
    threatfox: str = ""
    gunicorn_workers_count: int = 1
    gunicorn_threads_count: int = 1
    gunicorn_timeout: int = 120
    disable_version_check: bool = False
    ssl_verify: bool = True
    virustotal: str = ""
    webscout: str = ""

    # Method to iterate through the dataclass fields
    def __iter__(self):
        """Iterate through the dataclass fields."""

        yield from self.__dataclass_fields__

    def _get_field_type(self, field_name: str) -> type:
        """Get the type of a field by its name."""

        if field_name in self.__dataclass_fields__:
            return self.__dataclass_fields__[field_name].type
        raise KeyError(f"Field '{field_name}' does not exist in {self.__class__.__name__}")

    def __setattr__(self, name: str, value: Any) -> None:
        """Set the value of a field in the dataclass.

        Validate the value against the field type and convert
        str to bool,int, or list where needed.
        """

        field_type = self._get_field_type(name)

        # Convert string to list if needed
        if (
            hasattr(field_type, "__origin__")
            and field_type.__origin__ is list
            and isinstance(value, str)
        ):
            value = (
                [item.strip() for item in value.split(",")]
                if "," in value
                else [value.strip()]
                if value.strip()
                else []
            )

        if field_type is int:
            # Convert string to int
            try:
                value = int(value)
            except ValueError:
                logger.warning(
                    f"Invalid value for {name}: {value}. Expected int. {name} not updated."
                )
                print(f"Invalid value for {name}: {value}. Expected int. {name} not updated.")
                return

        if field_type is bool and isinstance(value, str):
            # Convert string to bool
            value = value.lower() in ["true", "1", "yes", "on"]

        super().__setattr__(name, value)

    # Add this get method to allow for a smooth transition from dict to dataclass
    def get(self, value: str) -> Any:
        """Get the value of a secret by its key.

        Return None if the key does not exist.
        """

        if value in self.__dataclass_fields__:
            return self.__dict__[value]

        return None

    def update(self, updated_secrets: dict[str, Any]) -> None:
        """Update the secrets with new values.

        Ensure that updated keys exists
        and the values match the required type of the field.
        """

        for key, value in updated_secrets.items():
            if key not in self.__dataclass_fields__:
                logger.warning(f"{key} is not a secret key.")
                continue

            setattr(self, key, value)


logger = logging.getLogger(__name__)

BASE_DIR: Path = Path.resolve(Path(__file__).parent.parent)

logger.debug(f"{BASE_DIR=}")

# Initialize secrets dictionary with default values
DEFAULT_SECRETS: Secrets = Secrets()


def load_env_file(env_file: Path) -> None:
    """Load environment variables from a .env file when present."""

    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=False)
        logger.info(
            "Loaded environment variables from .env file at %s. "
            "This file is optional and intended for local/dev use; "
            "in production, inject variables directly into the environment.",
            env_file,
        )
        return

    logger.debug(
        "No .env file found at %s. Relying on environment variables already present in the process.",  # noqa: E501
        env_file,
    )


def read_secrets_from_env(secrets: Secrets) -> Secrets:
    """Load secrets from environment variables.

    Each secret field is read from the corresponding uppercase environment variable.
    """

    # Load secrets from environment variables.
    env_configured: bool = False

    for key in secrets:
        env_value: str | None = os.getenv(key.upper())
        if env_value:
            env_configured: bool = True
            secrets.update({key: env_value})

    if not env_configured:
        msg: str = (
            "No environment variables were configured. "
            "Create a .env file from .env.sample or export variables before startup."
        )
        print(msg)
        logger.info(msg)

    return secrets


@lru_cache
def get_config() -> Secrets:
    """Get the configuration for the application."""

    load_env_file(BASE_DIR / ".env")
    secrets: Secrets = Secrets()
    secrets = read_secrets_from_env(secrets)

    if not secrets.get("proxy_url"):
        print("No proxy URL was set. Using no proxy.")
        logger.info("No proxy URL was set. Using no proxy.")

    return secrets
