import json
import logging
import os
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any


class QueryError(Exception):
    pass


@dataclass
class Secrets:
    """Dataclass to hold the secrets for the application."""

    abuseipdb: str = ""
    api_cache_timeout: int = 86400  # Default to 1 day
    api_prefix: str = "api"
    alienvault: str = ""
    config_page_enabled: bool = False
    criminalip_api_key: str = ""
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_falcon_base_url: str = "https://falcon.crowdstrike.com"
    dfir_iris_url: str = ""
    dfir_iris_api_key: str = ""
    google_cse_cx: str = ""
    google_cse_key: str = ""
    google_safe_browsing: str = ""
    gui_cache_timeout: int = 1800
    gui_enabled_engines: list[str] = field(default_factory=list)
    ipapi: str = ""
    ipinfo: str = ""
    max_form_memory_size: int = 1_048_576
    mde_client_id: str = ""
    mde_client_secret: str = ""
    mde_tenant_id: str = ""
    misp_api_key: str = ""
    misp_url: str = ""
    opencti_api_key: str = ""
    opencti_url: str = ""
    proxy_url: str = ""
    rl_analyze_url: str = ""
    rl_analyze_api_key: str = ""
    shodan: str = ""
    spur_us: str = ""
    threatfox: str = ""
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
            and "," in value
        ):
            value = [item.strip() for item in value.split(",")]

        if field_type is int:
            # Convert string to int
            try:
                value = int(value)
            except ValueError:
                logger.warning(f"Invalid value for {name}: {value}. Expected int. {name} not updated.")
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

# Define the path to the secrets file
SECRETS_FILE: Path = Path(BASE_DIR / "secrets.json")

# Initialize secrets dictionary with default values
DEFAULT_SECRETS: Secrets = Secrets()


def read_secrets_from_file(secrets_file: Path) -> Secrets:
    """Load secrets from a JSON file, if it exists.

    Return a dictionary with any updated secrets.
    """

    # Make a copy of the defaults, we can compare for changes later
    secrets: Secrets = Secrets()

    # Load secrets from secrets.json if it exists
    if secrets_file.exists():
        try:
            with secrets_file.open() as f:
                secrets.update(json.load(f))
        except OSError as e:
            print("Unable to read secrets file. Reading environment variables anyway...")
            logger.debug(f"Error reading secrets file: {e}")
            logger.error("Unable to read secrets file. Reading environment variables anyway...")
        except json.JSONDecodeError as e:
            print("Error while decoding secrets:", e)
            logger.debug(f"Error while decoding secrets: {e}")
            logger.error("Error while decoding secrets. Reading environment variables anyway...")
    else:
        print("Secrets file not found. Reading environment variables anyway...")
        logger.info("Secrets file not found. Reading environment variables anyway...")

    return secrets


def read_secrets_from_env(secrets: Secrets) -> Secrets:
    """Load secrets from envrionment variables.

    Override the config file if the environment variable is set.
    """

    # Load secrets from environment variables - override the ones from secrets.json, if present
    env_configured: bool = False

    for key in secrets:
        env_value: str | None = os.getenv(key.upper())
        if env_value:
            env_configured: bool = True
            secrets.update({key: env_value})

    if not env_configured:
        print("No environment variables were configured. You can configure secrets later in secrets.json.")
        logger.info("No environment variables were configured. You can configure secrets later in secrets.json.")

    return secrets


def save_secrets_to_file(secrets: Secrets, secrets_file: Path) -> None:
    """Save the secrets to a JSON file."""

    # Save the secrets to the secrets.json file
    try:
        with secrets_file.open("w") as f:
            json.dump(asdict(secrets), f, indent=4)
    except OSError as e:
        print(f"Unable to write secrets file: {e}")
        logger.error(f"Unable to write secrets file: {e}")
        return
    except json.JSONDecodeError as e:
        print("Error while encoding secrets:", e)
        logger.error("Error while encoding secrets: %s", e)
        return

    print("Secrets file was updated.")
    logger.info("Secrets file was updated.")

    return


@lru_cache
def get_config() -> Secrets:
    """Get the configuration for the application."""

    secrets: Secrets = read_secrets_from_file(SECRETS_FILE)
    secrets = read_secrets_from_env(secrets)

    if not secrets.get("proxy_url"):
        print("No proxy URL was set. Using no proxy.")
        logger.info("No proxy URL was set. Using no proxy.")

    # If the secrets are not the same as the defaults, save them to the file
    if secrets != DEFAULT_SECRETS:
        if not SECRETS_FILE.exists():
            print("Secrets file was not found. Attempting to save current values to a new one.")

        save_secrets_to_file(secrets, SECRETS_FILE)

    return secrets
