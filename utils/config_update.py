"""Helper functions for updating configuration from form data."""

from typing import Any

from flask import Request

from utils.config import SECRETS_FILE, Secrets, save_secrets_to_file

# Define all updatable secret fields (excludes some runtime/system fields)
UPDATABLE_SECRET_FIELDS = [
    "proxy_url",
    "virustotal",
    "abuseipdb",
    "ipapi",
    "ipinfo",
    "google_cse_key",
    "google_cse_cx",
    "google_safe_browsing",
    "mde_tenant_id",
    "mde_client_id",
    "mde_client_secret",
    "shodan",
    "opencti_api_key",
    "opencti_url",
    "crowdstrike_client_id",
    "crowdstrike_client_secret",
    "crowdstrike_falcon_base_url",
    "webscout",
    "threatfox",
    "dfir_iris_api_key",
    "dfir_iris_url",
    "rl_analyze_api_key",
    "rl_analyze_url",
    "alienvault",
    "criminalip_api_key",
    "misp_api_key",
    "misp_url",
    "spur_us",
]


def update_secrets_from_form(secrets: Secrets, request: Request) -> None:
    """Update secrets object from form data.

    Args:
        secrets: Secrets dataclass instance to update
        request: Flask request object containing form data
    """
    for field_name in UPDATABLE_SECRET_FIELDS:
        form_value = request.form.get(field_name)
        if form_value is not None:
            setattr(secrets, field_name, form_value)


def update_gui_enabled_engines(secrets: Secrets, request: Request) -> list[str]:
    """Update GUI enabled engines from form data.

    Args:
        secrets: Secrets dataclass instance to update
        request: Flask request object containing form data

    Returns:
        Updated list of enabled engines, or empty list if no update
    """
    updated_gui_enabled_engines = request.form.get("gui_enabled_engines", "")
    if updated_gui_enabled_engines:
        enabled_engines = [
            engine.strip().lower() for engine in updated_gui_enabled_engines.split(",")
        ]
        secrets.gui_enabled_engines = enabled_engines
        return enabled_engines
    return []


def process_config_update(secrets: Secrets, request: Request) -> tuple[dict[str, Any], int]:
    """Process configuration update from form data.

    Args:
        secrets: Secrets dataclass instance to update
        request: Flask request object containing form data

    Returns:
        Tuple of (response_dict, status_code)
    """
    try:
        # Update all standard secret fields
        update_secrets_from_form(secrets, request)

        # Update GUI enabled engines and get the updated list
        updated_engines = update_gui_enabled_engines(secrets, request)

        # Save the secrets to the secrets.json file
        save_secrets_to_file(secrets, SECRETS_FILE)

        return {
            "message": "Configuration updated successfully.",
            "updated_engines": updated_engines,
        }, 200

    except Exception as e:
        return {
            "message": f"An error occurred while updating the configuration. {e}",
        }, 500
