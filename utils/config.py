import os
import json

import logging

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

logger.debug("BASE_DIR: %s", BASE_DIR)

# Define the path to the secrets file
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.json')

# Initialize secrets dictionary with default values
secrets = {
    "proxy_url": "",
    "virustotal": "",
    "abuseipdb": "",
    "ipinfo": "",
    "google_safe_browsing": "",
    "mde_tenant_id": "",
    "mde_client_id": "",
    "mde_client_secret": "",
    "shodan": "",
    "opencti_api_key": "",
    "opencti_url": "",
    "crowdstrike_client_id": "",
    "crowdstrike_client_secret": "",
    "crowdstrike_falcon_base_url": "https://falcon.crowdstrike.com", # Default URL
    "webscout": "",
    "max_form_memory_size": 1048576, # 1 MB
    "api_prefix": "api",
    "config_page_enabled": False,
    "gui_enabled_engines": [],
    "ssl_verify": True, # Default to be secure
    "api_cache_timeout": 86400,  # Default to 1 day
    "gui_cache_timeout": 1800   # Default to 30 minutes
}

secrets_file_exists = False

# Load secrets from secrets.json if it exists
try:
    if os.path.exists(SECRETS_FILE):
        secrets_file_exists = True
        with open(SECRETS_FILE, 'r') as f:
            secrets.update(json.load(f))
    else:
        print("Secrets file not found. Reading environment variables anyway...")
        logger.info("Secrets file not found. Reading environment variables anyway...")

    # Load secrets from environment variables - override the ones from secrets.json if provided
    env_configured = False
    for key in secrets.keys():
        env_value = os.getenv(key.upper())
        if env_value:
            env_configured = True
            if key == "gui_enabled_engines":
                # Split the comma-separated list of engines into a list
                secrets[key] = [engine.strip().lower() for engine in env_value.split(",")]
            elif key == "config_page_enabled":
                secrets[key] = env_value.lower() in ["true", "1", "yes"]
            elif key == "ssl_verify":
                secrets[key] = env_value.lower() in ["true", "1", "yes"]
            else:
                secrets[key] = env_value

    # Check if proxy variable is set
    if not secrets["proxy_url"]:
        print("No proxy URL was set. Using no proxy.")
        logger.info("No proxy URL was set. Using no proxy.")

    if not env_configured:
        print("No environment variables were configured. You can configure secrets later in secrets.json.")
        logger.info("No environment variables were configured. You can configure secrets later in secrets.json.")

    # Dump all the variables and create the secrets.json file - this will overwrite the existing file
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f, indent=4)
        
    if not secrets_file_exists:
        print("Secrets file was automatically generated.")
        logger.info("Secrets file was automatically generated.")

except Exception as e:
    print("Error while loading secrets:", e)
    logger.error("Error while loading secrets: %s", e)
    exit(1)

def get_config():
    return secrets