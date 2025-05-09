import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


def query_hudsonrock(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Perform a search query using Hudson Rock API for email or domain observables.

    Args:
        observable (str): The search query string (e.g., an email or domain).
        observable_type (str): The type of observable ('email' or 'domain').
        proxies (dict): Dictionary containing proxy settings, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing the search results.
        None: If an error occurs (network, parsing, etc.).
    """
    try:
        if observable_type == "URL":
            parsed_url = urlparse(observable)
            observable = parsed_url.netloc
            observable_type = "FQDN"

        if observable_type == "Email":
            url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={observable}"
        elif observable_type == "FQDN":
            url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={observable}"
        else:
            logger.error("Unsupported observable type: %s", observable_type)
            return None

        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        return response.json()

    except Exception as e:
        logger.error(
            "Error while querying Hudson Rock for '%s': %s",
            observable,
            e,
            exc_info=True,
        )
    return None
