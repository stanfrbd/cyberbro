import base64
import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "URL",
]


def query_phishtank(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Query the PhishTank API to check if a given observable is a known phishing URL.
    Uses the user-agent "phishtank/IntelOwl" for the request since IntelOwl is allowed by PhishTank.

    Args:
        observable (str): The observable to be checked (e.g., URL or FQDN).
        observable_type (str): The type of the observable (e.g., "URL", "FQDN").
        proxies (dict): Dictionary of proxies to be used for the request.

    Returns:
        dict: The results from the PhishTank API if the request is successful.
        None: If any exception or error occurs during the request.
    """
    headers = {"User-Agent": "phishtank/Cyberbro"}
    observable_to_analyze = observable

    if observable_type == "FQDN":
        observable_to_analyze = f"http://{observable}"
    parsed = urlparse(observable_to_analyze)
    if not parsed.path:
        observable_to_analyze += "/"

    data = {
        "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
        "format": "json",
    }

    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=data,
            headers=headers,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        json_data = response.json()

        if "results" in json_data:
            logger.debug("PhishTank response: %s", json_data["results"])
            return json_data["results"]
        logger.warning("PhishTank response has no 'results' key: %s", json_data)

    except Exception as e:
        logger.error("Error querying PhishTank for '%s': %s", observable, e, exc_info=True)

    return None
