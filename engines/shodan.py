import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


def query_shodan(
    observable: str, api_key: str, proxies: dict[str, str], ssl_verify: bool = True
) -> dict[str, Any] | None:
    """
    Queries the Shodan API for information about a given observable (typically an IP).

    Args:
        observable (str): The IP address to query in Shodan.
        api_key (str): The Shodan API key.
        proxies (dict): A dictionary of proxy configurations.

    Returns:
        dict: Contains the data about open ports, tags, and a link to the Shodan host page.
              Example:
              {
                  "ports": [...],
                  "tags": [...],
                  "link": "https://www.shodan.io/host/<IP>"
              }
        None: If the request was unsuccessful or an error occurred.
    """
    headers: dict = {"Accept": "application/json"}
    params: dict = {"key": api_key}
    url: str = f"https://api.shodan.io/shodan/host/{observable}"

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()

        data: dict = response.json()
        # Shodan returns a more comprehensive JSON; we just pick out key fields
        data["link"] = f"https://www.shodan.io/host/{observable}"

        return {
            "ports": data.get("ports", []),
            "tags": data.get("tags", []),
            "link": data["link"],
        }

    except Exception as e:
        logger.error("Error querying Shodan for '%s': %s", observable, e, exc_info=True)

    return None
