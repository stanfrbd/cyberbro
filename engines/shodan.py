import logging

import requests
from requests.exceptions import HTTPError, JSONDecodeError

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]


def query_shodan(observable: str, api_key: str, proxies: dict[str, str], ssl_verify: bool = True) -> dict[str, list | str] | None:
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

        # Shodan returns 404 if the observable is not found
        # We handle this case specifically to avoid raising an exception
        if response.status_code == 404:
            logger.info("Observable '%s' not found in Shodan.", observable)
            return None

        # Raise an exception for any other HTTP error
        response.raise_for_status()

        data: dict = response.json()
    except HTTPError as e:
        logger.error(f"Error querying Shodan for {observable}: {e}")
        return None
    except JSONDecodeError as e:
        logger.error(f"Error decoding JSON response from Shodan for {observable}: {e}")
        return None

    # Shodan returns a more comprehensive JSON; we just pick out key fields
    return {
        "ports": data.get("ports", []),
        "tags": data.get("tags", []),
        "link": f"https://www.shodan.io/host/{observable}",
    }
