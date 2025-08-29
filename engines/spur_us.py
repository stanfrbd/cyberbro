import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]


def query_spur_us(
    ip: str, proxies: dict[str, str], ssl_verify: bool = True, api_key: Optional[str] = None
) -> Optional[dict[str, str]]:
    """
    Retrieves information about the given IP address from the spur.us website or API.

    Args:
        ip (str): The IP address to retrieve information for.
        proxies (dict): Dictionary of proxies for the request.
        ssl_verify (bool): Whether to verify SSL certificates.
        api_key (str, optional): API key for the spur.us API.

    Returns:
        dict: A dictionary containing the link to the spur.us context page and the anonymity status, e.g.:
              {
                  "link": "https://spur.us/context/<ip>",
                  "tunnels": "NORD_VPN" (for example)
              }
        None: If an error occurs during the request or parsing process.
    """
    spur_url = f"https://spur.us/context/{ip}"

    try:
        if api_key:
            # Use API with token authentication
            api_url = f"https://api.spur.us/v2/context/{ip}"
            headers = {"Token": api_key}

            response = requests.get(
                api_url,
                proxies=proxies,
                verify=ssl_verify,
                headers=headers,
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()
            tunnels_info = "Not anonymous"

            if "tunnels" in data and data["tunnels"]:
                for tunnel in data["tunnels"]:
                    if tunnel.get("operator"):
                        tunnels_info = tunnel["operator"]
                        break

            return {"link": spur_url, "tunnels": tunnels_info}
        else:
            # No API key, return link with Unknown tunnels
            return {"link": spur_url, "tunnels": "Unknown - Behind Captcha"}

    except Exception as e:
        logger.error("Error querying spur.us for IP '%s': %s", ip, e, exc_info=True)

    return None
