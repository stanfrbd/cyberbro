import logging
from typing import Optional

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

ua = UserAgent()


def get_spur(ip: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, str]]:
    """
    Retrieves information about the given IP address from the spur.us website.

    Args:
        ip (str): The IP address to retrieve information for.
        proxies (dict): Dictionary of proxies for the request.

    Returns:
        dict: A dictionary containing the link to the spur.us context page and the anonymity status, e.g.:
              {
                  "link": "https://spur.us/context/<ip>",
                  "tunnels": "Tor Exit Node" (for example)
              }
        None: If an error occurs during the request or parsing process.
    """
    try:
        spur_url = f"https://spur.us/context/{ip}"
        response = requests.get(
            spur_url,
            proxies=proxies,
            verify=ssl_verify,
            headers={"User-Agent": ua.random},
            timeout=5,
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        title_tag = soup.title

        if title_tag is not None:
            title_text = title_tag.get_text()
            if "(" in title_text and ")" in title_text:
                # Extract substring between parentheses, e.g. " (Tor Proxy) "
                content = title_text.split("(")[1].split(")")[0].strip()
            else:
                content = "Not anonymous"
        else:
            content = "Not anonymous"

        return {"link": spur_url, "tunnels": content}

    except Exception as e:
        logger.error("Error querying spur.us for IP '%s': %s", ip, e, exc_info=True)

    return None
