import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]


def query_ipapi(ip: str, api_key: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Queries the IP information from the ipapi.is API using POST for better security.

    Args:
        ip (str): The IP address to query.
        api_key (str): API key for authentication.
        proxies (dict): Dictionary containing proxy settings.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        dict: The raw API response containing all IP information.
        None: If an error occurs.
    """
    try:
        url = "https://api.ipapi.is"
        headers = {"Content-Type": "application/json"}
        data = {"q": ip, "key": api_key}
        response = requests.post(url, json=data, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        # Reformat ASN field to match other engines (e.g., "AS12345")
        if "ip" in data:
            # sometimes ASN info is missing, that leads to errors in GUI
            if "asn" not in data or not data["asn"]:
                data["asn"] = {"asn": "Unknown", "org": "Unknown"}
            elif "asn" in data["asn"]:
                data["asn"]["asn"] = f"AS{data['asn']['asn']}"
            return data

    except Exception as e:
        logger.error("Error querying ipapi for '%s': %s", ip, e, exc_info=True)

    return None
