import base64
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


def query_virustotal(
    observable: str,
    observable_type: str,
    api_key: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the VirusTotal API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        observable_type (str): The type of the observable ("IPv4", "FQDN", "URL", "MD5", etc.).
        api_key (str): VirusTotal API key.
        proxies (dict): Dictionary of proxies.

    Returns:
        dict: Contains detection ratio, total malicious, link, and community_score, for example:
            {
                "detection_ratio": "5/70",
                "total_malicious": 5,
                "link": "https://www.virustotal.com/gui/ip-address/<ip>/detection",
                "community_score": 10
            }
        None: If any error occurs.
    """
    try:
        headers = {"x-apikey": api_key}
        # Determine the correct endpoint & link based on the observable type
        if observable_type in ["IPv4", "IPv6"]:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable}"
            link = f"https://www.virustotal.com/gui/ip-address/{observable}/detection"
        elif observable_type == "FQDN":
            url = f"https://www.virustotal.com/api/v3/domains/{observable}"
            link = f"https://www.virustotal.com/gui/domain/{observable}/detection"
        elif observable_type == "URL":
            encoded_url = base64.urlsafe_b64encode(observable.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
            link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
        else:  # Assume a file hash
            url = f"https://www.virustotal.com/api/v3/files/{observable}"
            link = f"https://www.virustotal.com/gui/file/{observable}/detection"

        response = requests.get(url, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})

            total_malicious = stats.get("malicious", 0)
            total_engines = sum(stats.values()) if stats else 0
            detection_ratio = f"{total_malicious}/{total_engines}" if total_engines else "0/0"

            # 'reputation' is usually the community score
            community_score = attributes.get("reputation", "Unknown")

            return {
                "detection_ratio": detection_ratio,
                "total_malicious": total_malicious,
                "link": link,
                "community_score": community_score,
            }

        # If 'data' or 'attributes' key is missing, fallback
        logger.warning("VirusTotal response missing expected keys for '%s': %s", observable, data)
        return {
            "detection_ratio": "0/0",
            "total_malicious": 0,
            "link": f"https://www.virustotal.com/gui/search/{observable}",
            "community_score": 0,
        }

    except Exception as e:
        logger.error("Error querying VirusTotal for '%s': %s", observable, e, exc_info=True)

    return None
