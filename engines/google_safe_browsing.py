import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


def query_google_safe_browsing(
    observable: str,
    observable_type: str,
    api_key: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the Google Safe Browsing API to check if the given observable is associated with any threats.

    Args:
        observable (str): The observable to be checked (URL, FQDN, or IP).
        observable_type (str): The type of the observable (e.g., "URL", "FQDN", "IPv4", "IPv6").
        api_key (str): Your Google Safe Browsing API key.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing the result of the query with the structure:
            {
                "threat_found": "Threat found" or "No threat found",
                "details": [...] or None
            }
        None: If an error occurs or the API request fails.
    """
    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

        threat_entries = []
        # Assign the URL to check based on the observable type
        if observable_type == "URL":
            threat_entries.append({"url": observable})
        elif observable_type == "FQDN" or observable_type in ["IPv4", "IPv6"]:
            threat_entries.append({"url": f"http://{observable}"})
        else:
            logger.warning(
                "Unsupported observable_type '%s' for Google Safe Browsing.",
                observable_type,
            )
            return None

        body = {
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED",
                ],
                "platformTypes": ["ALL"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries,
            }
        }

        response = requests.post(url, json=body, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "matches" in data:
            return {"threat_found": "Threat found", "details": data["matches"]}
        return {"threat_found": "No threat found", "details": None}

    except Exception as e:
        logger.error(
            "Error while querying Google Safe Browsing for '%s': %s",
            observable,
            e,
            exc_info=True,
        )

    return None
