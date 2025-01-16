import logging
import json
import requests
from typing import Optional, Dict, Any, List

# Disable SSL warning
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)

def query_threatfox(
    observable: str,
    observable_type: str,
    proxies: Dict[str, str]
) -> Optional[Dict[str, Any]]:
    """
    Queries the ThreatFox API for information about a given observable (URL, IP, hash).

    Args:
        observable (str): The observable to search for (e.g., URL, IP address, hash).
        observable_type (str): The type of the observable (e.g., "URL", "IP", "hash").
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary with "count" (int), "malware_printable" (list), and "link" (str). For example:
              {
                  "count": 2,
                  "malware_printable": ["MalwareX", "RansomwareY"],
                  "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A<observable>"
              }
        None: If an error occurs.
    """
    try:
        # If it's a URL, we typically just want the domain portion for searching
        if observable_type == "URL":
            # e.g., https://example.com/path => domain = example.com
            domain_part = observable.split("/")[2].split(":")[0]
            observable = domain_part

        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {
            "query": "search_ioc",
            "search_term": observable
        }

        response = requests.post(
            url,
            data=json.dumps(payload),
            proxies=proxies,
            verify=False,
            timeout=5
        )
        response.raise_for_status()

        result = response.json()
        data = result.get("data", [])

        malware_printable_set = set()
        if isinstance(data, list):
            for item in data:
                if item:
                    malware_name = item.get("malware_printable", "Unknown")
                    malware_printable_set.add(malware_name)

            count = len(data)
        else:
            count = 0

        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{observable}"
        return {
            "count": count,
            "malware_printable": list(malware_printable_set),
            "link": link
        }

    except Exception as e:
        logger.error("Error querying ThreatFox for '%s': %s", observable, e, exc_info=True)

    return None
