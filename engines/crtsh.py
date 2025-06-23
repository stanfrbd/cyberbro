import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "URL",
]


def query_crtsh(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the crt.sh API for information about a given observable (URL or FQDN).

    Args:
        observable (str): The observable to query.
        observable_type (str): The type of the observable (e.g., "URL", "IP", "MD5", "SHA256", etc.).
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary containing "scan_count", "top_domains", and "link". For example:
              {
                  "top_domains": [{"domain": "example.com", "count": 5}, ...],
                  "link": "https://crt.sh/?q=example.com"
              }
        None: If an error occurs.
    """
    query_fields = {
        "URL": "page.domain",
        "FQDN": "page.domain"
    }
    query_field = query_fields.get(observable_type, "page.domain")

    try:
        # If observable is a URL, extract domain
        if observable_type == "URL":
            domain_part = observable.split("/")[2].split(":")[0]
            observable = domain_part

        url = f"https://crt.sh/?q={observable}&output=json"

        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=10)
        response.raise_for_status()

        results = response.json()
        domain_count = {}
        for entry in results:
            domains = set()

            common_name	= entry.get("common_name", None)
            if common_name is not None and len(common_name) != 0:
                domains.add(common_name)

            name_value = entry.get("name_value", None)
            if name_value is not None and len(name_value) != 0:
                for el in name_value.split("\n"):
                    if len(el) > 0:
                        domains.add(str(el).strip())
            
            for domain in domains:
                domain_count[domain] = domain_count.get(domain, 0) + 1

        # Sort and extract top 5
        sorted_domains = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
        top_domains = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]
        return {
            "top_domains": top_domains,
            "link": f"https://crt.sh/?q={observable}",
        }

    except Exception as e:
        logger.error(
            "Error querying crt.sh for '%s' (%s): %s",
            observable,
            observable_type,
            e,
            exc_info=True,
        )

    return None
