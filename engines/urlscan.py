import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


def query_urlscan(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the urlscan.io API for information about a given observable (URL, IP, or file hash).

    Args:
        observable (str): The observable to query.
        observable_type (str): The type of the observable (e.g., "URL", "IP", "MD5", "SHA256", etc.).
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: A dictionary containing "scan_count", "top_domains", and "link". For example:
              {
                  "scan_count": 10,
                  "top_domains": [{"domain": "example.com", "count": 5}, ...],
                  "link": "https://urlscan.io/search/#page.domain:example.com"
              }
        None: If an error occurs.
    """
    query_fields = {
        "IPv4": "ip",
        "IPv6": "ip",
        "MD5": "files.md5",
        "SHA1": "files.sha1",
        "SHA256": "files.sha256",
        "URL": "page.domain",
        "FQDN": "page.domain",
    }
    query_field = query_fields.get(observable_type, "page.domain")

    try:
        # If observable is a URL, extract domain
        if observable_type == "URL":
            domain_part = observable.split("/")[2].split(":")[0]
            observable = domain_part

        url = f"https://urlscan.io/api/v1/search/?q={query_field}:{observable}"

        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        result = response.json()
        results = result.get("results", [])
        scan_count = result.get("total", 0)

        domain_count = {}
        for entry in results:
            page_info = entry.get("page", {})
            domain = page_info.get("domain", "Unknown")
            domain_count[domain] = domain_count.get(domain, 0) + 1

        # Sort and extract top 5
        sorted_domains = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
        top_domains = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]

        return {
            "scan_count": scan_count,
            "top_domains": top_domains,
            "link": f"https://urlscan.io/search/#{query_field}:{observable}",
        }

    except Exception as e:
        logger.error(
            "Error querying urlscan.io for '%s' (%s): %s",
            observable,
            observable_type,
            e,
            exc_info=True,
        )

    return None
