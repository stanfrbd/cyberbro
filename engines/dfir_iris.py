import json
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "BOGON",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


def query_dfir_iris(
    observable: str,
    observable_type: str,
    dfir_iris_api_key: str,
    dfir_iris_url: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the DFIR-IRIS API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        observable_type (str): What type of IOC, (IPv4, IPv6, FQDN, MD5, SHA1, SHA256, URL)
        dfir_iris_api_key (str): DFIR_IRIS API key.
        dfir_iris_url (str): DFIR_IRIS url.
        proxies (dict): Dictionary of proxies.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        dict: A dictionary with number of cases with the indicator, and the case id links, for example:
            {
                "reports": 3,
                "links": ["https://dfir_iris_url/case/ioc?cid=3","https://dfir_iris_url/case/ioc?cid=4"]
            }
        None: If any error occurs.
    """

    # Use selective wildcards to match ioc
    if observable_type in ("IPv4", "IPv6", "MD5", "SHA1", "SHA256", "BOGON"):
        body = {"search_value": f"%{observable}", "search_type": "ioc"}
    elif observable_type in ("FQDN", "URL"):
        body = {"search_value": f"{observable}%", "search_type": "ioc"}
    else:
        body = {"search_value": f"{observable}", "search_type": "ioc"}

    try:
        url = f"{dfir_iris_url}/search?cid=1"
        headers = {"Authorization": f"Bearer {dfir_iris_api_key}", "Content-Type": "application/json"}
        payload = json.dumps(body)
        response = requests.post(url, headers=headers, data=payload, proxies=None, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "data" not in data:
            logger.warning("DFIR-IRIS response has no 'data' key. Full response: %s", data)
            return None

        if len(data["data"]) > 0:
            links = []
            for i in data["data"]:
                case_id = i["case_id"]
                link = f"{dfir_iris_url}/case/ioc?cid={case_id}"
                links.append(link)

            return {"reports": len(set(links)), "links": sorted(set(links))}  # Return unique case id's

        return None

    except Exception as e:
        logger.error("Error querying DFIR-IRIS for '%s': %s", observable, e, exc_info=True)

    return None
