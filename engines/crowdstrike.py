import logging
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urljoin

from falconpy import APIHarnessV2

logger = logging.getLogger(__name__)


def map_observable_type(observable_type: str) -> str:
    if observable_type in ["MD5", "SHA256", "SHA1"] or observable_type in [
        "IPv4",
        "IPv6",
    ]:
        return observable_type.lower()
    if observable_type in ["FQDN", "URL"]:
        return "domain"
    return None


def generate_ioc_id(observable: str, observable_type: str) -> str:
    if observable_type == "domain":
        return f"domain_{observable}"
    if observable_type in ["ipv4", "ipv6"]:
        return f"ip_address_{observable}"
    if observable_type == "md5":
        return f"hash_md5_{observable}"
    if observable_type == "sha256":
        return f"hash_sha256_{observable}"
    if observable_type == "sha1":
        return f"hash_sha1_{observable}"
    return None


def get_falcon_client(
    client_id: str, client_secret: str, proxies: dict[str, str], ssl_verify: bool = True
) -> APIHarnessV2:
    return APIHarnessV2(
        client_id=client_id,
        client_secret=client_secret,
        proxy=proxies,
        user_agent="cyberbro",
        ssl_verify=ssl_verify,
        timeout=5,
    )


def query_crowdstrike(
    observable: str,
    observable_type: str,
    client_id: str,
    client_secret: str,
    falcon_url: str = "https://falcon.crowdstrike.com",
    ssl_verify: bool = True,
    proxies: Optional[dict[str, str]] = None,
) -> Optional[dict[str, Any]]:
    """
    Queries CrowdStrike Falcon for information about a given observable.

    Args:
        observable (str): The observable to query.
        observable_type (str): The type of the observable (e.g., 'URL', 'MD5', 'SHA1', 'SHA256').
        client_id (str): The client ID for CrowdStrike API authentication.
        client_secret (str): The client secret for CrowdStrike API authentication.
        falcon_url (str): The base URL for the CrowdStrike Falcon API.
        ssl_verify (bool): Whether to verify SSL certificates.
        proxies (Dict[str, str]): Proxy settings for the API client.

    Returns:
        Optional[Dict[str, Any]]: A dictionary with the query results or None if an error occurs.
    """

    try:
        falcon = get_falcon_client(client_id, client_secret, proxies, ssl_verify)

        # Ensure the URL is properly formatted
        falcon_url = urljoin(falcon_url, "/").rstrip("/")

        if observable_type == "URL":
            observable = observable.split("/")[2].split(":")[0]

        observable = observable.lower()
        observable_type = map_observable_type(observable_type)

        response = falcon.command("indicator_get_device_count_v1", type=observable_type, value=observable)
        logger.debug("Falcon response: %s", response)

        if response["status_code"] != 200:
            logger.debug("Indicator not found: %s", response["body"]["errors"][0]["message"])
            result = {"device_count": 0}
        else:
            data = response["body"]["resources"][0]
            result = {"device_count": data.get("device_count", 0)}

        id_to_search = generate_ioc_id(observable, observable_type)
        request_body = {"ids": [id_to_search]}

        response = falcon.command("GetIntelIndicatorEntities", body=request_body)
        logger.debug("GetIntelIndicatorEntities response: %s", response)

        if response["status_code"] != 200 or not response["body"]["resources"]:
            logger.debug("Indicator not found or error in response: %s", response)
            result.update(
                {
                    "indicator_found": False,
                    "published_date": "",
                    "last_updated": "",
                    "actors": [],
                    "malicious_confidence": "",
                    "threat_types": [],
                    "kill_chain": [],
                    "malware_families": [],
                    "vulnerabilities": [],
                    "link": f"{falcon_url}/search/?term=_all%3A~%27{observable}%27",
                }
            )
            return result

        resource = response["body"]["resources"][0]
        result.update(
            {
                "indicator_found": True,
                "published_date": datetime.fromtimestamp(resource.get("published_date", 0), tz=timezone.utc).strftime(
                    "%Y-%m-%d"
                ),
                "last_updated": datetime.fromtimestamp(resource.get("last_updated", 0), tz=timezone.utc).strftime(
                    "%Y-%m-%d"
                ),
                "actors": resource.get("actors", []),
                "malicious_confidence": resource.get("malicious_confidence", ""),
                "threat_types": resource.get("threat_types", []),
                "kill_chain": resource.get("kill_chains", []),
                "malware_families": resource.get("malware_families", []),
                "vulnerabilities": resource.get("vulnerabilities", []),
                "link": f"{falcon_url}/search/?term=_all%3A~%27{observable}%27",
            }
        )

        return result

    except Exception as e:
        logger.error(
            "Error querying CrowdStrike Falcon for '%s': %s",
            observable,
            e,
            exc_info=True,
        )
        return None
