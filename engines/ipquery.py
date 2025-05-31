import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]

def query_ipquery(ip: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Queries the IP information from the ipquery.io API.

    Args:
        ip (str): The IP address to query.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing extracted information:
            {
                "ip": ...,
                "geolocation": "city, region",
                "country_code": ...,
                "country_name": ...,
                "isp": ...,
                "asn": ...,
                "is_vpn": ...,
                "is_tor": ...,
                "is_proxy": ...,
                "risk_score": ...,
                "link": ...
            }
        None: If an error occurs or 'ip' key isn't in the response.
    """
    try:
        url = f"https://api.ipquery.io/{ip}"
        response = requests.get(url, proxies=proxies, verify=False, timeout=5)
        response.raise_for_status()

        data = response.json()
        if "ip" in data:
            ip_resp = data.get("ip", "Unknown")
            city = data.get("location", {}).get("city", "Unknown")
            region = data.get("location", {}).get("state", "Unknown")
            country_code = data.get("location", {}).get("country_code", "Unknown")
            country_name = data.get("location", {}).get("country", "Unknown")
            isp = data.get("isp", {}).get("isp", "Unknown")
            asn = data.get("isp", {}).get("asn", "Unknown")

            is_vpn = data.get("risk", {}).get("is_vpn", False)
            is_tor = data.get("risk", {}).get("is_tor", False)
            is_proxy = data.get("risk", {}).get("is_proxy", False)
            risk_score = data.get("risk", {}).get("risk_score", "Unknown")

            return {
                "ip": ip_resp,
                "geolocation": f"{city}, {region}",
                "country_code": country_code,
                "country_name": country_name,
                "isp": isp,
                "asn": asn,
                "is_vpn": is_vpn,
                "is_tor": is_tor,
                "is_proxy": is_proxy,
                "risk_score": risk_score,
                "link": f"https://api.ipquery.io/{ip_resp}",
            }

    except Exception as e:
        logger.error("Error querying ipquery for '%s': %s", ip, e, exc_info=True)

    return None
