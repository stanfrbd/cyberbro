import logging
import requests
import time
import pycountry
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def query_webscout(ip: str, api_key: str, proxies: Dict[str, str], ssl_verify: bool = True) -> Optional[Dict[str, Any]]:
    """
    Queries the IP information from the webscout.io API.

    Args:
        ip (str): The IP address to query.
        api_key (str): The API key for webscout.io.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing extracted information:
            {
                "ip": ...,
                "risk_score": ...,
                "location": "country_name, region",
                "country_code": ...,
                "country_name": ...,
                "hostnames": ...,
                "domains_on_ip": ...,
                "operator": ...,
                "network_type": ...,
                "network_provider": ...,
                "network_service": ...,
                "network_service_region": ...,
                "network_provider_services": ...,
                "behavior": ...,
                "as_org": ...,
                "asn": ...,
                "provider_description": ...,
                "operator_description": ...,
                "network_risk_score": ...,
                "network_range": ...,
                "is_private": ...,
                "open_ports": ...
            }
        None: If an error occurs or 'status' key isn't 'success'.
    """
    try:
        # rate limit
        time.sleep(1)
        url = f"https://api.webscout.io/query/ip/{ip}?apikey={api_key}"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        if data.get("status") == "success":
            ip_resp = data["data"].get("ip", "Unknown")
            risk_score = data["data"].get("risk_score", "Unknown")
            location = data["data"].get("location", {})
            country_code = location.get("country_iso", "Unknown")
            city = location.get("city", "Unknown")
            # Attempt to resolve country name
            try:
                country_obj = pycountry.countries.get(alpha_2=country_code)
                country_name = country_obj.name if country_obj else "Unknown"
            except Exception:
                country_name = "Unknown"
            hostnames = data["data"].get("hostnames", [])
            domains_on_ip = data["data"].get("domains_on_ip", "Unknown")
            network = data["data"].get("network", {})
            network_type = network.get("type", "Unknown")
            network_service = network.get("service", "Unknown")
            network_service_region = network.get("region", "Unknown")
            network_risk_score = network.get("risk_score", "Unknown")
            network_range = network.get("range", "Unknown")
            is_private = network.get("private", False)
            as_data = data["data"].get("as", {})
            as_org = as_data.get("organization", "Unknown")
            asn_list = as_data.get("as_numbers", [])
            asn = ", ".join(map(str, asn_list)) if len(asn_list) > 1 else (asn_list[0] if asn_list else "Unknown")
            company = data["data"].get("company", {})
            network_provider = company.get("name", "Unknown")
            network_provider_services = company.get("business", [])
            description = company.get("description", "Unknown")
            behavior_data = data["data"].get("behavior", {})
            behavior = behavior_data.get("tags", [])
            osint_data = data["data"].get("osint", {})
            osint_tags = osint_data.get("tags", [])
            behavior = behavior or []  # Ensure behavior is a list
            osint_tags = osint_tags or []  # Ensure osint_tags is a list
            if behavior or osint_tags:
                behavior = list(set(behavior + osint_tags))  # Merge and remove duplicates
            open_ports = behavior_data.get("open_ports", [])
            anonymization = data["data"].get("anonymization", {})
            is_vpn = anonymization.get("vpn", False)
            is_proxy = anonymization.get("proxy", False)
            is_tor = anonymization.get("tor", False)
            anonymization_service = anonymization.get("service", "")

            return {
                "ip": ip_resp,
                "risk_score": risk_score,
                "location": f"{country_name}, {city}",
                "country_code": country_code,
                "country_name": country_name,
                "hostnames": hostnames,
                "domains_on_ip": domains_on_ip,
                "network_type": network_type,
                "network_provider": network_provider,
                "network_service": network_service,
                "network_service_region": network_service_region,
                "network_provider_services": network_provider_services,
                "behavior": behavior,
                "as_org": as_org,
                "asn": asn,
                "description": description,
                "network_risk_score": network_risk_score,
                "network_range": network_range,
                "is_private": is_private,
                "open_ports": open_ports,
                "is_vpn": is_vpn,
                "is_proxy": is_proxy,
                "is_tor": is_tor,
                "anonymization_service": anonymization_service
                }

    except Exception as e:
        logger.error("Error querying webscout for '%s': %s", ip, e, exc_info=True)

    return None