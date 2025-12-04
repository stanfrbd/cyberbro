import logging
import time
from typing import Any, Optional

import pycountry
import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "IPv4",
    "IPv6",
]


def query_webscout(ip: str, api_key: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Queries the IP information from the webscout.io API and adapts parsing to the new API schema.
    Keeps the original return fields for compatibility and adds a few new relevant fields when available.
    """
    try:
        # rate limit
        time.sleep(1)
        url = f"https://api.webscout.io/query/ip/{ip}?apikey={api_key}"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        logger.debug("webscout response for %s: %s", ip, data)

        if data.get("status") == "success":
            d = data.get("data", {})

            # Basic IP & location
            ip_resp = d.get("ip", ip)
            location = d.get("location", {}) or {}
            country_code = location.get("country_iso", "Unknown") or "Unknown"
            city = location.get("city", "Unknown") or "Unknown"
            # Resolve country name
            try:
                country_obj = pycountry.countries.get(alpha_2=country_code)
                country_name = country_obj.name if country_obj else "Unknown"
            except Exception:
                country_name = "Unknown"

            # Hostnames
            hostnames = d.get("hostnames")
            if hostnames is None:
                hostnames = []

            # Network
            network = d.get("network", {}) or {}
            network_type = network.get("type", "") or ""
            network_service = network.get("service", "") or ""
            network_service_region = network.get("region", "") or ""
            network_range = network.get("range", "Unknown") or "Unknown"
            is_private = network.get("private", False)

            # AS
            as_data = d.get("as", {}) or {}
            as_org = as_data.get("organization", "Unknown") or "Unknown"
            raw_as = as_data.get("as_number")
            as_number = "AS" + str(raw_as) if raw_as else "Unknown"

            # Company / provider info
            company = d.get("company", {}) or {}
            network_provider = company.get("name", "Unknown") or "Unknown"
            network_provider_services = company.get("business", []) or []
            description = company.get("description", "Unknown") or "Unknown"

            # Anonymization
            anonymization = d.get("anonymization", {}) or {}
            is_vpn = bool(anonymization.get("vpn", False))
            is_proxy = bool(anonymization.get("proxy", False))
            is_tor = bool(anonymization.get("tor", False))
            # legacy single anonymization_service field: pick first service provider/display_name if present
            anonymization_services_raw = anonymization.get("services", []) or []
            anonymization_service = ""
            if anonymization_services_raw:
                first = anonymization_services_raw[0]
                anonymization_service = first.get("provider") or first.get("display_name") or ""
            # keep full list as a new field
            anonymization_services = [
                {
                    "provider": s.get("provider"),
                    "display_name": s.get("display_name"),
                    "thumbnail_url": s.get("thumbnail_url"),
                }
                for s in anonymization_services_raw
            ]

            # OSINT / behavior / tags
            # new schema has osint.services each with tags array; aggregate them for legacy "behavior"
            osint = d.get("osint", {}) or {}
            osint_services = osint.get("services", []) or []
            osint_tags = []
            for svc in osint_services:
                tags = svc.get("tags", []) or []
                osint_tags.extend(tags)
            # remove duplicates
            behavior = list(dict.fromkeys(osint_tags))
            # keep top-level osint first/last seen as new fields
            osint_first_seen = osint.get("first_seen")
            osint_last_seen = osint.get("last_seen")

            # Open ports - no longer present in example; keep for compatibility as empty list if missing
            # previous implementation used behavior_data.get("open_ports", [])
            open_ports = d.get("open_ports", []) or []

            # Netflow - new useful fields
            netflow = d.get("netflow", {}) or {}
            has_netflow = bool(netflow.get("has_netflow", False))
            netflow_days_seen = netflow.get("days_seen")
            netflow_total_observation = netflow.get("total_observation")
            netflow_last_seen = netflow.get("last_seen")

            def _date_only(dt: Optional[str]) -> Optional[str]:
                if isinstance(dt, str) and "T" in dt:
                    return dt.split("T", 1)[0]
                return dt

            return {
                # original fields (kept for compatibility)
                "ip": ip_resp,
                "location": f"{country_name}, {city}",
                "country_code": country_code,
                "country_name": country_name,
                "hostnames": hostnames,
                "network_type": network_type,
                "network_provider": network_provider,
                "network_service": network_service,
                "network_service_region": network_service_region,
                "network_provider_services": network_provider_services,
                "behavior": behavior,
                "as_org": as_org,
                "asn": as_number,
                "description": description,
                "network_range": network_range,
                "is_private": is_private,
                "open_ports": open_ports,
                "is_vpn": is_vpn,
                "is_proxy": is_proxy,
                "is_tor": is_tor,
                "anonymization_service": anonymization_service,
                # new fields (added for relevance)
                "anonymization_services": anonymization_services,
                "osint_first_seen": _date_only(osint_first_seen),
                "osint_last_seen": _date_only(osint_last_seen),
                "has_netflow": has_netflow,
                "netflow_days_seen": netflow_days_seen,
                "netflow_total_observation": netflow_total_observation,
                "netflow_last_seen": _date_only(netflow_last_seen),
            }

    except Exception as e:
        logger.error("Error querying webscout for '%s': %s", ip, e, exc_info=True)

    return None
