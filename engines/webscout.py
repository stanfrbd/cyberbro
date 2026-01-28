import logging
import time
from typing import Any

import pycountry
import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class WebscoutEngine(BaseEngine):
    @property
    def name(self):
        return "webscout"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def _date_only(self, dt: str | None) -> str | None:
        if isinstance(dt, str) and "T" in dt:
            return dt.split("T", 1)[0]
        return dt

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        api_key: str = self.secrets.webscout
        try:
            # TODO: Hardcoded 1-second rate limiting makes tests slow
            # and cannot be disabled
            # Is this something we could use tenacity for?
            time.sleep(1)  # rate limit
            # TODO: No credential validation - empty keys still make API requests
            url = f"https://api.webscout.io/query/ip/{observable_value}?apikey={api_key}"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()

            if data.get("status") == "success":
                d = data.get("data", {})

                # ... (complex parsing logic moved to internal fields or simplified) ...
                location = d.get("location", {}) or {}
                country_code = location.get("country_iso", "Unknown") or "Unknown"
                city = location.get("city", "Unknown") or "Unknown"

                try:
                    country_obj = pycountry.countries.get(alpha_2=country_code)
                    country_name = country_obj.name if country_obj else "Unknown"
                except Exception:
                    country_name = "Unknown"

                network = d.get("network", {}) or {}
                company = d.get("company", {}) or {}
                as_data = d.get("as", {}) or {}
                anonymization = d.get("anonymization", {}) or {}
                osint = d.get("osint", {}) or {}
                # TODO: Inconsistent dict access patterns - some use `or {}` redundantly

                # Aggregate OSINT tags for 'behavior'
                osint_tags = []
                for svc in osint.get("services", []):
                    tags = svc.get("tags", []) or []
                    osint_tags.extend(tags)
                behavior = list(dict.fromkeys(osint_tags))

                """
                Check for risk score
                (if available in a non-standard location or just hardcode as unknown)
                Since risk_score is NOT explicitly in the returned data,
                we assume it's calculated or pulled
                from somewhere else, or the 'export.py' is for an older version.
                Setting a placeholder for export.
                """

                return {
                    "ip": d.get("ip", observable_value),
                    "risk_score": None,  # Placeholder for backward compatibility
                    "is_proxy": bool(anonymization.get("proxy", False)),
                    "is_tor": bool(anonymization.get("tor", False)),
                    "is_vpn": bool(anonymization.get("vpn", False)),
                    "country_code": country_code,
                    "country_name": country_name,
                    # TODO: Location string could have trailing comma if city is empty
                    "location": f"{country_name}, {city}",
                    "hostnames": d.get("hostnames", []),
                    "domains_on_ip": None,  # Placeholder for backward compatibility
                    "network_type": network.get("type", ""),
                    "network_provider": company.get("name", "Unknown"),
                    "network_service": network.get("service", ""),
                    "network_service_region": network.get("region", ""),
                    "network_provider_services": company.get("business", []),
                    "behavior": behavior,
                    "as_org": as_data.get("organization", "Unknown"),
                    "asn": "AS" + str(as_data.get("as_number"))
                    if as_data.get("as_number")
                    else "Unknown",
                    "description": company.get("description", "Unknown"),
                }

        except Exception as e:
            logger.error("Error querying webscout for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"ws_{k}": None
                for k in [
                    "risk",
                    "is_proxy",
                    "is_tor",
                    "is_vpn",
                    "cn",
                    "country",
                    "location",
                    "hostnames",
                    "domains_on_ip",
                    "network_type",
                    "network_provider",
                    "network_service",
                    "network_service_region",
                    "network_provider_services",
                    "behavior",
                    "as_org",
                    "asn",
                    "desc",
                ]
            }

        return {
            "ws_risk": analysis_result.get("risk_score"),
            "ws_is_proxy": analysis_result.get("is_proxy"),
            "ws_is_tor": analysis_result.get("is_tor"),
            "ws_is_vpn": analysis_result.get("is_vpn"),
            "ws_cn": analysis_result.get("country_code"),
            "ws_country": analysis_result.get("country_name"),
            "ws_location": analysis_result.get("location"),
            "ws_hostnames": ", ".join(analysis_result.get("hostnames", [])),
            "ws_domains_on_ip": analysis_result.get("domains_on_ip"),
            "ws_network_type": analysis_result.get("network_type"),
            "ws_network_provider": analysis_result.get("network_provider"),
            "ws_network_service": analysis_result.get("network_service"),
            "ws_network_service_region": analysis_result.get("network_service_region"),
            "ws_network_provider_services": ", ".join(
                analysis_result.get("network_provider_services", [])
            ),
            "ws_behavior": ", ".join(analysis_result.get("behavior", [])),
            "ws_as_org": analysis_result.get("as_org"),
            "ws_asn": analysis_result.get("asn"),
            "ws_desc": analysis_result.get("description"),
        }
