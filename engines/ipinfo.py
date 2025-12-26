import logging
from typing import Any, Optional

import pycountry
import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class IPInfoEngine(BaseEngine):
    @property
    def name(self):
        return "ipinfo"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        try:
            url = f"https://ipinfo.io/{observable_value}/json?token={self.secrets.ipinfo}"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()

            # Handle bogon/private IPs explicitly
            if "bogon" in data:
                return {
                    "ip": observable_value,
                    "geolocation": "",
                    "country_code": "",
                    "country_name": "Bogon",
                    "hostname": "Private IP",
                    "asn": "BOGON",
                    "link": f"https://ipinfo.io/{observable_value}",
                }

            if "ip" in data:
                ip_resp = data.get("ip", "Unknown")
                city = data.get("city", "Unknown")
                region = data.get("region", "Unknown")
                asn_raw = data.get("org", "Unknown")
                country_code = data.get("country", "Unknown")

                # Attempt to resolve country name
                try:
                    country_obj = pycountry.countries.get(alpha_2=country_code)
                    country_name = country_obj.name if country_obj else "Unknown"
                except Exception:
                    country_name = "Unknown"

                return {
                    "ip": ip_resp,
                    "geolocation": f"{city}, {region}",
                    "country_code": country_code,
                    "country_name": country_name,
                    "hostname": data.get("hostname", "Unknown"),
                    "asn": asn_raw,  # Keep raw string for parsing in export logic
                    "link": f"https://ipinfo.io/{ip_resp}",
                }

        except Exception as e:
            logger.error("Error querying ipinfo for '%s': %s", observable_value, e, exc_info=True)

        return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"ipinfo_{k}": None for k in ["cn", "country", "geo", "asn", "org"]}

        asn_data = analysis_result.get("asn").split(" ", 1) if analysis_result.get("asn") else []

        return {
            "ipinfo_cn": analysis_result.get("country_code"),
            "ipinfo_country": analysis_result.get("country_name"),
            "ipinfo_geo": analysis_result.get("geolocation"),
            "ipinfo_asn": asn_data[0] if len(asn_data) > 0 else None,
            "ipinfo_org": asn_data[1] if len(asn_data) > 1 else None,
        }
