import logging
from collections.abc import Mapping
from typing import Any

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class IPQueryEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "ipquery"

    @property
    @override
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    @override
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            url = f"https://api.ipquery.io/{observable_value}"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()
            if "ip" in data:
                location = data.get("location", {})
                isp_data = data.get("isp", {})
                risk_data = data.get("risk", {})

                return {
                    "ip": data.get("ip", "Unknown"),
                    "geolocation": f"{location.get('city', 'Unknown')}, {location.get('state', 'Unknown')}",  # noqa: E501
                    "country_code": location.get("country_code", "Unknown"),
                    "country_name": location.get("country", "Unknown"),
                    "isp": isp_data.get("isp", "Unknown"),
                    "asn": isp_data.get("asn", "Unknown"),
                    "is_vpn": risk_data.get("is_vpn", False),
                    "is_tor": risk_data.get("is_tor", False),
                    "is_proxy": risk_data.get("is_proxy", False),
                    "risk_score": risk_data.get("risk_score", "Unknown"),
                    "link": f"https://api.ipquery.io/{observable_value}",
                }

        except Exception as e:
            logger.error(
                "Error querying ipquery for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )

        return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {
                f"ipq_{k}": None
                for k in ["cn", "country", "geo", "asn", "isp", "vpn", "tor", "proxy"]
            }

        return {
            "ipq_cn": analysis_result.get("country_code"),
            "ipq_country": analysis_result.get("country_name"),
            "ipq_geo": analysis_result.get("geolocation"),
            "ipq_asn": analysis_result.get("asn"),
            "ipq_isp": analysis_result.get("isp"),
            "ipq_vpn": analysis_result.get("is_vpn"),
            "ipq_tor": analysis_result.get("is_tor"),
            "ipq_proxy": analysis_result.get("is_proxy"),
        }
