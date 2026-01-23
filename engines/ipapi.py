import logging
from collections.abc import Mapping
from typing import Any

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class IPAPIEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "ipapi"

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
            url = "https://api.ipapi.is"
            headers = {"Content-Type": "application/json"}
            data = {"q": observable_value}

            # Validate API key (should be non-empty and 20 characters)
            if self.secrets.ipapi and len(self.secrets.ipapi) == 20:
                # Use API key if it matches the expected length
                data["key"] = self.secrets.ipapi
            else:
                # Don't use API key if it doesn't match the format
                if self.secrets.ipapi:
                    logger.warning(
                        "ipapi API key format is invalid, querying without API key for '%s'",
                        observable_value,
                    )
                else:
                    logger.warning(
                        "Be careful, you don't use API key for ipapi, rate limit can happen more often (query: '%s')",  # noqa: E501
                        observable_value,
                    )

            response = requests.post(
                url,
                json=data,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()
            if "ip" in data:
                # Reformat ASN field as per original logic
                if "asn" not in data or not data["asn"]:
                    data["asn"] = {"asn": "Unknown", "org": "Unknown"}
                elif "asn" in data["asn"]:
                    data["asn"]["asn"] = f"AS{data['asn']['asn']}"
                return data

        except Exception as e:
            logger.error("Error querying ipapi for '%s': %s", observable_value, e, exc_info=True)

        return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {
                f"ipapi_{k}": None
                for k in [
                    "ip",
                    "is_vpn",
                    "is_tor",
                    "is_proxy",
                    "is_abuser",
                    "city",
                    "state",
                    "country",
                    "country_code",
                    "asn",
                    "org",
                    "vpn_service",
                    "vpn_url",
                ]
            }

        location_data = analysis_result.get("location", {})
        asn_data = analysis_result.get("asn", {})
        vpn_data = analysis_result.get("vpn", {})

        return {
            "ipapi_ip": analysis_result.get("ip"),
            "ipapi_is_vpn": analysis_result.get("is_vpn"),
            "ipapi_is_tor": analysis_result.get("is_tor"),
            "ipapi_is_proxy": analysis_result.get("is_proxy"),
            "ipapi_is_abuser": analysis_result.get("is_abuser"),
            "ipapi_city": location_data.get("city"),
            "ipapi_state": location_data.get("state"),
            "ipapi_country": location_data.get("country"),
            "ipapi_country_code": location_data.get("country_code"),
            "ipapi_asn": asn_data.get("asn"),
            "ipapi_org": asn_data.get("org"),
            "ipapi_vpn_service": vpn_data.get("service"),
            "ipapi_vpn_url": vpn_data.get("url"),
        }
