import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class VPNDetectionEngine(BaseEngine):
    @property
    def name(self):
        return "vpndetection"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        try:
            url = f"https://api.vpndetection.io/{observable.value}"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()
            if "ip" in data:
                return self._parse(data)

        except Exception as e:
            logger.error(
                "Error querying VPNDetection for '%s': %s", observable.value, e, exc_info=True
            )

        return None

    def _parse(self, data: dict[str, Any]) -> dict[str, Any]:
        location = data.get("location") or {}
        asn_data = data.get("asn") or {}
        relay = data.get("relay") or {}
        asn = asn_data.get("asn")

        return {
            "ip": data["ip"],
            "is_vpn": data.get("is_vpn", False),
            "is_tor": data.get("is_tor", False),
            "is_relay": data.get("is_relay", False),
            "relay_provider": relay.get("provider") or None,
            "country_code": location.get("country", "Unknown"),
            "country_name": location.get("country_name", "Unknown"),
            "asn": f"AS{asn}" if asn else "Unknown",
            "as_name": asn_data.get("name", "Unknown"),
            "link": f"https://vpndetection.io/{data['ip']}",
        }

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"vpnd_{k}": None
                for k in ["cn", "country", "asn", "as_name", "vpn", "tor", "relay"]
            }

        return {
            "vpnd_cn": analysis_result.get("country_code"),
            "vpnd_country": analysis_result.get("country_name"),
            "vpnd_asn": analysis_result.get("asn"),
            "vpnd_as_name": analysis_result.get("as_name"),
            "vpnd_vpn": analysis_result.get("is_vpn"),
            "vpnd_tor": analysis_result.get("is_tor"),
            "vpnd_relay": analysis_result.get("relay_provider") or analysis_result.get("is_relay"),
        }
