import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class InternetDataEngine(BaseEngine):
    """IP ownership and network data from InternetData, no API key.

    Each address is sent to api.internetdata.io, see https://internetdata.io/terms
    and https://internetdata.io/privacy.
    """

    @property
    def name(self):
        return "internetdata"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        try:
            url = f"https://api.internetdata.io/{observable.value}"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()
            if "ip" in data:
                return self._parse(data)

        except Exception as e:
            logger.error(
                "Error querying InternetData for '%s': %s", observable.value, e, exc_info=True
            )

        return None

    def _parse(self, data: dict[str, Any]) -> dict[str, Any]:
        location = data.get("location") or {}
        asn_data = data.get("asn") or {}
        company = data.get("company") or {}
        abuse = data.get("abuse") or {}
        relay = data.get("relay") or {}
        asn = asn_data.get("asn")

        return {
            "ip": data["ip"],
            "country_code": location.get("country") or "Unknown",
            "country_name": location.get("country_name") or "Unknown",
            "asn": f"AS{asn}" if asn else "Unknown",
            "as_name": asn_data.get("name") or "Unknown",
            "company_name": company.get("name") or None,
            "company_domain": company.get("domain") or None,
            "hostname": data.get("hostname") or None,
            "abuse_email": abuse.get("email") or None,
            "is_tor": data.get("is_tor", False),
            "is_relay": data.get("is_relay", False),
            "relay_provider": relay.get("provider_name") or relay.get("provider") or None,
            "is_anycast": data.get("is_anycast", False),
            "is_bogon": data.get("is_bogon", False),
            "link": f"https://internetdata.io/{data['ip']}",
        }

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"inetd_{k}": None
                for k in [
                    "cn",
                    "country",
                    "asn",
                    "as_name",
                    "company",
                    "company_domain",
                    "hostname",
                    "abuse",
                    "tor",
                    "relay",
                    "anycast",
                ]
            }

        return {
            "inetd_cn": analysis_result.get("country_code"),
            "inetd_country": analysis_result.get("country_name"),
            "inetd_asn": analysis_result.get("asn"),
            "inetd_as_name": analysis_result.get("as_name"),
            "inetd_company": analysis_result.get("company_name"),
            "inetd_company_domain": analysis_result.get("company_domain"),
            "inetd_hostname": analysis_result.get("hostname"),
            "inetd_abuse": analysis_result.get("abuse_email"),
            "inetd_tor": analysis_result.get("is_tor"),
            "inetd_relay": analysis_result.get("relay_provider") or analysis_result.get("is_relay"),
            "inetd_anycast": analysis_result.get("is_anycast"),
        }
