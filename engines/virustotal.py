import base64
import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class VirusTotalEngine(BaseEngine):
    @property
    def name(self):
        return "virustotal"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )

    def analyze(self, observable_value: str, observable_type: ObservableType) -> dict | None:
        headers = {"x-apikey": self.secrets.virustotal}
        # TODO: validate api_key before API call

        match observable_type:
            case ObservableType.IPV4 | ObservableType.IPV6:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable_value}"
                link = f"https://www.virustotal.com/gui/ip-address/{observable_value}/detection"
            case ObservableType.FQDN:
                url = f"https://www.virustotal.com/api/v3/domains/{observable_value}"
                link = f"https://www.virustotal.com/gui/domain/{observable_value}/detection"
            case ObservableType.URL:
                encoded_url = (
                    base64.urlsafe_b64encode(observable_value.encode()).decode().strip("=")
                )
                url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
                link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
            case _:
                url = f"https://www.virustotal.com/api/v3/files/{observable_value}"
                link = f"https://www.virustotal.com/gui/file/{observable_value}/detection"

        try:
            response = requests.get(
                url, headers=headers, proxies=self.proxies, verify=self.ssl_verify, timeout=5
            )
            response.raise_for_status()
            data = response.json()

            if "data" in data and "attributes" in data["data"]:
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                total_malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                return {
                    "detection_ratio": f"{total_malicious}/{total}",
                    "total_malicious": total_malicious,
                    "link": link,
                    "community_score": attrs.get("reputation", 0),
                }
            return None

        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"vt_detect": None, "vt_nb_detect": None, "vt_community": None}
        return {
            "vt_detect": analysis_result.get("detection_ratio"),
            "vt_nb_detect": analysis_result.get("total_malicious"),
            "vt_community": analysis_result.get("community_score"),
        }
