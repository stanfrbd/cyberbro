import base64
import logging
from collections.abc import Mapping

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class VirusTotalEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "virustotal"

    @property
    @override
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict | None:
        headers = {"x-apikey": self.secrets.virustotal}

        try:
            if observable_type in ["IPv4", "IPv6"]:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{observable_value}"
                link = f"https://www.virustotal.com/gui/ip-address/{observable_value}/detection"
            elif observable_type == "FQDN":
                url = f"https://www.virustotal.com/api/v3/domains/{observable_value}"
                link = f"https://www.virustotal.com/gui/domain/{observable_value}/detection"
            elif observable_type == "URL":
                encoded_url = (
                    base64.urlsafe_b64encode(observable_value.encode()).decode().strip("=")
                )
                url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
                link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
            else:
                url = f"https://www.virustotal.com/api/v3/files/{observable_value}"
                link = f"https://www.virustotal.com/gui/file/{observable_value}/detection"

            response = requests.get(
                url,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
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

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {"vt_detect": None, "vt_nb_detect": None, "vt_community": None}
        return {
            "vt_detect": analysis_result.get("detection_ratio"),
            "vt_nb_detect": analysis_result.get("total_malicious"),
            "vt_community": analysis_result.get("community_score"),
        }
