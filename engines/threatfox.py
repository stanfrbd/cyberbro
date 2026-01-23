import json
import logging
from collections.abc import Mapping
from typing import Any

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class ThreatFoxEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "threatfox"

    @property
    @override
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "URL"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            # If it's a URL, use the domain portion
            if observable_type == "URL":
                domain_part = observable_value.split("/")[2].split(":")[0]
                observable = domain_part
            else:
                observable = observable_value

            url = "https://threatfox-api.abuse.ch/api/v1/"
            payload = {"query": "search_ioc", "search_term": observable}
            headers = {"Auth-Key": self.secrets.threatfox}

            response = requests.post(
                url,
                data=json.dumps(payload),
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()

            result = response.json()
            data = result.get("data", [])

            malware_printable_set = set()
            count = 0

            if isinstance(data, list):
                for item in data:
                    if item:
                        malware_name = item.get("malware_printable", "Unknown")
                        malware_printable_set.add(malware_name)
                count = len(data)

            link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{observable}"
            return {
                "count": count,
                "malware_printable": list(malware_printable_set),
                "link": link,
            }

        except Exception as e:
            logger.error(
                "Error querying ThreatFox for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {f"tf_{k}": None for k in ["count", "malware"]}

        malware_str = ", ".join(analysis_result.get("malware_printable", []))
        return {
            "tf_count": analysis_result.get("count"),
            "tf_malware": malware_str if malware_str else None,
        }
