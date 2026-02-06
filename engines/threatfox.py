import json
import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class ThreatFoxEngine(BaseEngine):
    @property
    def name(self):
        return "threatfox"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.URL

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        try:
            # If it's a URL, use the domain portion
            if observable_type is ObservableType.URL:
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
                "Error querying ThreatFox for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"tf_{k}": None for k in ["count", "malware"]}

        malware_str = ", ".join(analysis_result.get("malware_printable", []))
        return {
            "tf_count": analysis_result.get("count"),
            "tf_malware": malware_str if malware_str else None,
        }
