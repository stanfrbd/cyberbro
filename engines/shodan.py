import logging
from typing import Any

import requests
from requests.exceptions import HTTPError, JSONDecodeError

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class ShodanEngine(BaseEngine):
    @property
    def name(self):
        return "shodan"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        return True

    def analyze(self, observable_value: str, observable_type: str) -> dict | None:
        headers = {"Accept": "application/json"}
        params = {"key": self.secrets.shodan}
        url = f"https://api.shodan.io/shodan/host/{observable_value}"

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()

            return {
                "ports": data.get("ports", []),
                "tags": data.get("tags", []),
                "link": f"https://www.shodan.io/host/{observable_value}",
            }
        except (HTTPError, JSONDecodeError, Exception) as e:
            logger.error(f"Error querying Shodan: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        return {"shodan_ports": analysis_result.get("ports") if analysis_result else None}
