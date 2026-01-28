import logging
from typing import Any

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class SpurUSEngine(BaseEngine):
    @property
    def name(self):
        return "spur"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        return True  # IP-only engine

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        spur_url = f"https://spur.us/context/{observable_value}"
        api_key = self.secrets.spur_us

        """TODO: test for api_key and return specific error if invalid"""

        try:
            if api_key and api_key.strip():
                api_url = f"https://api.spur.us/v2/context/{observable_value}"
                headers = {"Token": api_key}

                response = requests.get(
                    api_url,
                    proxies=self.proxies,
                    verify=self.ssl_verify,
                    headers=headers,
                    timeout=5,
                )
                response.raise_for_status()

                data = response.json()
                tunnels_info = "Not anonymous"

                if data.get("tunnels"):
                    for tunnel in data["tunnels"]:
                        if tunnel.get("operator"):
                            tunnels_info = tunnel["operator"]
                            break

                return {"link": spur_url, "tunnels": tunnels_info, "data": data}

            # No API key case (original logic)
            return {"link": spur_url, "tunnels": "Unknown - Behind Captcha"}

        except Exception as e:
            logger.error(
                "Error querying spur.us for IP '%s': %s", observable_value, e, exc_info=True
            )
            return {"link": spur_url, "tunnels": "Unknown - Behind Captcha"}

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"spur_us_anon": None}

        return {"spur_us_anon": analysis_result.get("tunnels")}
