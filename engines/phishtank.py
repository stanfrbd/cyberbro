import base64
import logging
from typing import Any
from urllib.parse import urlparse

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class PhishTankEngine(BaseEngine):
    @property
    def name(self):
        return "phishtank"

    @property
    def supported_types(self):
        return ["FQDN", "URL"]

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        headers = {"User-Agent": "phishtank/Cyberbro"}
        observable_to_analyze = observable_value

        if observable_type == "FQDN":
            observable_to_analyze = f"http://{observable_value}"

        # Ensure URL has a path (e.g., adds / to http://domain.com)
        parsed = urlparse(observable_to_analyze)
        if not parsed.path:
            observable_to_analyze += "/"

        data = {
            "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
            "format": "json",
        }

        try:
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=data,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()
            json_data = response.json()

            if "results" in json_data:
                return json_data["results"]

        except Exception as e:
            logger.error(
                "Error querying PhishTank for '%s': %s", observable_value, e, exc_info=True
            )

        return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"phishtank_{k}": None for k in ["in_db", "verified", "valid"]}

        # The API returns an inner 'results' key which holds the actual data
        return {
            "phishtank_in_db": analysis_result.get("in_database"),
            "phishtank_verified": analysis_result.get("verified"),
            "phishtank_valid": analysis_result.get("valid"),
        }
