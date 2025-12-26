import logging
from typing import Any, Optional

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class AbuseIPDBEngine(BaseEngine):
    @property
    def name(self):
        return "abuseipdb"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        # AbuseIPDB only supports IPs, so we want it to run AFTER any potential DNS resolution
        return True

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.secrets.abuseipdb, "Accept": "application/json"}
        params = {"ipAddress": observable_value}

        try:
            response = requests.get(url, headers=headers, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()
            json_response = response.json()

            if "data" not in json_response:
                return None

            data = json_response["data"]
            return {
                "reports": data.get("totalReports", 0),
                "risk_score": data.get("abuseConfidenceScore", 0),
                "link": f"https://www.abuseipdb.com/check/{observable_value}",
            }
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"a_ipdb_reports": None, "a_ipdb_risk": None}
        return {"a_ipdb_reports": analysis_result.get("reports"), "a_ipdb_risk": analysis_result.get("risk_score")}
