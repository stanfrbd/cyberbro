import logging
from typing import Any

import pycountry
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

    def analyze(self, observable_value: str, observable_type: str) -> dict | None:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.secrets.abuseipdb, "Accept": "application/json"}
        params = {"ipAddress": observable_value}

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()
            json_response = response.json()

            if "data" not in json_response:
                return None

            data = json_response["data"]

            # Extract country code and resolve country name
            country_code = data.get("countryCode", "")
            country_name = "Unknown"
            if country_code:
                try:
                    country_obj = pycountry.countries.get(alpha_2=country_code)
                    country_name = country_obj.name if country_obj else "Unknown"
                except Exception:
                    country_name = "Unknown"

            return {
                "reports": data.get("totalReports", 0),
                "risk_score": data.get("abuseConfidenceScore", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country_code": country_code,
                "country_name": country_name,
                "usage_type": data.get("usageType", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "hostnames": data.get("hostnames", []),
                "is_tor": data.get("isTor", False),
                "last_reported_at": data.get("lastReportedAt", ""),
                "link": f"https://www.abuseipdb.com/check/{observable_value}",
            }
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "a_ipdb_reports": None,
                "a_ipdb_risk": None,
                "a_ipdb_country": None,
                "a_ipdb_isp": None,
                "a_ipdb_domain": None,
                "a_ipdb_usage_type": None,
                "a_ipdb_is_tor": None,
                "a_ipdb_last_reported": None,
            }
        return {
            "a_ipdb_reports": analysis_result.get("reports"),
            "a_ipdb_risk": analysis_result.get("risk_score"),
            "a_ipdb_country": analysis_result.get("country_name"),
            "a_ipdb_isp": analysis_result.get("isp"),
            "a_ipdb_domain": analysis_result.get("domain"),
            "a_ipdb_usage_type": analysis_result.get("usage_type"),
            "a_ipdb_is_tor": analysis_result.get("is_tor"),
            "a_ipdb_last_reported": analysis_result.get("last_reported_at"),
        }
