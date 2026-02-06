import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingEngine(BaseEngine):
    @property
    def name(self):
        return "google_safe_browsing"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.URL

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        api_key = self.secrets.google_safe_browsing

        try:
            url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            params: dict[str, str] = {"key": api_key}

            threat_entries = []
            match observable_type:
                case ObservableType.URL:
                    threat_entries.append({"url": observable_value})
                case ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6:
                    threat_entries.append({"url": f"http://{observable_value}"})
                case _:
                    return None

            body = {
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                        "THREAT_TYPE_UNSPECIFIED",
                    ],
                    "platformTypes": ["ALL"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": threat_entries,
                }
            }

            response = requests.post(
                url,
                params=params,
                json=body,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()
            if "matches" in data:
                return {"threat_found": "Threat found", "details": data["matches"]}
            return {"threat_found": "No threat found", "details": None}

        except Exception as e:
            logger.error(
                "Error while querying Google Safe Browsing for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        return {"gsb_threat": analysis_result.get("threat_found") if analysis_result else None}
