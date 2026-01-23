import logging
from collections.abc import Mapping
from typing import Any

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class RostiEngine(BaseEngine):
    @property
    @override
    def name(self) -> str:
        return "rosti"

    @property
    @override
    def supported_types(self) -> list[str]:
        return ["IPv4", "IPv6", "FQDN", "URL", "Email", "MD5", "SHA1", "SHA256"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict:
        """Query Rösti API and normalize the response structure."""
        if not self.secrets.rosti_api_key:
            logger.warning("Rösti API key is not configured.")
            return {"success": False, "error_msg": "API key is not configured"}

        url = "https://api.rosti.bin.re/v2/iocs"
        headers = {"X-API-Key": self.secrets.rosti_api_key}
        params = {"q": observable_value, "pattern": "true"}

        try:
            response = self._make_request(
                url,
                headers=headers,
                params=params,
                timeout=8,
            )
            response.raise_for_status()
            payload = response.json()
        except (
            requests.exceptions.RequestException,
            requests.exceptions.JSONDecodeError,
        ) as exc:
            message: str = f"Error querying Rösti for {observable_value}: {exc}"
            logger.error(message, exc_info=True)
            return {"success": False, "error_msg": message}

        raw_results = payload.get("data", [])
        meta = payload.get("meta", {}) if isinstance(payload, dict) else {}

        normalized_results: list[dict[str, Any]] = []
        if isinstance(raw_results, list):
            for item in raw_results:
                if not isinstance(item, dict):
                    continue

                report_id = item.get("report")
                link = None
                if report_id:
                    link = f"https://rosti.bin.re/reports/{report_id}"

                normalized_results.append(
                    {
                        "value": item.get("value"),
                        "type": item.get("type"),
                        "category": item.get("category"),
                        "date": item.get("date"),
                        "comment": item.get("comment"),
                        "ids": item.get("ids"),
                        "report": item.get("report"),
                        "link": link,
                        "timestamp": item.get("timestamp"),
                        "risk": item.get("risk"),
                        "id": item.get("id"),
                    }
                )

        return {
            "count": len(normalized_results),
            "results": normalized_results,
            "total": meta.get("total"),
            "has_more": bool(meta.get("has_more")),
        }

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result or analysis_result.get("count", 0) == 0:
            return {"rosti_count": 0, "rosti_values": None, "rosti_types": None}

        values = [
            item.get("value") for item in analysis_result.get("results", []) if item.get("value")
        ]
        types = [
            item.get("type") for item in analysis_result.get("results", []) if item.get("type")
        ]

        values_preview = ", ".join(values[:5]) if values else None
        types_preview = ", ".join(types[:5]) if types else None

        return {
            "rosti_count": analysis_result.get("count"),
            "rosti_values": values_preview,
            "rosti_types": types_preview,
        }
