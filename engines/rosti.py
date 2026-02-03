import logging
from typing import Any

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


def query_rosti(
    observable_value: str, api_key: str, proxies: dict, ssl_verify: bool
) -> dict[str, Any] | None:
    """Query Rösti API and normalize the response structure."""
    if not api_key:
        logger.warning("Rösti API key is not configured.")
        return None

    url = "https://api.rosti.bin.re/v2/iocs"
    headers = {"X-API-Key": api_key}
    params = {"q": observable_value, "pattern": "true"}

    try:
        response = requests.get(
            url, headers=headers, params=params, proxies=proxies, verify=ssl_verify, timeout=8
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.error("Error querying Rösti for '%s': %s", observable_value, exc, exc_info=True)
        return None

    raw_results = payload.get("data", []) if isinstance(payload, dict) else []
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


class RostiEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "rosti"

    @property
    def supported_types(self) -> list[str]:
        return ["IPv4", "IPv6", "FQDN", "URL", "Email", "MD5", "SHA1", "SHA256"]

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        return query_rosti(
            observable_value, self.secrets.rosti_api_key, self.proxies, self.ssl_verify
        )

    def create_export_row(self, analysis_result: Any) -> dict:
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
