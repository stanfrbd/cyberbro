import logging
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class MISPEngine(BaseEngine):
    @property
    def name(self):
        return "misp"

    @property
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    def _map_observable_type(self, observable_type: str) -> str:
        mapping = {
            "URL": "url",
            "IPv4": ["ip-dst", "ip-src", "ip-src|port", "ip-dst|port", "domain|ip"],
            "IPv6": ["ip-dst", "ip-src", "ip-src|port", "ip-dst|port", "domain|ip"],
            "FQDN": ["domain", "domain|ip", "hostname", "hostname|port"],
            "SHA256": "sha256",
            "SHA1": "sha1",
            "MD5": "md5",
        }
        return mapping.get(observable_type, "")

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        api_key = self.secrets.misp_api_key
        misp_url = self.secrets.misp_url

        try:
            if not api_key or not misp_url:
                logger.error("MISP API key or URL is required")
                return None

            misp_url = misp_url.rstrip("/")
            url = f"{misp_url}/attributes/restSearch"
            headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}

            misp_type = self._map_observable_type(observable_type)
            if not misp_type:
                logger.error("Unsupported observable type for MISP: %s", observable_type)
                return None

            payload = {"returnFormat": "json", "value": observable_value, "type": misp_type}

            response = requests.post(url, json=payload, headers=headers, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            result = response.json()
            attributes = result.get("response", {}).get("Attribute", [])

            event_data = []
            seen_event_ids = set()
            first_seen = None
            last_seen = None
            count = 0

            if isinstance(attributes, list):
                for attribute in attributes:
                    timestamp = attribute.get("timestamp")
                    if timestamp:
                        if first_seen is None or int(timestamp) < int(first_seen):
                            first_seen = timestamp
                        if last_seen is None or int(timestamp) > int(last_seen):
                            last_seen = timestamp

                    event = attribute.get("Event", {})
                    event_id = event.get("id")

                    if event_id in seen_event_ids:
                        continue

                    seen_event_ids.add(event_id)
                    event_title = event.get("info", "Unknown")
                    event_url = f"{misp_url}/events/view/{event_id}" if event_id else None

                    event_data.append({"title": event_title, "url": event_url, "timestamp": timestamp})

                    count = len(attributes)  # Total attributes count

                event_data.sort(key=lambda x: x["timestamp"], reverse=True)
                event_data = event_data[:5]  # Keep only 5 most recent events

            link = f"{misp_url}/attributes/index?value={quote(observable_value)}"

            if first_seen:
                first_seen = datetime.fromtimestamp(int(first_seen), tz=timezone.utc).strftime("%Y-%m-%d")
            if last_seen:
                last_seen = datetime.fromtimestamp(int(last_seen), tz=timezone.utc).strftime("%Y-%m-%d")

            return {
                "count": count,
                "events": event_data,
                "link": link,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }

        except Exception as e:
            logger.error("Error querying MISP for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"misp_{k}": None for k in ["count", "first_seen", "last_seen"]}

        return {
            "misp_count": analysis_result.get("count"),
            "misp_first_seen": analysis_result.get("first_seen"),
            "misp_last_seen": analysis_result.get("last_seen"),
        }
