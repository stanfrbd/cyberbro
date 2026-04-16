import logging
from typing import Any

import requests
from requests.exceptions import JSONDecodeError, RequestException

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class RansomwareLiveEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "ransomware_live"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        if not self.secrets.ransomware_live_api_key:
            logger.warning("Ransomware.Live API key is not configured.")
            return None

        if observable.type is ObservableType.URL:
            query_value: str = observable._return_fqdn_from_url()
            if not query_value:
                logger.error("Invalid URL passed to ransomware_live: %s", observable.value)
                return None
        else:
            query_value = observable.value

        url = f"https://api-pro.ransomware.live/victims/domain/{query_value}"
        headers = {"Authorization": f"Bearer {self.secrets.ransomware_live_api_key}"}

        try:
            response = requests.get(
                url,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
        except (RequestException, JSONDecodeError) as e:
            logger.error(
                "Error querying Ransomware.Live for '%s': %s",
                observable.value,
                e,
                exc_info=True,
            )
            return None

        victims: list[dict[str, Any]] = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                victims.append(
                    {
                        "victim": item.get("victim"),
                        "group": item.get("group"),
                        "published": item.get("published"),
                        "website": item.get("website"),
                        "description": item.get("description"),
                        "url": item.get("url"),
                    }
                )

        return {
            "found": len(victims) > 0,
            "count": len(victims),
            "victims": victims,
            "link": f"https://ransomware.live/#/victim/{query_value}",
        }

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "ransomware_live_found": None,
                "ransomware_live_count": None,
                "ransomware_live_groups": None,
                "ransomware_live_victims": None,
            }

        groups = list({v["group"] for v in analysis_result.get("victims", []) if v.get("group")})
        victim_names = list(
            {v["victim"] for v in analysis_result.get("victims", []) if v.get("victim")}
        )

        return {
            "ransomware_live_found": analysis_result.get("found"),
            "ransomware_live_count": analysis_result.get("count"),
            "ransomware_live_groups": ", ".join(groups) if groups else None,
            "ransomware_live_victims": ", ".join(victim_names) if victim_names else None,
        }
