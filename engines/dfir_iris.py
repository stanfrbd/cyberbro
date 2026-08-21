import json
import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class DFIRIrisEngine(BaseEngine):
    @property
    def name(self):
        return "dfir_iris"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
        )

    def _build_search_body(self, observable: Observable, search_type: str) -> dict[str, str]:
        """Build the request body for a DFIR-IRIS search, applying the same selective
        wildcard pattern used for both ioc and notes searches."""
        match observable.type:
            case (
                ObservableType.IPV4
                | ObservableType.IPV6
                | ObservableType.MD5
                | ObservableType.SHA1
                | ObservableType.SHA256
                | ObservableType.BOGON
            ):
                return {"search_value": f"%{observable.value}", "search_type": search_type}
            case ObservableType.FQDN | ObservableType.URL:
                return {"search_value": f"{observable.value}%", "search_type": search_type}
            case _:
                return {"search_value": f"{observable.value}", "search_type": search_type}

    def _query(self, dfir_iris_url: str, body: dict[str, str]) -> Any:
        """Send a search request to DFIR-IRIS and return the parsed JSON response."""
        dfir_iris_api_key = self.secrets.dfir_iris_api_key
        url = f"{dfir_iris_url}/search"
        params: dict[str, int] = {"cid": 1}
        headers = {
            "Authorization": f"Bearer {dfir_iris_api_key}",
            "Content-Type": "application/json",
        }
        payload = json.dumps(body)
        # NOTE: Original code uses proxies=None here, keeping that behavior.
        response = requests.post(
            url,
            params=params,
            headers=headers,
            data=payload,
            proxies=None,
            verify=self.ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _extract_case_ids(data: Any) -> list[int]:
        """Extract the case_ids from a DFIR-IRIS search response, if any."""
        if not data or "data" not in data or not data["data"]:
            return []
        return [i["case_id"] for i in data["data"]]

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        dfir_iris_url = self.secrets.dfir_iris_url

        try:
            ioc_body = self._build_search_body(observable, "ioc")
            ioc_data = self._query(dfir_iris_url, ioc_body)
        except Exception as e:
            logger.error(
                "Error querying DFIR-IRIS for '%s': %s", observable.value, e, exc_info=True
            )
            return None

        ioc_links = [
            f"{dfir_iris_url}/case/ioc?cid={case_id}"
            for case_id in self._extract_case_ids(ioc_data)
        ]

        notes_links: list[str] = []
        if self.secrets.dfir_iris_search_notes:
            try:
                notes_body = self._build_search_body(observable, "notes")
                notes_data = self._query(dfir_iris_url, notes_body)
                notes_links = [
                    f"{dfir_iris_url}/case/notes?cid={case_id}"
                    for case_id in self._extract_case_ids(notes_data)
                ]
            except Exception as e:
                logger.warning(
                    "Error querying DFIR-IRIS notes for '%s': %s",
                    observable.value,
                    e,
                    exc_info=True,
                )

        if not ioc_links and not notes_links:
            return None

        unique_links = sorted(set(ioc_links) | set(notes_links))
        return {"reports": len(unique_links), "links": unique_links}

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"dfir_iris_total_count": None, "dfir_iris_link": None}

        links_str = ", ".join(analysis_result.get("links", []))
        return {
            "dfir_iris_total_count": analysis_result.get("reports"),
            "dfir_iris_link": links_str if links_str else None,
        }
