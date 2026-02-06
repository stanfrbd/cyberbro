import logging
import time
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class GoogleCSEEngine(BaseEngine):
    @property
    def name(self):
        return "google"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
            | ObservableType.EMAIL
        )

    def analyze(
        self, observable_value: str, observable_type: ObservableType, dorks: str = ""
    ) -> dict[str, Any] | None:
        # This engine requires specific secrets (CSE_CX, CSE_KEY)
        google_cse_cx: str = self.secrets.google_cse_cx
        google_cse_key: str = self.secrets.google_cse_key

        if not all([google_cse_cx, google_cse_key]):
            logger.error(
                "Missing secrets for Google Custom Search Engine for %s observable",
                observable_value,
            )
            return None

        time.sleep(0.5)  # Respect rate limit

        dorks_prefix: str = dorks.strip()
        if dorks_prefix:
            dorks_prefix += " "

        q = f'{dorks_prefix}"{observable_value}"'

        url: str = "https://www.googleapis.com/customsearch/v1"
        params: dict[str, str] = {"key": google_cse_key, "cx": google_cse_cx, "q": q}

        try:
            resp = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=10
            )

            data = None
            try:
                data = resp.json()
            except ValueError:
                data = None

            if resp.status_code >= 400 or (isinstance(data, dict) and "error" in data):
                msg = "API Error"
                if isinstance(data, dict) and "error" in data:
                    err = data.get("error", {})
                    msg = (
                        err.get("message")
                        or (err.get("errors", [{}])[0].get("message"))
                        or str(err)
                    )
                logger.warning("Google CSE error for '%s': %s", observable_value, msg)
                return {
                    "results": [
                        {
                            "title": "API Error",
                            "description": "Check Cyberbro logs for details",
                            "url": "",
                        }
                    ],
                    "total": 0,
                }

            if data is None:
                logger.error(
                    "Expected JSON from Google CSE for '%s' but got none.", observable_value
                )
                return None

            items: list = data.get("items", [])
            total_results: int = int(data.get("searchInformation", {}).get("totalResults", 0))

            search_results = [
                {
                    "title": item.get("title"),
                    "description": item.get("snippet"),
                    "url": item.get("link"),
                }
                for item in items
            ]

            return {"results": search_results, "total": total_results}

        except requests.RequestException as e:
            logger.error(
                "Network error querying Google CSE for '%s': %s", observable_value, e, exc_info=True
            )
        except Exception as e:
            logger.error(
                "Unexpected error querying Google CSE for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )

        return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Since original export fields are missing, provide a count
        return {"google_results_count": analysis_result.get("total") if analysis_result else None}
