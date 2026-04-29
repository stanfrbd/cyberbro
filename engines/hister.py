import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class HisterEngine(BaseEngine):
    @property
    def name(self):
        return "hister"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
            | ObservableType.EMAIL
            | ObservableType.CHROME_EXTENSION
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
        )

    def analyze(self, observable: Observable) -> dict | None:
        token: str = self.secrets.hister_token
        base_url: str = self.secrets.hister_base_url

        if not token or not base_url:
            logger.warning("Hister token or base URL not set")
            return None

        query = json.dumps(
            {"text": observable.value, "limit": 10, "fields": ["url", "title", "text"]}
        )
        url = f"{base_url.rstrip('/')}/search"
        headers = {
            "Authorization": f"Bearer {token}",
            "Origin": "hister://",
        }
        params = {"query": query}

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

            documents = json_response.get("documents", [])
            results = []
            seen_urls: set[str] = set()
            for doc in documents:
                doc_url = doc.get("url", "")
                if not doc_url or doc_url in seen_urls:
                    continue
                seen_urls.add(doc_url)
                added_ts = doc.get("added", 0)
                added_date = (
                    datetime.fromtimestamp(added_ts, tz=timezone.utc).strftime("%Y-%m-%d")
                    if added_ts
                    else ""
                )
                results.append(
                    {
                        "url": doc_url,
                        "title": doc.get("title", ""),
                        "added": added_date,
                    }
                )

            search_url = f"{base_url.rstrip('/')}/?q={quote(observable.value)}"
            return {
                "total": json_response.get("total", 0),
                "results": results,
                "link": search_url,
            }
        except Exception as e:
            logger.error(f"Error querying Hister: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "hister_total": None,
                "hister_results": None,
            }
        return {
            "hister_total": analysis_result.get("total"),
            "hister_results": len(analysis_result.get("results", [])),
        }
