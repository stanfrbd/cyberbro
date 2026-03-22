import logging
from typing import Any
from urllib.parse import quote

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class URLScanEngine(BaseEngine):
    @property
    def name(self):
        return "urlscan"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        query_fields: dict[ObservableType, str] = {
            ObservableType.IPV4: "ip",
            ObservableType.IPV6: "ip",
            ObservableType.MD5: "files.md5",
            ObservableType.SHA1: "files.sha1",
            ObservableType.SHA256: "files.sha256",
            ObservableType.URL: "page.domain",
            ObservableType.FQDN: "page.domain",
        }
        query_field = query_fields.get(observable.type, "page.domain")

        try:
            if observable.type is ObservableType.URL:
                query_value = observable.value.split("/")[2].split(":")[0]
            else:
                query_value = observable.value

            url = "https://urlscan.io/api/v1/search/"
            # URLQuery requires IPv6 addresses to be quoted, due to the colons
            # So far, testing seems to indicate quotes work for all query types
            params: dict[str, str] = {"q": f"{query_field}:{quote(query_value)}"}

            response = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=5
            )
            response.raise_for_status()

            result = response.json()
            results = result.get("results", [])
            scan_count = result.get("total", 0)

            domain_count = {}
            for entry in results:
                page_info = entry.get("page", {})
                domain = page_info.get("domain", "Unknown")
                domain_count[domain] = domain_count.get(domain, 0) + 1

            sorted_domains = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
            top_domains = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]

            return {
                "scan_count": scan_count,
                "top_domains": top_domains,
                "link": f"https://urlscan.io/search/#{query_field}:{query_value}",
            }

        except Exception as e:
            logger.error(
                "Error querying urlscan.io for '%s': %s", observable.value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"urlscan_{k}": None for k in ["count", "top_domains"]}

        domains = analysis_result.get("top_domains", [])
        top_domains_str = ", ".join([d["domain"] for d in domains])

        return {
            "urlscan_count": analysis_result.get("scan_count"),
            "urlscan_top_domains": top_domains_str if top_domains_str else None,
        }
