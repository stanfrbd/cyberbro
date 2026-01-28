import logging
from typing import Any

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class URLScanEngine(BaseEngine):
    @property
    def name(self):
        return "urlscan"

    @property
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        query_fields = {
            "IPv4": "ip",
            "IPv6": "ip",
            "MD5": "files.md5",
            "SHA1": "files.sha1",
            "SHA256": "files.sha256",
            "URL": "page.domain",
            "FQDN": "page.domain",
        }
        query_field = query_fields.get(observable_type, "page.domain")

        try:
            if observable_type == "URL":
                domain_part = observable_value.split("/")[2].split(":")[0]
                observable = domain_part
            else:
                observable = observable_value

            # TODO: Bug #4 - Observable values are not URL-encoded
            # Special characters in domain/hash could break the query string
            # Consider using: urllib.parse.quote(observable) or requests params parameter
            url = f"https://urlscan.io/api/v1/search/?q={query_field}:{observable}"

            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
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
                "link": f"https://urlscan.io/search/#{query_field}:{observable}",
            }

        except Exception as e:
            logger.error(
                "Error querying urlscan.io for '%s': %s", observable_value, e, exc_info=True
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
