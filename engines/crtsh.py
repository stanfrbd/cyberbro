import logging
from typing import Any, Optional

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class CrtShEngine(BaseEngine):
    @property
    def name(self):
        return "crtsh"

    @property
    def supported_types(self):
        return ["FQDN", "URL"]

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        try:
            # If observable is a URL, extract domain
            if observable_type == "URL":
                domain_part = observable_value.split("/")[2].split(":")[0]
                observable = domain_part
            else:
                observable = observable_value

            url = f"https://crt.sh/json?q={observable}"

            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=20)
            response.raise_for_status()

            results = response.json()
            domain_count = {}
            for entry in results:
                domains = set()
                common_name = entry.get("common_name")
                if common_name:
                    domains.add(common_name)

                name_value = entry.get("name_value")
                if name_value:
                    for el in name_value.split("\n"):
                        if el:
                            domains.add(str(el).strip())

                for domain in domains:
                    domain_count[domain] = domain_count.get(domain, 0) + 1

            # Sort and extract top 5
            sorted_domains = sorted(domain_count.items(), key=lambda item: item[1], reverse=True)
            top_domains = [{"domain": dmn, "count": cnt} for dmn, cnt in sorted_domains[:5]]
            return {
                "top_domains": top_domains,
                "link": f"https://crt.sh/?q={observable}",
            }

        except Exception as e:
            logger.error("Error querying crt.sh for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"crtsh_top_domains": None}

        domains = analysis_result.get("top_domains", [])
        top_domains_str = ", ".join([d["domain"] for d in domains])

        return {"crtsh_top_domains": top_domains_str if top_domains_str else None}
