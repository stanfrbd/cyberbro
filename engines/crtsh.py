import logging
from typing import Any

import requests
from requests.exceptions import ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class CrtShEngine(BaseEngine):
    @property
    def name(self):
        return "crtsh"

    @property
    @override
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        # If observable is a URL, extract domain
        if observable.type is ObservableType.URL:
            query_value: str = observable._return_fqdn_from_url()
            if not query_value:
                logger.error(f"Invalid URL passed to crtsh: {observable.value}")
                return None
        else:
            query_value = observable.value

        url = "https://crt.sh/json"
        params: dict[str, str] = {"q": query_value}

        try:
            response = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=20
            )
            response.raise_for_status()

            results = response.json()

        except (ReadTimeout, ConnectTimeout):
            """
            Crt.sh can be **SLOW**, especially for large domains, or domains
            with a long certificate history.
            """
            logger.info(f"Timeout occurred while querying crt.sh for {observable.value}.")
            return None
        except HTTPError as e:
            logger.error("Error querying crt.sh for '%s': %s", observable.value, e, exc_info=True)
            return None
        except JSONDecodeError as e:
            msg: str = (
                f"Unexpected error while parsing response from crt.sh for {observable.value}: {e}"
            )
            logger.error(msg)
            return None

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
            "link": f"https://crt.sh/?q={query_value}",
        }

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"crtsh_top_domains": None}

        domains = analysis_result.get("top_domains", [])
        top_domains_str = ", ".join([d["domain"] for d in domains])

        return {"crtsh_top_domains": top_domains_str if top_domains_str else None}
