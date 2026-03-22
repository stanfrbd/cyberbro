import logging
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import dns.reversename

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from utils.utils import identify_observable_type, is_really_ipv6

logger = logging.getLogger(__name__)


class ReverseDNSEngine(BaseEngine):
    @property
    def name(self):
        return "reverse_dns"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.URL
        )

    @property
    def is_pivot_engine(self):
        # This engine can change the observable type (e.g., FQDN -> IP)
        return True

    def _resolve_ptr(self, value: str) -> dict[str, list[str]]:
        reverse_name = dns.reversename.from_address(value)
        answer = dns.resolver.resolve(reverse_name, "PTR")
        return {"reverse_dns": [str(answer[0])]}

    def _resolve_a(self, value: str) -> dict[str, list[str]]:
        answer = dns.resolver.resolve(value, "A")
        return {"reverse_dns": [str(ip) for ip in answer]}

    def _extract_url_host(self, url: str) -> str:
        parsed_url = urlparse(url)
        return parsed_url.hostname or ""

    def analyze(self, observable: Observable) -> dict | None:
        observable_value = observable.value
        observable_type = observable.type

        try:
            if observable_type in (
                ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.BOGON
            ):
                return self._resolve_ptr(observable_value)

            if observable_type is ObservableType.FQDN:
                return self._resolve_a(observable_value)

            if observable_type is ObservableType.URL:
                extracted = self._extract_url_host(observable_value)
                if not extracted:
                    logger.debug(f"Failed to parse URL: {observable_value}")
                    return None

                if is_really_ipv6(extracted):
                    return self._resolve_ptr(extracted)

                try:
                    extracted_type = identify_observable_type(extracted)
                except ValueError:
                    return None

                match extracted_type:
                    case ObservableType.FQDN:
                        return self._resolve_a(extracted)
                    case ObservableType.IPV4:
                        return self._resolve_ptr(extracted)
                    case _:
                        return None

            return None
        except Exception as e:
            logger.debug(f"Reverse DNS failed: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        rev_dns_data = analysis_result
        return {
            "rev_dns": bool(rev_dns_data),
            "dns_lookup": rev_dns_data.get("reverse_dns") if rev_dns_data else None,
        }
