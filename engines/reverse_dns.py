import logging
from typing import Any

import dns.resolver
import dns.reversename
from pydantic import AnyUrl, ValidationError

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

    def analyze(self, observable: Observable) -> dict | None:
        observable_value = observable.value
        observable_type = observable.type
        try:
            if observable_type in [ObservableType.IPV4, ObservableType.IPV6, ObservableType.BOGON]:
                reverse_name = dns.reversename.from_address(observable_value)
                answer = dns.resolver.resolve(reverse_name, "PTR")
                return {"reverse_dns": [str(answer[0])]}

            if observable_type is ObservableType.FQDN:
                answer = dns.resolver.resolve(observable_value, "A")
                return {"reverse_dns": [str(ip) for ip in answer]}

            if observable_type is ObservableType.URL:
                try:
                    extracted: str = AnyUrl(observable_value).host or ""
                    if not extracted:
                        raise ValidationError
                except ValidationError:
                    logger.debug(f"Failed to parse URL: {observable_value}")
                    return None

                # Check for IPv6 address
                if ":" in extracted:
                    if is_really_ipv6(extracted):
                        reverse_name = dns.reversename.from_address(extracted)
                        answer = dns.resolver.resolve(reverse_name, "PTR")
                        return {"reverse_dns": [str(answer[0])]}
                    extracted = extracted.split(":")[0]

                # TODO: Fix identify_observable_type to not return "Unknown"
                extracted_type: ObservableType = identify_observable_type(extracted)
                # assert isinstance(extracted_type, ObservableType)
                match extracted_type:
                    case ObservableType.FQDN:
                        answer = dns.resolver.resolve(extracted, "A")
                        return {"reverse_dns": [str(ip) for ip in answer]}
                    case ObservableType.IPV4:
                        reverse_name = dns.reversename.from_address(extracted)
                        answer = dns.resolver.resolve(reverse_name, "PTR")
                        return {"reverse_dns": [str(answer[0])]}
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
