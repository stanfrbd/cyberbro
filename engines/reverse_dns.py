import logging
from collections.abc import Mapping

import dns.resolver
import dns.reversename
from typing_extensions import override

from models.base_engine import BaseEngine
from utils.utils import identify_observable_type, is_really_ipv6

logger = logging.getLogger(__name__)


class ReverseDNSEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "reverse_dns"

    @property
    @override
    def supported_types(self):
        return ["BOGON", "FQDN", "IPv4", "IPv6", "URL"]

    @property
    @override
    def is_pivot_engine(self):
        # This engine can change the observable type (e.g., FQDN -> IP)
        return True

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict | None:
        try:
            if observable_type in ["IPv4", "IPv6", "BOGON"]:
                reverse_name = dns.reversename.from_address(observable_value)
                answer = dns.resolver.resolve(reverse_name, "PTR")
                return {"reverse_dns": [str(answer[0])]}

            if observable_type == "FQDN":
                answer = dns.resolver.resolve(observable_value, "A")
                return {"reverse_dns": [str(ip) for ip in answer]}

            if observable_type == "URL":
                extracted = observable_value.split("/")[2]
                if ":" in extracted:
                    if is_really_ipv6(extracted):
                        reverse_name = dns.reversename.from_address(extracted)
                        answer = dns.resolver.resolve(reverse_name, "PTR")
                        return {"reverse_dns": [str(answer[0])]}
                    extracted = extracted.split(":")[0]

                extracted_type = identify_observable_type(extracted)
                if extracted_type == "FQDN":
                    answer = dns.resolver.resolve(extracted, "A")
                    return {"reverse_dns": [str(ip) for ip in answer]}
                if extracted_type == "IPv4":
                    reverse_name = dns.reversename.from_address(extracted)
                    answer = dns.resolver.resolve(reverse_name, "PTR")
                    return {"reverse_dns": [str(answer[0])]}

            return None
        except Exception as e:
            logger.debug(f"Reverse DNS failed: {e}")
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        rev_dns_data = analysis_result
        return {
            "rev_dns": bool(rev_dns_data),
            "dns_lookup": rev_dns_data.get("reverse_dns") if rev_dns_data else None,
        }
