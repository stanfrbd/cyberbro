import logging
from typing import Any

import dns.resolver
import dns.reversename

from models.base_engine import BaseEngine
from utils.utils import identify_observable_type, is_really_ipv6

logger = logging.getLogger(__name__)


class ReverseDNSEngine(BaseEngine):
    @property
    def name(self):
        return "reverse_dns"

    @property
    def supported_types(self):
        return ["BOGON", "FQDN", "IPv4", "IPv6", "URL"]

    @property
    def is_pivot_engine(self):
        # This engine can change the observable type (e.g., FQDN -> IP)
        return True

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
                # POTENTIAL FUTURE REMEDIATION: URL parsing uses fragile string split logic.
                # Current approach: split("/")[2] for domain extraction,
                # then split(":")[0] for port removal.
                #
                # Limitations: IPv6 in brackets without port ([ipv6]/path) becomes
                # malformed ([ipv6:...]).
                #
                # Solution: Refactor to use urllib.parse.urlparse() for robust URL handling.
                # See: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse
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

    def create_export_row(self, analysis_result: Any) -> dict:
        rev_dns_data = analysis_result
        return {
            "rev_dns": bool(rev_dns_data),
            "dns_lookup": rev_dns_data.get("reverse_dns") if rev_dns_data else None,
        }
