import logging
from typing import Any, Optional

import dns.resolver
import dns.reversename

# We assume these utility functions exist in utils.utils
from utils.utils import identify_observable_type, is_really_ipv6

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "BOGON",
    "FQDN",
    "IPv4",
    "IPv6",
    "URL",
]

def reverse_dns(observable: str, observable_type: str) -> Optional[dict[str, Any]]:
    """
    Perform a reverse DNS or standard DNS lookup on the given observable.

    Args:
        observable (str): The observable (IP, FQDN, or URL).
        observable_type (str): The type of the observable ("IPv4", "IPv6", "BOGON", "FQDN", "URL").

    Returns:
        dict: A dictionary with the key 'reverse_dns' containing a list of resolved addresses or PTR records.
              Example:
              {
                  "reverse_dns": ["resolved.host.name" or "8.8.8.8", ...]
              }
        None: If an error occurs or the type is not recognized.
    """
    try:
        # If the observable is an IP address (IPv4/IPv6 or BOGON), do a PTR lookup
        if observable_type in ["IPv4", "IPv6", "BOGON"]:
            reverse_name = dns.reversename.from_address(observable)
            answer = dns.resolver.resolve(reverse_name, "PTR")
            return {"reverse_dns": [str(answer[0])]}

        # If it's an FQDN, do an A record lookup
        if observable_type == "FQDN":
            answer = dns.resolver.resolve(observable, "A")
            return {"reverse_dns": [str(ip) for ip in answer]}

        # If it's a URL, parse out the domain/host part
        if observable_type == "URL":
            extracted = observable.split("/")[2]  # e.g., domain.com or 8.8.8.8:8080

            # Handle port in the host part
            if ":" in extracted:
                # Check if it's an IPv6
                if is_really_ipv6(extracted):
                    reverse_name = dns.reversename.from_address(extracted)
                    answer = dns.resolver.resolve(reverse_name, "PTR")
                    return {"reverse_dns": [str(answer[0])]}
                # Remove the port to isolate domain or IPv4
                extracted = extracted.split(":")[0]

            # Identify the cleaned-up host type
            extracted_type = identify_observable_type(extracted)
            if extracted_type == "FQDN":
                answer = dns.resolver.resolve(extracted, "A")
                return {"reverse_dns": [str(ip) for ip in answer]}
            if extracted_type == "IPv4":
                reverse_name = dns.reversename.from_address(extracted)
                answer = dns.resolver.resolve(reverse_name, "PTR")
                return {"reverse_dns": [str(answer[0])]}

        logger.warning(
            "Unsupported observable_type '%s' or no relevant logic found.",
            observable_type,
        )
        return None

    except Exception as e:
        logger.error(
            "Error resolving reverse DNS for '%s' (%s): %s",
            observable,
            observable_type,
            e,
            exc_info=True,
        )

    return None
