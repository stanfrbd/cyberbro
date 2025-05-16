import logging
from typing import Any, Optional

import requests

# We assume these utility functions exist in utils.utils
from utils.utils import identify_observable_type

# List of DNS record types and their identifiers (filtered for cybersecurity relevance)
dns_record_types = [
    {"type": "A", "id": 1},  # IPv4 address
    {"type": "AAAA", "id": 28},  # IPv6 address
    {"type": "CNAME", "id": 5},  # Canonical name
    {"type": "MX", "id": 15},  # Mail exchange
    {"type": "TXT", "id": 16},  # Text records (e.g., SPF, DKIM)
    {"type": "PTR", "id": 12},  # Reverse DNS
    {"type": "NS", "id": 2},  # Name server
    {"type": "SOA", "id": 6},  # Start of Authority
]

logger = logging.getLogger(__name__)


def query_google_dns(
    observable: str, observable_type: str, proxies: Optional[dict[str, str]] = None, ssl_verify: bool = True
) -> Optional[dict[str, Any]]:
    """
    Queries the Google DNS API for the given observable (domain or IP) and enriches the data with a type_name field.

    Args:
        observable (str): The observable (domain or IP).
        observable_type (str): The type of the observable ("IPv4", "IPv6", "FQDN", "URL").
        proxies (dict): Dictionary containing proxy settings.
        ssl_verify (bool): Indicates whether SSL verification should be enabled.

    Returns:
        dict: A dictionary containing the DNS records and enriched data.
    """
    try:
        if observable_type in ["IPv4", "IPv6"]:
            # Perform reverse DNS lookup using Google DNS API
            reverse_name = f"{observable}.in-addr.arpa"
            url = f"https://dns.google/resolve?name={reverse_name}&type=PTR"
            response = requests.get(url, proxies=proxies, verify=ssl_verify)
            response.raise_for_status()
            data = response.json()

            # Enrich the data with a type_name field
            for answer in data.get("Answer", []):
                answer["type_name"] = next(
                    (record["type"] for record in dns_record_types if record["id"] == answer["type"]), "Unknown"
                )

            return data

        if observable_type == "FQDN":
            # Query Google DNS API for each record type separately
            all_records = []
            for record in dns_record_types:
                url = f"https://dns.google/resolve?name={observable}&type={record['id']}"
                response = requests.get(url, proxies=proxies, verify=ssl_verify)
                response.raise_for_status()
                data = response.json()

                # Enrich the data with a type_name field
                for answer in data.get("Answer", []):
                    answer["type_name"] = record["type"]
                    if answer["type_name"] == "MX":
                        # Split the record by space and take the last part
                        answer["data"] = answer["data"].strip().split(" ")[-1]
                    all_records.append(answer)

            return {"Answer": all_records}

        if observable_type == "URL":
            # Extract the domain from the URL
            extracted = observable.split("/")[2]
            if ":" in extracted:
                extracted = extracted.split(":")[0]
            extracted_type = identify_observable_type(extracted)
            return query_google_dns(extracted, extracted_type, proxies, ssl_verify)

        logger.warning("Unsupported observable_type '%s' or no relevant logic found.", observable_type)
        return None

    except Exception as e:
        logger.error("Error querying Google DNS for '%s': %s", observable, e, exc_info=True)
        return None
