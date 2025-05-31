import logging
from typing import Any, Optional

import requests
import tldextract

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "URL",
]

def query_openrdap(
    observable: str,
    observable_type: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the Open RDAP service for information about a given domain.
    Open RDAP is a free RDAP resolver that provides information about domain names.

    Args:
        observable (str): The observable to query (e.g., URL or FQDN).
        observable_type (str): The type of the observable ("URL" or "FQDN").
        proxies (dict): A dictionary of proxies to use for the request.

    Returns:
        dict: The JSON-like information from the RDAP service, including abuse contact, registrar,
              creation/expiration dates, etc. For example:
              {
                'abuse_contact': ...,
                'registrar': ...,
                'organization': ...,
                ...
              }
        None: If an error occurs or the observable_type is unsupported.
    """
    try:
        if observable_type == "URL":
            # Example: http://domain.com/path => extract domain
            domain_part = observable.split("/")[2].split(":")[0]
        elif observable_type == "FQDN":
            domain_part = observable
        else:
            logger.warning("Unsupported observable type '%s' for RDAP.", observable_type)
            return None

        # Extract base domain from the given domain (removes subdomains, if any)
        ext = tldextract.extract(domain_part)
        domain = ext.registered_domain
        if not domain:
            logger.warning("Could not extract a valid registered domain from '%s'.", domain_part)
            return None

        api_url = f"https://rdap.net/domain/{domain}"
        response = requests.get(api_url, verify=ssl_verify, proxies=proxies, timeout=5)
        response.raise_for_status()

        data = response.json()

        abuse_contact = ""
        registrar = ""
        organization = ""
        registrant = ""
        registrant_email = ""
        name_servers = []
        creation_date = ""
        expiration_date = ""
        update_date = ""
        link = ""

        # Parse 'entities' to find details like abuse contact, registrar, registrant, etc.
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "abuse" in roles:
                abuse_contact = _extract_vcard_field(entity, "email") or abuse_contact
            if "registrar" in roles:
                registrar = _extract_vcard_field(entity, "fn") or registrar
            if "registrant" in roles:
                registrant = _extract_vcard_field(entity, "fn") or registrant
                registrant_email = _extract_vcard_field(entity, "email") or registrant_email
                organization = _extract_vcard_field(entity, "org") or organization

            # Sub-entities can also contain 'abuse' roles
            for sub_entity in entity.get("entities", []):
                if "abuse" in sub_entity.get("roles", []):
                    abuse_contact = _extract_vcard_field(sub_entity, "email") or abuse_contact

        # Parse name servers
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                name_servers.append(ns_name.lower())

        # Parse event dates
        for event in data.get("events", []):
            action = event.get("eventAction")
            date_str = event.get("eventDate", "")
            if date_str and "T" in date_str:
                date_str = date_str.split("T")[0]  # Keep YYYY-MM-DD
            if action == "registration":
                creation_date = date_str
            elif action == "expiration":
                expiration_date = date_str
            elif action == "last changed":
                update_date = date_str

        # Parse links
        for el in data.get("links", []):
            if el.get("rel") == "self":
                link = el.get("href", "")

        return {
            "abuse_contact": abuse_contact,
            "registrar": registrar,
            "organization": organization,
            "registrant": registrant,
            "registrant_email": registrant_email,
            "name_servers": name_servers,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "update_date": update_date,
            "link": link,
        }

    except Exception as e:
        logger.error(
            "Error querying RDAP for '%s' (%s): %s",
            observable,
            observable_type,
            e,
            exc_info=True,
        )

    return None


def _extract_vcard_field(entity: dict[str, Any], field: str) -> str:
    """
    Helper to extract a specific field (e.g., 'email', 'fn', 'org') from
    an entity's 'vcardArray' if present.
    """
    vcard_array = entity.get("vcardArray", [])
    if len(vcard_array) < 2:
        return ""

    # vcard_array is typically [ "vcard", [ [field, type, type_val, actual_value], ... ] ]
    for item in vcard_array[1]:
        if len(item) == 4 and item[0] == field and item[3]:
            return item[3]
    return ""
