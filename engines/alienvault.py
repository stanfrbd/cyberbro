import logging
from typing import Any
from urllib.parse import quote

import requests
from pydantic import ValidationError

from models.alienvault_datamodel import OTXReport, Pulse
from utils.config import QueryError, Secrets, get_config

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

NAME: str = "alienvault"
LABEL: str = "Alientvault"
SUPPORTS: list[str] = ["hash", "IP", "domain", "url", "risk"]
DESCRIPTION: str = "Checks Alienvault for IP, domain, URL, hash"
COST: str = "Free"
API_KEY_REQUIRED: bool = True


def run_engine(
    observable_dict: dict,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict[str, Any] | None:
    """
    Queries the OTX AlienVault API for information about a given observable (URL, IP, domain, hash).

    Args:
        observable_dict (dict): The observable mapping which contains:
        - value (str): The observable to search for (e.g., URL, IP address, domain, hash).
        - type (str): The type of the observable
            (e.g., "URL", "IPv4", "IPv6", "FQDN", "SHA256", "SHA1", "MD5").
        proxies (dict): A dictionary of proxies to use for the request.
        ssl_verify (bool): Whether to verify SSL certificates.
        api_key (str): OTX AlienVault API key (required).

    Returns:
        dict: A dictionary with "count" (int), "pulses" (list),
        "malware_families" (list), "adversary" (list), and "link" (str). For example:
              {
                  "count": 2,
                  "pulses": [
                      {"title": "Malware Campaign", "url": "https://example.com/report"},
                      {"title": "Phishing Alert", "url": None}
                  ],
                  "malware_families": ["Emotet"],
                  "adversary": ["Scattered Spider"],
                  "link": "https://otx.alienvault.com/browse/global/pulses?q=<observable>"
              }
        None: If an error occurs or API key is missing.
    """

    secrets: Secrets = get_config()
    api_key: str = secrets.alienvault
    if not api_key:
        logger.error("OTX AlienVault API key is required")
        return None

    try:
        result: dict = query_alienvault(observable_dict, api_key, proxies, ssl_verify)
        report: dict = parse_alienvault_response(result)
    except QueryError:
        logger.warning("Error retrieving or parsing report from AlienVault")
        return None

    return report


def get_endpoint(artifact: str, observable_type: str) -> str | None:
    # Map observable type to OTX endpoint
    endpoint_map = {
        "IPv4": f"/indicators/IPv4/{quote(artifact)}/general",
        "IPv6": f"/indicators/IPv6/{quote(artifact)}/general",
        "FQDN": f"/indicators/domain/{quote(artifact)}/general",
        "SHA1": f"/indicators/file/{quote(artifact)}/general",
        "MD5": f"/indicators/file/{quote(artifact)}/general",
        "SHA256": f"/indicators/file/{quote(artifact)}/general",
    }

    return endpoint_map.get(observable_type)


def query_alienvault(observable_dict: dict, api_key: str, proxies: dict[str, str] | None = None, ssl_verify: bool = True) -> dict:
    artifact: str = observable_dict["value"]

    # If it's a URL, extract the domain portion for searching
    if (observable_type := observable_dict["type"]) == "URL":
        artifact: str = observable_dict["value"].split("/")[2].split(":")[0]
        observable_type = "FQDN"

    endpoint = get_endpoint(artifact, observable_type)

    if not endpoint:
        raise QueryError(f"Invalid observable type: {observable_type}") from None

    url = f"https://otx.alienvault.com/api/v1{endpoint}"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(url, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.exceptions.RequestException as req_err:
        logger.error("Network error while querying OTX AlienVault: %s", req_err, exc_info=True)
        raise QueryError from req_err

    return result


def parse_alienvault_response(result: dict) -> dict:
    try:
        otx_report: OTXReport = OTXReport(**result)
    except ValidationError as e:
        logger.error("Error validating OTX response")
        raise QueryError from e

    """
    Malware Families

    OTX includes `malware_families` in three different locations:
    - Pulse
        - This is a MalwareFamily object, described in the alienvault_datamodel
    - Related.Alienvault
        - This is a string
    - Related.Other
        - This is a string

    Comparing families in a case insensitive way helps prevent duplicated entries,
    but we want to preserve case for the report.
    """
    report_malware_families: list[str] = []
    report_malware_families.extend([family for family in otx_report.pulse_info.related.alienvault.malware_families if family.lower() not in map(str.lower, report_malware_families)])

    report_malware_families.extend([family for family in otx_report.pulse_info.related.other.malware_families if family.lower() not in map(str.lower, report_malware_families)])

    """
    Adversary

    OTX returns an adversary string in three locations, same as malware_families
    But all of them are only strings. :-)
    """
    adversary: set[str] = set(otx_report.pulse_info.related.alienvault.adversary)

    pulses: list[Pulse] = otx_report.pulse_info.pulses
    pulse_data: list[dict[str, str | None]] = []
    seen_urls: set[str | None] = set()  # Track unique pulse URLs

    # Sort pulses by 'created' timestamp in descending order
    sorted_pulses = sorted(pulses, key=lambda x: x.created, reverse=True)

    for pulse in sorted_pulses:
        if (pulse.name == "Unknown") or (not pulse.id):
            continue

        # Link to default pulse URL if no other more specific link is present
        pulse_url_default_value: str = f"https://otx.alienvault.com/pulse/{pulse.id}"
        pulse_url: str = pulse.references[0] if pulse.references else pulse_url_default_value

        # Skip if this pulse URL has already been seen (excluding None entries)
        if pulse_url != pulse_url_default_value and pulse_url in seen_urls:
            continue

        # Add to seen URLs and include in output
        seen_urls.add(pulse_url)
        pulse_data.append({"title": pulse.name, "url": pulse_url})

        # Add the pulse malware_family to the set
        report_malware_families.extend([family.display_name for family in pulse.malware_families if family.display_name.lower() not in map(str.lower, report_malware_families)])

        if pulse.adversary:
            adversary.add(pulse.adversary)

        # Stop after collecting 5 unique pulses
        if len(pulse_data) >= 5:
            break

    count = len(pulse_data)

    # The original observable is included in the OTXReport object as the "indicator"
    link = f"https://otx.alienvault.com/browse/global/pulses?q={quote(otx_report.indicator)}"
    return {
        "count": count,
        "pulses": pulse_data,
        "malware_families": report_malware_families,
        "adversary": list(adversary),
        "link": link,
    }
