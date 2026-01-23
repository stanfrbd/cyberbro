import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

import requests
from pydantic import ValidationError
from typing_extensions import override

from models.alienvault_datamodel import OTXReport, Pulse
from models.base_engine import BaseEngine
from utils.config import QueryError

logger = logging.getLogger(__name__)


class AlienVaultEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "alienvault"

    @property
    @override
    def supported_types(self):
        return [
            "FQDN",
            "IPv4",
            "IPv6",
            "MD5",
            "SHA1",
            "SHA256",
            "URL",
        ]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        """
        Queries the OTX AlienVault API for information about a given observable.
        Reuses the original maintainer's logic for querying and parsing.
        """
        api_key: str = self.secrets.alienvault
        if not api_key:
            logger.error("OTX AlienVault API key is required")
            return None

        # Prepare the dictionary expected by the original helper functions
        observable_dict = {"value": observable_value, "type": observable_type}

        try:
            # Reuse the existing query logic
            result: dict = query_alienvault(observable_dict, api_key, self.proxies, self.ssl_verify)

            # Reuse the existing parsing logic
            report: dict = parse_alienvault_response(result)
            return report

        except QueryError:
            logger.warning("Error retrieving or parsing report from AlienVault")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in AlienVault engine: {e}")
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {
                "alienvault_pulses": None,
                "alienvault_malwares": None,
                "alienvault_adversary": None,
            }

        malware_families = ", ".join(analysis_result.get("malware_families", []))
        adversaries = ", ".join(analysis_result.get("adversary", []))

        return {
            "alienvault_pulses": analysis_result.get("count"),
            "alienvault_malwares": malware_families if malware_families else None,
            "alienvault_adversary": adversaries if adversaries else None,
        }


# --- Original Maintainer's Code / Helper Functions (Preserved) ---


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


def query_alienvault(
    observable_dict: dict,
    api_key: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> dict:
    artifact: str = observable_dict["value"]

    # If it's a URL, extract the domain portion for searching
    if (observable_type := observable_dict["type"]) == "URL":
        artifact = observable_dict["value"].split("/")[2].split(":")[0]
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
    - Pulse (MalwareFamily object)
    - Related.Alienvault (string)
    - Related.Other (string)
    """
    report_malware_families: list[str] = []
    report_malware_families.extend(
        [
            family
            for family in otx_report.pulse_info.related.alienvault.malware_families
            if family.lower() not in map(str.lower, report_malware_families)
        ]
    )

    report_malware_families.extend(
        [
            family
            for family in otx_report.pulse_info.related.other.malware_families
            if family.lower() not in map(str.lower, report_malware_families)
        ]
    )

    """
    Adversary
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
        report_malware_families.extend(
            [
                family.display_name
                for family in pulse.malware_families
                if family.display_name.lower() not in map(str.lower, report_malware_families)
            ]
        )

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
