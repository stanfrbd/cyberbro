import json
import logging
from enum import StrEnum
from typing import Any, Self

import requests
from pydantic import BaseModel, Field, ValidationError, model_validator
from requests.exceptions import HTTPError

from models.base_engine import BaseEngine
from utils.config import Secrets, get_config

logger = logging.getLogger(__name__)


class OpenPort(BaseModel):
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None


class IDSAlert(BaseModel):
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None


class CurrentOpenedPorts(BaseModel):
    count: int
    data: list[OpenPort] = Field(default_factory=list)


class IDSAlerts(BaseModel):
    count: int
    data: list[IDSAlert] = Field(default_factory=list)


class Issues(BaseModel):
    is_anonymous_vpn: bool = False
    is_cloud: bool = False
    is_darkweb: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_proxy: bool = False
    is_scanner: bool = False
    is_snort: bool = False
    is_tor: bool = False
    is_vpn: bool = False


class WhoisRecord(BaseModel):
    as_name: str | None = None
    as_no: int | None = None
    city: str | None = None
    region: str | None = None
    org_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    org_country_code: str | None = None
    confirmed_time: str | None = None


class Whois(BaseModel):
    count: int = 0
    data: list[WhoisRecord] = Field(default_factory=list)


class ScoreStatus(StrEnum):
    SAFE = "Safe"
    LOW = "Low"
    MODERATE = "Moderate"
    DANGEROUS = "Dangerous"
    CRITICAL = "Critical"


class Score(BaseModel):
    inbound: ScoreStatus | None = None
    outbound: ScoreStatus | None = None


class SuspiciousInfoReport(BaseModel):
    status: int
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts | None = None
    ids: IDSAlerts | None = None
    ip: str = ""
    issues: Issues | None = None
    representative_domain: str = ""
    score: Score | None = None
    whois: Whois | None = None

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        # If the status is anything other than 2xx, raise an error
        if not 199 < self.status < 300:
            raise ValueError(
                f"Unable to generate Suspicious Info Report for IP: {self.ip}."
                f"Status Code: {self.status}{self.model_dump_json()}"
            )
        return self


base_url: str = "https://api.criminalip.io"


# --- Original Helper Functions (Preserved) ---


def retrieve_api_key() -> str:
    """Retrieve the API key from the secrets config."""

    secrets: Secrets = get_config()

    api_key: str = secrets.criminalip_api_key

    return api_key


def get_suspicious_info_report(
    api_key: str,
    observable: str,
    proxies: dict[str, str] | None = None,
    ssl_verify: bool = True,
) -> SuspiciousInfoReport | None:
    """Retrieve 'Suspicious Info' Report."""

    url: str = f"{base_url}/v2/feature/ip/suspicious-info"
    params: dict = {"ip": observable}
    headers: dict = {"x-api-key": f"{api_key}"}

    try:
        response = requests.get(
            url, params=params, headers=headers, proxies=proxies, verify=ssl_verify
        )
        response.raise_for_status()
    except HTTPError as e:
        logger.error(
            f"Error retrieving Criminal IP Suspicious Info report for {observable}: {e}",
        )
        return None

    try:
        suspcious_info_report: SuspiciousInfoReport = SuspiciousInfoReport(**response.json())
    except ValidationError as e:
        logger.error(
            f"Error validating Criminal IP Suspicious Info report for {observable}: {e}",
        )
        return None

    return suspcious_info_report


# --- New Engine Class Implementation ---


class CriminalIPEngine(BaseEngine):
    @property
    def name(self):
        return "criminalip"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    def analyze(self, observable_value: str, observable_type: str) -> dict | None:
        """Perform Criminal IP analysis using the preserved helper/models."""

        api_key: str = self.secrets.criminalip_api_key

        if not api_key:
            logger.error("API key for CriminalIP engine is not configured.")
            return None

        report: SuspiciousInfoReport | None = get_suspicious_info_report(
            api_key, observable_value, self.proxies, self.ssl_verify
        )

        if not report:
            logger.error("Failed to retrieve the CriminalIP report.")
            return None

        # Convert the Pydantic model to a standard dict for the rest of the app
        return json.loads(report.model_dump_json())

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"cip_score_inbound": None, "cip_score_outbound": None, "cip_abuse_count": None}

        score = analysis_result.get("score", {})

        return {
            "cip_score_inbound": score.get("inbound"),
            "cip_score_outbound": score.get("outbound"),
            "cip_abuse_count": analysis_result.get("abuse_record_count"),
        }


# --- Main Block for Testing (Preserved) ---

if __name__ == "__main__":
    # Example usage
    api_key: str = retrieve_api_key()
    ssl_verify: bool = False

    if not api_key:
        logger.error("API key is not configured.")
        exit(1)

    observable: str = input("Enter an IP address: ")

    if not observable:
        logger.error("No observable provided.")
        exit(1)

    report: SuspiciousInfoReport | None = get_suspicious_info_report(
        api_key, observable, ssl_verify=ssl_verify
    )

    if report:
        print("Suspicious Info Report:")
        print(report)
    else:
        logger.error("Failed to retrieve the report.")
