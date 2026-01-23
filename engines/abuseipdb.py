import logging
from collections.abc import Mapping

from pydantic import ConfigDict, Field, ValidationError
from pydantic.dataclasses import dataclass
from requests.exceptions import RequestException
from typing_extensions import override

from models.base_engine import BaseEngine, BaseReport

logger = logging.getLogger(__name__)


"""
This report object is also included in the API response, but
there is no need to validate it, if we are not using it.

@dataclass(slots=True)
class AbuseIPDBAPIReport:
    reported_at: str = Field(alias="reportedAt", default="")
    comment: str = Field(alias="comment", default="")
    categories: list = Field(alias="categories", default_factory=list)
    reporter_id: int = Field(alias="reporterId", default=0)
    reporter_country_code: str = Field(alias="reporterCountryCode", default="")
    reporter_country_name: str = Field(alias="reporterCountryName", default="")
"""


@dataclass(slots=True)
class AbuseIPDBAPIData:
    model_config = ConfigDict(extra="ignore")
    total_reports: int = Field(alias="totalReports")
    abuse_confidence_score: int = Field(alias="abuseConfidenceScore")

    """
    The following fields are also available in the API response, but
    there is no need to validate them, if we are not using them.

    ip_address: str = Field(alias="ipAddress")
    is_public: bool = Field(alias="isPublic")
    ip_version: int = Field(alias="ipVersion")
    is_whitelisted: bool = Field(alias="isWhitelisted")
    is_tor: bool = Field(alias="isTor")
    num_distinct_users: int = Field(alias="numDistinctUsers")
    country_code: str = Field(alias="countryCode", default="")
    country_name: str = Field(alias="countryName", default="")
    usage_type: str = Field(alias="usageType", default="")
    isp: str = Field(alias="isp", default="")
    domain: str = Field(alias="domain", default="")
    hostnames: list = Field(default_factory=list)
    last_reported_at: str = Field(alias="lastReportedAt", default="")
    reports: list[AbuseIPDBAPIReport] = Field(default_factory=list)
    """


@dataclass(slots=True)
class AbuseIPDBAPIResponse:
    data: AbuseIPDBAPIData


@dataclass(slots=True)
class AbuseIPDBReport(BaseReport):
    reports: int = 0
    risk_score: int = 0
    link: str = ""


class AbuseIPDBEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "abuseipdb"

    @property
    @override
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    @override
    def execute_after_reverse_dns(self):
        """
        AbuseIPDB only supports IPs, so we want it to run AFTER
        any potential DNS resolution
        """

        return True

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.secrets.abuseipdb, "Accept": "application/json"}
        params = {"ipAddress": observable_value}

        try:
            response = self._make_request(
                url,
                headers=headers,
                params=params,
                timeout=5,
            )
            response.raise_for_status()
            api_response: AbuseIPDBAPIResponse = AbuseIPDBAPIResponse(**response.json())

            return AbuseIPDBReport(
                success=True,
                reports=api_response.data.total_reports,
                risk_score=api_response.data.abuse_confidence_score,
                link=f"https://www.abuseipdb.com/check/{observable_value}",
            ).__json__()
        except ValidationError as e:
            message: str = f"Invalid response from AbuseIPDB: {e}"
            logger.error(message)
            return AbuseIPDBReport(success=False, error_msg=message).__json__()
        except RequestException as e:
            message = f"Error querying AbuseIPDB: {e}"
            logger.error(message)
            return AbuseIPDBReport(success=False, error_msg=message).__json__()

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {"a_ipdb_reports": None, "a_ipdb_risk": None}
        return {
            "a_ipdb_reports": analysis_result.get("reports"),
            "a_ipdb_risk": analysis_result.get("risk_score"),
        }
