"""
Bad ASN Check Engine
Checks if an IP's ASN is listed in known bad ASN databases.
Requires ASN data from other engines (ipapi, ipinfo, ipquery).
"""

import logging
from collections.abc import Mapping

from typing_extensions import override

from models.base_engine import BaseEngine
from utils.bad_asn_manager import check_asn

logger = logging.getLogger(__name__)

# Keywords to identify legitimate cloud/hosting providers that can be abused
LEGITIMATE_PROVIDER_KEYWORDS: set[str] = {
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "vultr",
    "cloudflare",
    "oracle",
    "ibm",
    "alibaba",
    "tencent",
    "rackspace",
    "contabo",
    "scaleway",
}

# High-risk countries for cybersecurity threats
HIGH_RISK_COUNTRIES: set[str] = {
    "RU",
    "CN",
    "UA",
    "IR",
    "KP",
    "MD",
    "SC",  # Russia, China, Ukraine, Iran, N.Korea, Moldova, Seychelles
    "BY",
    "PK",
    "BD",
    "VN",
    "BG",
    "RO",  # Belarus, Pakistan, Bangladesh, Vietnam, Bulgaria, Romania
    "IN",
    "HK",
    "TR",
    "ID",
    "LT",
    "AL",
    "EE",  # India, Hong Kong, Turkey, Indonesia, Lithuania, Albania, Estonia
}


def is_legitimate_provider(source_description: str) -> bool:
    """Check if the ASN source description contains keywords of legitimate providers.

    Args:
        source_description: The source description from bad ASN databases

    Returns:
        True if the description contains known legitimate provider keywords
    """
    if not source_description:
        return False

    source_lower = source_description.lower()
    return any(keyword in source_lower for keyword in LEGITIMATE_PROVIDER_KEYWORDS)


def calculate_risk_score(source_description: str, is_legitimate: bool) -> int:
    """Calculate a risk score (0-100) based on multiple factors.

    Args:
        source_description: The source description from bad ASN databases
        is_legitimate: Whether the ASN is a legitimate cloud/hosting provider

    Returns:
        Risk score from 0 (low risk) to 100 (critical risk)
    """
    score = 50  # Base score for being in a bad ASN list

    # Factor 1: Presence in authoritative sources
    source_lower = source_description.lower()
    if "spamhaus" in source_lower and "brianhama" in source_lower:
        score += 20  # In multiple lists = higher confidence
    elif "spamhaus" in source_lower:
        score += 10  # Spamhaus is more authoritative

    # Factor 2: Legitimate provider penalty
    if is_legitimate:
        score -= 30  # Reduce score significantly for known legitimate providers

    # Factor 3: High-risk country location
    for country in HIGH_RISK_COUNTRIES:
        if f", {country})" in source_description:
            score += 10
            break

    # Ensure score stays within bounds
    return max(0, min(100, score))


def extract_asn_org_name(context: dict) -> str | None:
    """Extract the ASN organization name from context engines.

    Args:
        context: Dictionary containing results from other engines

    Returns:
        ASN organization name as string, or None if not found
    """
    # Try ipapi first (most reliable)
    ipapi_data = context.get("ipapi")
    if ipapi_data and isinstance(ipapi_data, dict):
        asn_obj = ipapi_data.get("asn")
        if asn_obj and isinstance(asn_obj, dict):
            org = asn_obj.get("org")
            if org and org != "Unknown":
                return str(org).strip()

    # Try ipinfo
    ipinfo_data = context.get("ipinfo")
    if ipinfo_data and isinstance(ipinfo_data, dict):
        asn_str = ipinfo_data.get("asn", "")
        if asn_str and isinstance(asn_str, str) and " " in asn_str:
            # Format: "AS13335 Cloudflare, Inc."
            parts = asn_str.split(" ", 1)
            if len(parts) > 1:
                return parts[1].strip()

    # Try webscout
    webscout_data = context.get("webscout")
    if webscout_data and isinstance(webscout_data, dict):
        org = webscout_data.get("as_org")
        if org and org != "Unknown":
            return str(org).strip()

    return None


class BadASNEngine(BaseEngine):
    """
    Engine that checks if an IP's ASN is listed in malicious ASN databases.
    This engine depends on ASN data from other engines like ipapi, ipinfo, or ipquery.
    """

    @property
    @override
    def name(self) -> str:
        return "bad_asn"

    @property
    @override
    def supported_types(self) -> list[str]:
        """Supports IPv4 and IPv6 addresses."""
        return ["IPv4", "IPv6"]

    @property
    @override
    def execute_after_reverse_dns(self) -> bool:
        """
        Execute in Phase 3 (Post-Pivot) to ensure other IP info engines
        (like ipapi, ipinfo, ipquery) have already run and retrieved ASN data.
        """
        return True

    @override
    def analyze(
        self, observable_value: str, observable_type: str, context: dict | None = None
    ) -> dict | None:
        """
        Check if the IP's ASN is listed in bad ASN databases.

        Args:
            observable_value: IP address to check
            observable_type: Should be IPv4 or IPv6
            context: Dictionary containing results from other engines (optional)

        Returns:
            Dictionary with status, source, and details if ASN is malicious,
            None otherwise
        """
        if not context:
            logger.warning(f"Bad ASN engine called without context for {observable_value}")
            return None

        # Try to extract ASN from various possible engine results
        asn = self._extract_asn_from_context(context)

        if not asn:
            logger.debug(f"No ASN found in context for {observable_value}, skipping Bad ASN check")
            return None

        # Check ASN against bad ASN databases
        result = check_asn(asn)

        if not result:
            # ASN is unlisted
            logger.debug(f"ASN {asn} for IP {observable_value} is not listed in bad ASN databases")
            return {
                "status": "unlisted",
                "asn": asn,
                "details": f"ASN {asn} is not listed in bad ASN databases",
            }

        # Extract ASN org name from context for verification
        context_asn_name = extract_asn_org_name(context)

        # Check if this is a legitimate provider that can be abused
        # by checking keywords in the source description
        source_description = result.get("source", "")
        is_legit = is_legitimate_provider(source_description)

        # Calculate risk score
        risk_score = calculate_risk_score(source_description, is_legit)

        # Add enriched data to result
        result["legitimate_but_abused"] = is_legit
        result["risk_score"] = risk_score
        result["asn_org_name"] = context_asn_name

        # Determine status based on legitimacy
        if is_legit:
            result["status"] = "potentially_legitimate"
            result["details"] = (
                f"ASN {asn} is listed in bad ASN databases BUT this appears to be a legitimate cloud/hosting provider "  # noqa: E501
                f"that can be abused by malicious actors. Risk Score: {risk_score}/100."
                f"Exercise caution but verify further context."
            )
            logger.info(
                f"Legitimate provider potentially abused: {asn} (score: {risk_score}) for IP {observable_value} - {result['source']}"  # noqa: E501
            )
        else:
            result["status"] = "malicious"
            result["details"] = (
                f"ASN {asn} is listed in bad ASN databases. Risk Score: {risk_score}/100. Source: {source_description}"  # noqa: E501
            )
            logger.info(
                f"Bad ASN detected: {asn} (score: {risk_score}) for IP {observable_value} - {result['source']}"  # noqa: E501
            )

        return result

    def _extract_asn_from_context(self, context: dict) -> str | None:
        """
        Extract ASN from results of other engines (ipapi, ipinfo, ipquery, webscout).

        Args:
            context: Dictionary containing results from other engines

        Returns:
            ASN as string (normalized), or None if not found
        """
        # Priority order: ipapi > ipinfo > ipquery > webscout (based on reliability)

        # Try ipapi first (uses api.ipapi.is)
        ipapi_data = context.get("ipapi")
        if ipapi_data and isinstance(ipapi_data, dict):
            # ipapi structure: {"asn": {"asn": "AS13335", "org": "..."}}
            asn_obj = ipapi_data.get("asn")
            if asn_obj and isinstance(asn_obj, dict):
                asn = asn_obj.get("asn")
                if asn and asn != "Unknown":
                    # ASN format: "AS13335" (string with AS prefix)
                    asn_str = str(asn).strip()
                    if asn_str.startswith("AS"):
                        asn_str = asn_str[2:]
                    if asn_str and asn_str.isdigit():
                        return asn_str

        # Try ipinfo (uses ipinfo.io)
        ipinfo_data = context.get("ipinfo")
        if ipinfo_data and isinstance(ipinfo_data, dict):
            # ipinfo structure: {"asn": "AS13335 Cloudflare, Inc."}
            asn_str = ipinfo_data.get("asn", "")
            if (
                asn_str
                and isinstance(asn_str, str)
                and asn_str != "Unknown"
                and asn_str != "BOGON"
                and asn_str.startswith("AS")
            ):
                # Extract ASN from format "AS13335 Cloudflare, Inc."
                parts = asn_str.split()
                if len(parts) > 0:
                    asn_num = parts[0][2:]  # Remove "AS" prefix from first part
                    if asn_num and asn_num.isdigit():
                        return asn_num

        # Try ipquery
        ipquery_data = context.get("ipquery")
        if ipquery_data and isinstance(ipquery_data, dict):
            asn = ipquery_data.get("asn")
            if asn:
                return str(asn)

        # Try webscout
        webscout_data = context.get("webscout")
        if webscout_data and isinstance(webscout_data, dict):
            # webscout structure: {"asn": "AS13335", "as_org": "..."}
            asn = webscout_data.get("asn")
            if asn and asn != "Unknown":
                # ASN format: "AS13335" (string with AS prefix)
                asn_str = str(asn).strip()
                if asn_str.startswith("AS"):
                    asn_str = asn_str[2:]
                if asn_str and asn_str.isdigit():
                    return asn_str

        return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        """
        Format Bad ASN check result for CSV/Excel export.

        Args:
            analysis_result: Result from analyze() method

        Returns:
            Dictionary with flattened data for export
        """
        if not analysis_result:
            return {
                "bad_asn_status": "N/A",
                "bad_asn_asn": "",
                "bad_asn_source": "",
                "bad_asn_details": "",
                "bad_asn_legitimate_but_abused": False,
                "bad_asn_risk_score": 0,
                "bad_asn_org_name": "",
            }

        return {
            "bad_asn_status": analysis_result.get("status", "N/A"),
            "bad_asn_asn": analysis_result.get("asn", ""),
            "bad_asn_source": analysis_result.get("source", ""),
            "bad_asn_details": analysis_result.get("details", ""),
            "bad_asn_legitimate_but_abused": analysis_result.get("legitimate_but_abused", False),
            "bad_asn_risk_score": analysis_result.get("risk_score", 0),
            "bad_asn_org_name": analysis_result.get("asn_org_name", ""),
        }
