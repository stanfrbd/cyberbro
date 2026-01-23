import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class HudsonRockEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "hudsonrock"

    @property
    @override
    def supported_types(self):
        return ["Email", "FQDN", "URL"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            if observable_type == "URL":
                parsed_url = urlparse(observable_value)
                observable = parsed_url.netloc
                observable_type = "FQDN"
            else:
                observable = observable_value

            if observable_type == "Email":
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={observable}"
            elif observable_type == "FQDN":
                url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={observable}"
            else:
                logger.error("Unsupported observable type: %s", observable_type)
                return None

            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()
            data = response.json()

            # Clean up output as in the original logic
            if observable_type == "FQDN":
                for section in ["data", "stats"]:
                    if section in data:
                        for key in ["all_urls", "clients_urls", "employees_urls"]:
                            if key in data[section]:
                                data[section][key] = [
                                    entry
                                    for entry in data[section][key]
                                    if "url" not in entry or "••" not in entry["url"]
                                ]
                    if section == "stats":
                        for key in ["clients_urls", "employees_urls"]:
                            if key in data[section]:
                                data[section][key] = [
                                    url for url in data[section][key] if "••" not in url
                                ]
                    if "thirdPartyDomains" in data:
                        data["thirdPartyDomains"] = [
                            entry
                            for entry in data["thirdPartyDomains"]
                            if "domain" in entry
                            and entry["domain"] is not None
                            and "••" not in entry["domain"]
                        ]
            return data

        except Exception as e:
            logger.error(
                "Error while querying Hudson Rock for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {
                f"hr_{k}": None
                for k in [
                    "total_corporate_services",
                    "total_user_services",
                    "total",
                    "total_stealers",
                    "employees",
                    "users",
                    "third_parties",
                    "stealer_families",
                ]
            }

        return {
            "hr_total_corporate_services": analysis_result.get("total_corporate_services"),
            "hr_total_user_services": analysis_result.get("total_user_services"),
            "hr_total": analysis_result.get("total"),
            "hr_total_stealers": analysis_result.get("totalStealers"),
            "hr_employees": analysis_result.get("employees"),
            "hr_users": analysis_result.get("users"),
            "hr_third_parties": analysis_result.get("third_parties"),
            "hr_stealer_families": ", ".join(analysis_result.get("stealerFamilies", [])),
        }
