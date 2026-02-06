import logging
from typing import Any
from urllib.parse import urlparse

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class HudsonRockEngine(BaseEngine):
    @property
    def name(self):
        return "hudsonrock"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.EMAIL | ObservableType.FQDN | ObservableType.URL

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        try:
            if observable_type is ObservableType.URL:
                # Candidate for FQDN from URL private method
                parsed_url = urlparse(observable_value)
                observable = parsed_url.netloc
                observable_type = ObservableType.FQDN
            else:
                observable = observable_value

            match observable_type:
                case ObservableType.EMAIL:
                    url_path = "search-by-email"
                    params = {"email": observable}
                case ObservableType.FQDN:
                    url_path = "search-by-domain"
                    params = {"domain": observable}
                case _:
                    logger.error("Unsupported observable type: %s", observable_type)
                    return None

            url: str = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{url_path}"
            response = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=5
            )
            response.raise_for_status()
            data = response.json()

            # Clean up output as in the original logic
            if observable_type is ObservableType.FQDN:
                for section in ["data", "stats"]:
                    if section in data:
                        for key in ["all_urls", "clients_urls", "employees_urls"]:
                            if key in data[section]:
                                data[section][key] = [
                                    entry
                                    for entry in data[section][key]
                                    if "url" not in entry or "••" not in entry["url"]
                                ]
                    # REFACTOR NOTE: Line 55 accesses data[section] without checking if
                    # section is in data. While line 45 checks `if section in data`, the
                    # logic below (lines 53-58) executes outside that block. This can cause
                    # KeyError if only "data" is present but not "stats" (or vice versa).
                    # Should restructure to ensure section exists before accessing.
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
                "Error while querying Hudson Rock for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
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
