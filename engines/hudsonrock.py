import logging
from typing import Any

import requests
from requests.exceptions import JSONDecodeError, RequestException

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class HudsonRockEngine(BaseEngine):
    @property
    def name(self):
        return "hudsonrock"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.EMAIL | ObservableType.FQDN | ObservableType.URL

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        if observable.type is ObservableType.URL:
            lookup_value: str = observable._return_fqdn_from_url()
            if not lookup_value:
                logger.error(f"Invalid URL passed to crtsh: {observable.value}")
                return None
            lookup_type = ObservableType.FQDN
        else:
            lookup_value = observable.value
            lookup_type = observable.type

        # lookup_type is used instead of observable.type, since
        # we might have converted the type from URL to FQDN above
        match lookup_type:
            case ObservableType.EMAIL:
                url_path = "search-by-email"
                params = {"email": lookup_value}
            case ObservableType.FQDN:
                url_path = "search-by-domain"
                params = {"domain": lookup_value}
            case _:
                logger.error("Unsupported observable type for HudsonRock: %s", lookup_type)
                return None

        url: str = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{url_path}"

        try:
            response = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=5
            )
            response.raise_for_status()
            data = response.json()
        except (RequestException, JSONDecodeError) as e:
            logger.error(
                "Error while querying Hudson Rock for '%s': %s", observable.value, e, exc_info=True
            )
            return None

        try:
            # Clean up output as in the original logic
            if lookup_type is ObservableType.FQDN:
                for section in ["data", "stats"]:
                    if section in data:
                        for key in ["all_urls", "clients_urls", "employees_urls"]:
                            if key in data[section]:
                                data[section][key] = [
                                    entry
                                    for entry in data[section][key]
                                    if "url" not in entry or "••" not in entry["url"]
                                ]
                    if section == "stats" and section in data:
                        for key in ["clients_urls", "employees_urls"]:
                            if key in data[section]:
                                data[section][key] = [
                                    u for u in data[section][key] if "••" not in u
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
                "Error processing data in Hudson Rock response for '%s': %s",
                observable.value,
                e,
                exc_info=True,
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
