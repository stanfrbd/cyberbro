import logging
from typing import Any
from urllib.parse import quote_plus

import requests
from requests.exceptions import ConnectTimeout, HTTPError, ReadTimeout, RequestException
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class ServiceNowEngine(BaseEngine):
    TABLES_TO_SEARCH: tuple[tuple[str, str], ...] = (
        ("inc", "incident"),
        ("sir", "sn_si_incident"),
        ("sir_task", "sn_si_task"),
        ("task", "task"),
        ("incident_task", "incident_task"),
        ("request", "sc_request"),
        ("request_item", "sc_req_item"),
    )

    @property
    def name(self) -> str:
        return "servicenow"

    @property
    @override
    def supported_types(self) -> ObservableType:
        # ServiceNow can search for various observables
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
            | ObservableType.EMAIL
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
        )

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        """
        Query ServiceNow for INC (incidents) and SIR (Security Incidents) records.
        Returns the top 5 most recent results and total count.
        """
        servicenow_url: str = self.secrets.servicenow_url
        servicenow_username: str = self.secrets.servicenow_username
        servicenow_password: str = self.secrets.servicenow_password

        if not servicenow_url or not servicenow_username or not servicenow_password:
            logger.warning("ServiceNow URL, username or password not set")
            return None

        # Ensure URL ends without trailing slash
        servicenow_url = servicenow_url.rstrip("/")

        query_value = observable.value

        query_value_encoded = quote_plus(query_value)

        # Prepare results dictionary
        results: dict[str, Any] = {
            "inc_results": [],
            "sir_results": [],
            "inc_total": 0,
            "sir_total": 0,
            "inc_types": {},
            "sir_types": {},
            "global_results": [],
            "global_total": 0,
            "table_totals": {},
            "links": {
                "global_search": f"{servicenow_url}/text_search_exact_match.do?sysparm_search={query_value_encoded}",
            },
        }

        # Headers for API request
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            merged_results: list[dict[str, str]] = []

            for alias, table_name in self.TABLES_TO_SEARCH:
                table_result = self._search_incidents(
                    servicenow_url,
                    query_value,
                    table_name,
                    headers,
                    servicenow_username,
                    servicenow_password,
                )

                if not table_result:
                    results["table_totals"][alias] = 0
                    continue

                table_total = table_result.get("total", 0)
                table_top = table_result.get("top_5", [])
                table_types = table_result.get("types", {})
                table_full_results = table_result.get("full_results", [])

                results["table_totals"][alias] = table_total

                if alias == "inc":
                    results["inc_results"] = table_top
                    results["inc_total"] = table_total
                    results["inc_types"] = table_types
                elif alias == "sir":
                    results["sir_results"] = table_top
                    results["sir_total"] = table_total
                    results["sir_types"] = table_types

                merged_results.extend(table_full_results)

            unique_global_results: list[dict[str, str]] = []
            unique_keys: set[str] = set()
            for item in merged_results:
                dedup_key = (
                    f"{item.get('number', '')}|{item.get('created_on', '')}|"
                    f"{item.get('short_description', '')}"
                )
                if dedup_key in unique_keys:
                    continue
                unique_keys.add(dedup_key)
                unique_global_results.append(item)

            merged_sorted_results = sorted(
                unique_global_results,
                key=lambda item: item.get("created_on", ""),
                reverse=True,
            )
            results["global_results"] = merged_sorted_results[:5]
            results["global_total"] = len(unique_global_results)

        except (ReadTimeout, ConnectTimeout):
            logger.info(f"Timeout occurred while querying ServiceNow for {observable.value}.")
            return None
        except HTTPError as e:
            logger.error(
                "Error querying ServiceNow for '%s': %s", observable.value, e, exc_info=True
            )
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying ServiceNow for {observable.value}: {e}")
            return None

        return results

    def _search_incidents(
        self,
        servicenow_url: str,
        query_value: str,
        table_name: str,
        headers: dict[str, str],
        servicenow_username: str,
        servicenow_password: str,
    ) -> dict[str, Any] | None:
        """
        Search for incidents/security incidents in ServiceNow.
        Returns top 5 most recent, total count, and breakdown by type.
        """
        api_endpoint = f"{servicenow_url}/api/now/table/{table_name}"

        query = f"123TEXTQUERY321={query_value}"
        if table_name == "task":
            query = (
                f"{query}^sys_class_nameNOT IN "
                "incident,sn_si_incident,sn_si_task,incident_task,sc_request,sc_req_item"
            )

        params = {
            "sysparm_query": query,
            "sysparm_limit": 200,
            "sysparm_exclude_reference_link": "true",
            "sysparm_fields": "sys_id,number,short_description,description,sys_created_on,type,category,sys_class_name",
        }

        try:
            response = requests.get(
                api_endpoint,
                headers=headers,
                auth=(servicenow_username, servicenow_password),
                params=params,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=10,
            )
            response.raise_for_status()

            json_response = response.json()

            if "result" not in json_response:
                return None

            results = json_response["result"]

            if not results:
                return {
                    "top_5": [],
                    "total": 0,
                    "types": {},
                }

            # Sort by creation date (most recent first)
            sorted_results = sorted(
                results,
                key=lambda item: item.get("sys_created_on", item.get("created_on", "")),
                reverse=True,
            )

            # Normalize rows
            normalized_results: list[dict[str, str]] = []
            for incident in sorted_results:
                sys_id = incident.get("sys_id", "")
                web_link = self._build_web_link(servicenow_url, table_name, sys_id)
                normalized_results.append(
                    {
                        "number": incident.get("number", "N/A"),
                        "short_description": incident.get("short_description", "N/A"),
                        "created_on": incident.get(
                            "sys_created_on", incident.get("created_on", "N/A")
                        ),
                        "type": incident.get(
                            "type",
                            incident.get("category", incident.get("sys_class_name", "Unknown")),
                        ),
                        "table": table_name,
                        "web_link": web_link,
                    }
                )

            # Count types
            type_count: dict[str, int] = {}
            for incident in results:
                incident_type = incident.get(
                    "type", incident.get("category", incident.get("sys_class_name", "Unknown"))
                )
                type_count[incident_type] = type_count.get(incident_type, 0) + 1

            return {
                "top_5": normalized_results[:5],
                "total": len(results),
                "types": type_count,
                "full_results": normalized_results,
            }

        except (ReadTimeout, ConnectTimeout) as e:
            logger.debug(f"Timeout searching {table_name} in ServiceNow: {e}")
            return None
        except HTTPError as e:
            logger.debug(f"HTTP error searching {table_name} in ServiceNow: {e}")
            return None
        except RequestException as e:
            logger.debug(f"Request error searching {table_name} in ServiceNow: {e}")
            return None

    def _build_web_link(self, servicenow_url: str, table_name: str, sys_id: str) -> str:
        if not sys_id:
            return ""

        if table_name == "sn_si_incident":
            return f"{servicenow_url}/now/sir/record/sn_si_incident/{sys_id}"

        if table_name == "sn_si_task":
            return f"{servicenow_url}/now/sir/record/sn_si_task/{sys_id}"

        if table_name == "incident":
            return (
                f"{servicenow_url}/now/nav/ui/classic/params/target/incident.do%3Fsys_id%3D{sys_id}"
            )

        return (
            f"{servicenow_url}/now/nav/ui/classic/params/target/{table_name}.do%3Fsys_id%3D{sys_id}"
        )

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "servicenow_inc_total": None,
                "servicenow_inc_top": None,
                "servicenow_sir_total": None,
                "servicenow_sir_top": None,
            }

        inc_top = ", ".join([r["number"] for r in analysis_result.get("inc_results", [])])
        sir_top = ", ".join([r["number"] for r in analysis_result.get("sir_results", [])])

        return {
            "servicenow_inc_total": analysis_result.get("inc_total"),
            "servicenow_inc_top": inc_top if inc_top else None,
            "servicenow_sir_total": analysis_result.get("sir_total"),
            "servicenow_sir_top": sir_top if sir_top else None,
        }
