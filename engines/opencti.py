import logging
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class OpenCTIEngine(BaseEngine):
    @property
    def name(self):
        return "opencti"

    @property
    def supported_types(self):
        return ["CHROME_EXTENSION", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        api_key = self.secrets.opencti_api_key
        opencti_url = self.secrets.opencti_url

        try:
            observable = observable_value
            if "http" in observable:
                observable = observable.split("/")[2].split(":")[0]

            base_url = urljoin(opencti_url, "/").rstrip("/")
            url = f"{base_url}/graphql"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            # GraphQL query (copied from original file)
            query = """
            query SearchStixCoreObjectsLinesPaginationQuery(
              $types: [String]
              $search: String
              $count: Int!
              $cursor: ID
              $orderBy: StixCoreObjectsOrdering
              $orderMode: OrderingMode
              $filters: FilterGroup
            ) {
              globalSearch(
                types: $types,
                search: $search,
                first: $count,
                after: $cursor,
                orderBy: $orderBy,
                orderMode: $orderMode,
                filters: $filters
              ) {
                edges {
                  node {
                    id
                    entity_type
                    created_at
                    createdBy { name id }
                    creators { id name }
                    objectMarking { id definition_type definition x_opencti_order x_opencti_color }
                  }
                  cursor
                }
                pageInfo {
                  endCursor
                  hasNextPage
                  globalCount
                }
              }
            }
            """

            variables = {
                "count": 100,
                "orderMode": "desc",
                "orderBy": "created_at",
                "filters": {
                    "mode": "and",
                    "filters": [{"key": "entity_type", "values": ["Stix-Core-Object"], "operator": "eq", "mode": "or"}],
                    "filterGroups": [],
                },
                "search": observable,
            }

            payload = {"id": "SearchStixCoreObjectsLinesPaginationQuery", "query": query, "variables": variables}
            search_link = f"{base_url}/dashboard/search/knowledge/{observable}"

            response = requests.post(url, headers=headers, json=payload, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()
            data = response.json()

            if "data" not in data or "globalSearch" not in data["data"]:
                return None

            global_search = data["data"]["globalSearch"]
            edges = global_search.get("edges", [])
            entity_counts = {}
            for edge in edges:
                entity_type = edge["node"]["entity_type"]
                entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

            global_count = global_search["pageInfo"]["globalCount"]
            latest_created_at = None
            latest_indicator_link = None
            first_id = None

            # Find the latest creation time and an indicator ID
            for edge in edges:
                node = edge["node"]
                if not latest_created_at or node["created_at"] > latest_created_at:
                    latest_created_at = node["created_at"]
                if node["entity_type"] == "Indicator" and not first_id:
                    first_id = node["id"]
                    latest_indicator_link = f"{base_url}/dashboard/observations/indicators/{first_id}"

            if not latest_created_at:
                return {
                    "entity_counts": {},
                    "global_count": global_count,
                    "search_link": search_link,
                    "latest_created_at": None,
                }

            # If Indicator ID found, query for additional attributes
            indicator_data = {}
            if first_id:
                additional_query = """
                query GetIndicator($id: String!) {
                  indicator(id: $id) {
                    name
                    x_opencti_score
                    revoked
                    valid_from
                    valid_until
                    confidence
                  }
                }
                """
                additional_payload = {"query": additional_query, "variables": {"id": first_id}}
                add_response = requests.post(
                    url,
                    headers=headers,
                    json=additional_payload,
                    proxies=self.proxies,
                    verify=self.ssl_verify,
                    timeout=5,
                )
                add_response.raise_for_status()
                additional_data = add_response.json()
                indicator_data = additional_data.get("data", {}).get("indicator", {})

            # Format dates
            latest_created_at = latest_created_at.split("T")[0] if latest_created_at else None
            valid_from = indicator_data.get("valid_from", "").split("T")[0] if indicator_data.get("valid_from") else None
            valid_until = indicator_data.get("valid_until", "").split("T")[0] if indicator_data.get("valid_until") else None

            return {
                "entity_counts": entity_counts,
                "global_count": global_count,
                "search_link": search_link,
                "latest_created_at": latest_created_at,
                "latest_indicator_link": latest_indicator_link,
                "latest_indicator_name": indicator_data.get("name"),
                "x_opencti_score": indicator_data.get("x_opencti_score"),
                "revoked": indicator_data.get("revoked"),
                "valid_from": valid_from,
                "valid_until": valid_until,
                "confidence": indicator_data.get("confidence"),
            }

        except Exception as e:
            logger.error("Error querying OpenCTI for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"opencti_{k}": None for k in ["entity_counts", "global_count", "last_seen"]}

        entity_counts = analysis_result.get("entity_counts", {})
        entity_counts_str = ", ".join(f"{k}:{v}" for k, v in entity_counts.items())

        return {
            "opencti_entity_counts": entity_counts_str,
            "opencti_global_count": analysis_result.get("global_count"),
            "opencti_last_seen": analysis_result.get("latest_created_at"),
        }
