import logging
from typing import Any, Optional
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "CHROME_EXTENSION",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

def query_opencti(
    observable: str,
    api_key: str,
    opencti_url: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the OpenCTI API for information about a given observable.

    Args:
        observable (str): The observable to check.
        api_key (str): The API key for authentication.
        opencti_url (str): Base URL to your OpenCTI instance.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary with entity_counts, global_count, search_link, etc.
        None: If an error occurs or data is missing.
    """
    try:
        # Get FQDN from URL to avoid false positives searches
        if "http" in observable:
            observable = observable.split("/")[2].split(":")[0]
        # Ensure the URL is properly formatted
        base_url = urljoin(opencti_url, "/").rstrip("/")
        url = f"{base_url}/graphql"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

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
                createdBy {
                  name
                  id
                }
                creators {
                  id
                  name
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
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
                "filters": [
                    {
                        "key": "entity_type",
                        "values": ["Stix-Core-Object"],
                        "operator": "eq",
                        "mode": "or",
                    }
                ],
                "filterGroups": [],
            },
            "search": observable,
        }

        payload = {
            "id": "SearchStixCoreObjectsLinesPaginationQuery",
            "query": query,
            "variables": variables,
        }
        search_link = f"{base_url}/dashboard/search/knowledge/{observable}"

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()

        if "data" not in data or "globalSearch" not in data["data"]:
            logger.warning("OpenCTI response missing 'data' or 'globalSearch': %s", data)
            return None

        global_search = data["data"]["globalSearch"]
        edges = global_search.get("edges", [])
        entity_counts = {}
        for edge in edges:
            entity_type = edge["node"]["entity_type"]
            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

        global_count = global_search["pageInfo"]["globalCount"]
        first_element = edges[0]["node"] if edges else None
        if not first_element:
            logger.info("No results found in OpenCTI for '%s'.", observable)
            return {
                "entity_counts": entity_counts,
                "global_count": global_count,
                "search_link": search_link,
                "latest_created_at": None,
                "latest_indicator_link": None,
                "latest_indicator_name": None,
                "x_opencti_score": None,
                "revoked": None,
                "valid_from": None,
                "valid_until": None,
                "confidence": None,
            }

        latest_created_at = first_element["created_at"]
        first_id = first_element["id"]
        latest_indicator_link = None

        # Check if the first element is an Indicator
        if first_element["entity_type"] == "Indicator":
            latest_indicator_link = f"{base_url}/dashboard/observations/indicators/{first_id}"
        else:
            # Look for any Indicator in the edges
            for edge in edges:
                if edge["node"]["entity_type"] == "Indicator":
                    first_id = edge["node"]["id"]
                    latest_created_at = edge["node"]["created_at"]
                    latest_indicator_link = f"{base_url}/dashboard/observations/indicators/{first_id}"
                    break

        # If we found or suspect an Indicator, query for additional attributes
        x_opencti_score = None
        revoked = None
        valid_from = None
        valid_until = None
        confidence = None
        name = None

        if latest_indicator_link:
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
            additional_payload = {
                "query": additional_query,
                "variables": {"id": first_id},
            }
            add_response = requests.post(
                url,
                headers=headers,
                json=additional_payload,
                proxies=proxies,
                verify=ssl_verify,
                timeout=5,
            )
            add_response.raise_for_status()
            additional_data = add_response.json()
            indicator_data = additional_data.get("data", {}).get("indicator", {})

            x_opencti_score = indicator_data.get("x_opencti_score")
            revoked = indicator_data.get("revoked")
            valid_from = indicator_data.get("valid_from")
            valid_until = indicator_data.get("valid_until")
            confidence = indicator_data.get("confidence")
            name = indicator_data.get("name")

        # Format dates
        if latest_created_at:
            latest_created_at = latest_created_at.split("T")[0]
        if valid_from:
            valid_from = valid_from.split("T")[0]
        if valid_until:
            valid_until = valid_until.split("T")[0]

        return {
            "entity_counts": entity_counts,
            "global_count": global_count,
            "search_link": search_link,
            "latest_created_at": latest_created_at,
            "latest_indicator_link": latest_indicator_link,
            "latest_indicator_name": name,
            "x_opencti_score": x_opencti_score,
            "revoked": revoked,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "confidence": confidence,
        }

    except Exception as e:
        logger.error("Error querying OpenCTI for '%s': %s", observable, e, exc_info=True)

    return None
