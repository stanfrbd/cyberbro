from __future__ import annotations

import logging
from collections import Counter
from ipaddress import ip_address
from typing import Literal
from urllib.parse import quote, urlsplit

import requests
from pydantic import BaseModel, Field, JsonValue, ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableFlag

logger = logging.getLogger(__name__)
PAGE_SIZE = 100
MAX_PAGES = 20


class _Filter(BaseModel):
    key: list[str]
    values: list[str]
    operator: Literal["eq", "not_eq"] = "eq"
    mode: Literal["or"] = "or"


class _FilterGroup(BaseModel):
    mode: Literal["or", "and"] = "or"
    filters: list[_Filter]
    filter_groups: list[_FilterGroup] = Field(default_factory=list, alias="filterGroups")


class _PageInfo(BaseModel):
    end_cursor: str | None = Field(default=None, alias="endCursor")
    has_next_page: bool = Field(default=False, alias="hasNextPage")
    global_count: int | None = Field(default=None, alias="globalCount")


class _Node(BaseModel):
    id: str
    entity_type: str
    created_at: str | None = None
    indicators: _Connection | None = None


class _Edge(BaseModel):
    node: _Node


class _Connection(BaseModel):
    edges: list[_Edge] = Field(default_factory=list)
    page_info: _PageInfo = Field(alias="pageInfo")


class _Indicator(BaseModel):
    name: str | None = None
    x_opencti_score: int | None = None
    revoked: bool | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    confidence: int | None = None


class _Data(BaseModel):
    global_search: _Connection | None = Field(default=None, alias="globalSearch")
    indicator: _Indicator | None = None


class _Response(BaseModel):
    data: _Data | None = None
    errors: list[JsonValue] | None = None


class _Request(BaseModel):
    query: str
    variables: dict[str, JsonValue]


SEARCH_QUERY = """
query CyberbroExactSearch($count: Int!, $cursor: ID, $filters: FilterGroup!) {
  globalSearch(first: $count, after: $cursor, filters: $filters,
               orderBy: created_at, orderMode: desc) {
    edges {
      node {
        id entity_type created_at
        ... on StixCyberObservable {
          indicators(first: 100) {
            edges { node { id entity_type created_at } }
            pageInfo { hasNextPage }
          }
        }
      }
    }
    pageInfo { endCursor hasNextPage globalCount }
  }
}
"""
INDICATOR_QUERY = """
query CyberbroIndicator($id: String!) {
  indicator(id: $id) {
    name x_opencti_score revoked valid_from valid_until confidence
  }
}
"""


class OpenCTIEngine(BaseEngine):
    proxies: dict[str, str]

    @property
    @override
    def name(self) -> str:
        return "opencti"

    @property
    @override
    def supported_types(self) -> ObservableFlag:
        return (
            ObservableFlag.CHROME_EXTENSION
            | ObservableFlag.FQDN
            | ObservableFlag.IPV4
            | ObservableFlag.IPV6
            | ObservableFlag.MD5
            | ObservableFlag.SHA1
            | ObservableFlag.SHA256
            | ObservableFlag.URL
        )

    @staticmethod
    def _search_target(observable: Observable) -> tuple[str, str | None]:
        """Keep URL lookups domain-based; never infer a URL from a substring."""
        value: str = observable.value.strip()
        kind: ObservableFlag = observable.type
        if kind is ObservableFlag.URL:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname:
                raise ValueError("URL must have a scheme and a host")
            # Accessing port also rejects malformed port specifications.
            _ = parsed.port
            value = parsed.hostname
            try:
                address = ip_address(value)
                return str(address), f"ipv{address.version}-addr:value"
            except ValueError:
                kind = ObservableFlag.FQDN
        if not value:
            raise ValueError("Empty observable")
        if kind is ObservableFlag.FQDN:
            domain: str = value.rstrip(".").encode("idna").decode("ascii").lower()
            if not domain:
                raise ValueError("Empty domain")
            return domain, "domain-name:value"
        if kind in (ObservableFlag.IPV4, ObservableFlag.IPV6):
            address = ip_address(value)
            return str(address), f"ipv{address.version}-addr:value"
        hashes: dict[ObservableFlag, str] = {
            ObservableFlag.MD5: "MD5",
            ObservableFlag.SHA1: "SHA-1",
            ObservableFlag.SHA256: "SHA-256",
        }
        if kind in hashes:
            return value.lower(), f"file:hashes.'{hashes[kind]}'"
        return value, None

    @staticmethod
    def _exact_filters(value: str, stix_path: str | None) -> _FilterGroup:
        """Equality filters do not tokenize IOC punctuation or expand wildcards."""
        named = _FilterGroup(
            mode="and",
            filters=[
                _Filter(key=["entity_type"], values=["Stix-Cyber-Observable"], operator="not_eq"),
                _Filter(key=["name", "aliases", "x_opencti_aliases"], values=[value]),
            ],
        )
        keys: list[str] = ["value"]
        types: list[str] = []
        if stix_path and stix_path.startswith("file:hashes."):
            keys = [stix_path.replace("file:", "").replace("'", "")]
            types = ["StixFile", "Artifact"]
        elif stix_path:
            types = [
                {
                    "domain-name:value": "Domain-Name",
                    "ipv4-addr:value": "IPv4-Addr",
                    "ipv6-addr:value": "IPv6-Addr",
                }[stix_path]
            ]
        observable_filters: list[_Filter] = [_Filter(key=keys, values=[value])]
        if types:
            observable_filters.append(_Filter(key=["entity_type"], values=types))
        observable = _FilterGroup(mode="and", filters=observable_filters)
        filters: list[_Filter] = []
        if stix_path:
            escaped: str = value.replace("\\", "\\\\").replace("'", "\\'")
            pattern: str = f"[{stix_path} = '{escaped}']"
            patterns: list[str] = [pattern]
            if stix_path == "file:hashes.'MD5'":
                patterns.append(pattern.replace("hashes.'MD5'", "hashes.MD5"))
            filters.append(_Filter(key=["pattern"], values=patterns))
        return _FilterGroup(filters=filters, filterGroups=[named, observable])

    @retry(
        retry=retry_if_exception_type((requests.Timeout, requests.ConnectionError)),
        stop=stop_after_attempt(2),
        wait=wait_fixed(0.5),
        reraise=True,
    )
    def _post(self, base_url: str, payload: _Request) -> _Data:
        response = requests.post(
            f"{base_url}/graphql",
            headers={"Authorization": f"Bearer {self.secrets.opencti_api_key}"},
            json=payload.model_dump(),
            proxies=self.proxies,
            verify=self.ssl_verify,
            timeout=10,
        )
        response.raise_for_status()
        result = _Response.model_validate(response.json())
        # GraphQL can report errors with HTTP 200 and partial data. Never turn
        # an authorization/schema failure into a clean 'zero matches' report.
        if result.errors or result.data is None:
            raise ValueError("OpenCTI returned GraphQL errors or no data")
        return result.data

    def _search(self, base_url: str, filters: _FilterGroup) -> tuple[list[_Node], bool]:
        nodes: dict[str, _Node] = {}
        cursor: str | None = None
        cursors: set[str] = set()
        truncated: bool = False
        for _ in range(MAX_PAGES):
            result = self._post(
                base_url,
                _Request(
                    query=SEARCH_QUERY,
                    variables={
                        "count": PAGE_SIZE,
                        "cursor": cursor,
                        "filters": filters.model_dump(mode="json", by_alias=True),
                    },
                ),
            )
            connection = result.global_search
            if connection is None or connection.page_info.global_count is None:
                raise ValueError("OpenCTI search response has no connection or total")
            for edge in connection.edges:
                nodes[edge.node.id] = edge.node
                if edge.node.indicators:
                    truncated |= edge.node.indicators.page_info.has_next_page
                    for linked in edge.node.indicators.edges:
                        nodes[linked.node.id] = linked.node
            if not connection.page_info.has_next_page:
                return list(nodes.values()), truncated
            cursor = connection.page_info.end_cursor
            if not cursor or cursor in cursors:
                raise ValueError("OpenCTI returned a missing or repeated pagination cursor")
            cursors.add(cursor)
        return list(nodes.values()), True

    @override
    def analyze(self, observable: Observable) -> dict[str, JsonValue] | None:
        if not self.secrets.opencti_api_key or not self.secrets.opencti_url:
            logger.warning("OpenCTI URL or API key is missing")
            return None
        try:
            value, stix_path = self._search_target(observable)
            base_url: str = self.secrets.opencti_url.rstrip("/")
            parsed = urlsplit(base_url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.netloc
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "OpenCTI URL must be an HTTP(S) base URL without query or fragment"
                )
            nodes, truncated = self._search(base_url, self._exact_filters(value, stix_path))
            latest = max(nodes, key=lambda node: node.created_at or "", default=None)
            indicator = max(
                (node for node in nodes if node.entity_type == "Indicator"),
                key=lambda node: node.created_at or "",
                default=None,
            )
            details = _Indicator()
            if indicator:
                response = self._post(
                    base_url, _Request(query=INDICATOR_QUERY, variables={"id": indicator.id})
                )
                details = response.indicator or _Indicator()
            counts: dict[str, JsonValue] = dict(Counter(node.entity_type for node in nodes))
            return {
                "entity_counts": counts,
                "global_count": len(nodes),
                "search_link": f"{base_url}/dashboard/search/knowledge/{quote(value, safe='')}",
                "search_value": value,
                "match_mode": "exact",
                "results_truncated": truncated,
                "latest_created_at": self._date(latest.created_at) if latest else None,
                "latest_indicator_link": (
                    f"{base_url}/dashboard/observations/indicators/{quote(indicator.id, safe='')}"
                )
                if indicator
                else None,
                "latest_indicator_name": details.name,
                "x_opencti_score": details.x_opencti_score,
                "revoked": details.revoked,
                "valid_from": self._date(details.valid_from),
                "valid_until": self._date(details.valid_until),
                "confidence": details.confidence,
            }
        except (requests.RequestException, ValidationError, ValueError, ConnectionError) as exc:
            logger.error("Error querying OpenCTI for '%s': %s", observable.value, exc)
            return None

    @staticmethod
    def _date(value: str | None) -> str | None:
        return value.split("T", 1)[0] if value else None

    @override
    def create_export_row(
        self, analysis_result: dict[str, JsonValue] | None
    ) -> dict[str, JsonValue]:
        if not analysis_result:
            return {
                f"opencti_{key}": None for key in ("entity_counts", "global_count", "last_seen")
            }
        counts = analysis_result.get("entity_counts")
        return {
            "opencti_entity_counts": ", ".join(f"{key}:{value}" for key, value in counts.items())
            if isinstance(counts, dict)
            else "",
            "opencti_global_count": analysis_result.get("global_count"),
            "opencti_last_seen": analysis_result.get("latest_created_at"),
        }
