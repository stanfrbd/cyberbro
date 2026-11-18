"""Regressions for literal IOC matching, pagination and linked indicators."""

import json

import pytest
import requests
import responses

from engines.opencti import OpenCTIEngine
from models.observable import Observable, ObservableFlag
from utils.config import Secrets

API = "https://cti.example/graphql"


@pytest.fixture
def engine() -> OpenCTIEngine:
    secrets = Secrets()
    secrets.opencti_url = "https://cti.example"
    secrets.opencti_api_key = "test-key"
    return OpenCTIEngine(secrets, proxies={"https": "http://proxy.example"}, ssl_verify=False)


def node(identifier: str, kind: str = "Domain-Name", **extra: object) -> dict:
    return {"id": identifier, "entity_type": kind, "created_at": "2026-01-01T10:00:00Z", **extra}


def page(
    nodes: list[dict], more: bool = False, cursor: str | None = None, total: int | None = None
) -> dict:
    return {
        "data": {
            "globalSearch": {
                "edges": [{"node": n} for n in nodes],
                "pageInfo": {
                    "hasNextPage": more,
                    "endCursor": cursor,
                    "globalCount": len(nodes) if total is None else total,
                },
            }
        }
    }


def detail() -> None:
    responses.post(API, json={"data": {"indicator": {"name": "Linked IOC", "x_opencti_score": 80}}})


def matches(group: dict, candidate: dict) -> bool:
    """Model documented FilterGroup equality semantics, not full-text matching."""
    results = []
    for f in group["filters"]:
        found = any(
            value
            in (
                candidate.get(key) if isinstance(candidate.get(key), list) else [candidate.get(key)]
            )
            for key in f["key"]
            for value in f["values"]
        )
        results.append(not found if f["operator"] == "not_eq" else found)
    results.extend(matches(child, candidate) for child in group["filterGroups"])
    return (all if group["mode"] == "and" else any)(results)


@pytest.mark.parametrize(
    ("value", "kind", "expected", "field", "entity_type"),
    [
        (
            "https://user:pass@EXAMPLE.com:8443/path?q=x#frag",
            ObservableFlag.URL,
            "example.com",
            "value",
            "Domain-Name",
        ),
        ("http://[2001:0db8::1]:80/path", ObservableFlag.URL, "2001:db8::1", "value", "IPv6-Addr"),
        ("HTTP://EXAMPLE.COM/", ObservableFlag.URL, "example.com", "value", "Domain-Name"),
        (
            "HTTP-STATUS.EXAMPLE.",
            ObservableFlag.FQDN,
            "http-status.example",
            "value",
            "Domain-Name",
        ),
        ("BÜCHER.example", ObservableFlag.FQDN, "xn--bcher-kva.example", "value", "Domain-Name"),
        ("192.0.2.1", ObservableFlag.IPV4, "192.0.2.1", "value", "IPv4-Addr"),
        ("2001:0DB8:0:0:0:0:0:1", ObservableFlag.IPV6, "2001:db8::1", "value", "IPv6-Addr"),
        ("A" * 32, ObservableFlag.MD5, "a" * 32, "hashes.MD5", "StixFile"),
        ("B" * 40, ObservableFlag.SHA1, "b" * 40, "hashes.SHA-1", "StixFile"),
        ("C" * 64, ObservableFlag.SHA256, "c" * 64, "hashes.SHA-256", "StixFile"),
        ("a" * 32, ObservableFlag.CHROME_EXTENSION, "a" * 32, "value", "Text"),
    ],
)
@responses.activate
def test_only_literal_values_match(engine, value, kind, expected, field, entity_type):
    candidates = [
        node("exact", entity_type, **{field: expected}),
        node("prefix", entity_type, **{field: expected + "0"}),
        node("suffix", entity_type, **{field: "x" + expected}),
        node("description", "Report", description=f"Observed {expected} in a campaign"),
        node("file-name", "StixFile", name=expected),
    ]
    candidates[-1]["entity_type"] = ["StixFile", "Stix-Cyber-Observable"]

    def callback(request):
        variables = json.loads(request.body)["variables"]
        assert not variables.get("search"), "A free-text query must not narrow/expand exact filters"
        matched = [c for c in candidates if matches(variables["filters"], c)]
        return 200, {}, json.dumps(page(matched))

    responses.add_callback(responses.POST, API, callback=callback)
    result = engine.analyze(Observable(value=value, type=kind))
    assert result is not None
    assert result["global_count"] == 1
    assert result["search_value"] == expected
    assert result["match_mode"] == "exact"
    assert expected in result["search_link"] or ":" in expected


@responses.activate
def test_recovers_linked_indicator_with_a_descriptive_name_and_deduplicates(engine):
    linked = node("i", "Indicator", created_at="2026-02-01T00:00:00Z")
    observable = node(
        "o", indicators={"edges": [{"node": linked}], "pageInfo": {"hasNextPage": False}}
    )
    responses.post(API, json=page([observable, linked]))
    detail()
    result = engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN))
    assert result["entity_counts"] == {"Domain-Name": 1, "Indicator": 1}
    assert result["global_count"] == 2
    assert result["latest_indicator_name"] == "Linked IOC"
    assert result["x_opencti_score"] == 80
    assert result["latest_created_at"] == "2026-02-01"


@responses.activate
def test_exact_patterns_cover_indicators_without_linked_observables(engine):
    candidate = {"pattern": "[ipv4-addr:value = '192.0.2.1']"}

    def callback(request):
        payload = json.loads(request.body)
        assert matches(payload["variables"]["filters"], candidate)
        assert not matches(
            payload["variables"]["filters"], {"pattern": "[ipv4-addr:value = '192.0.2.10']"}
        )
        return 200, {}, json.dumps(page([node("i", "Indicator")]))

    # Match the operation so the details response has its own handler.
    responses.add_callback(
        responses.POST,
        API,
        callback=callback,
        match=[lambda r: ("CyberbroExactSearch" in json.loads(r.body)["query"], "search only")],
    )
    detail()
    assert (
        engine.analyze(Observable(value="192.0.2.1", type=ObservableFlag.IPV4))["global_count"] == 1
    )


@responses.activate
def test_reads_all_pages_and_selects_latest_indicator_by_timestamp(engine):
    responses.post(API, json=page([node("old", "Indicator")], True, "next", 2))
    responses.post(
        API, json=page([node("new", "Indicator", created_at="2026-04-01T00:00:00Z")], total=2)
    )
    detail()
    result = engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN))
    assert result["entity_counts"] == {"Indicator": 2}
    assert result["global_count"] == 2
    assert json.loads(responses.calls[1].request.body)["variables"]["cursor"] == "next"
    assert json.loads(responses.calls[2].request.body)["variables"]["id"] == "new"


@pytest.mark.parametrize("cursor", [None, "repeated"])
@responses.activate
def test_invalid_pagination_cannot_return_a_false_complete_report(engine, cursor):
    responses.post(API, json=page([node("one")], True, cursor, 3))
    responses.post(API, json=page([node("two")], True, cursor, 3))
    assert engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN)) is None


@pytest.mark.parametrize("linked", [False, True])
@responses.activate
def test_reports_partial_counts_when_either_limit_is_hit(engine, monkeypatch, linked):
    monkeypatch.setattr("engines.opencti.MAX_PAGES", 1)
    record = node("o")
    if linked:
        record["indicators"] = {"edges": [], "pageInfo": {"hasNextPage": True}}
    responses.post(API, json=page([record], not linked, "more", 300))
    result = engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN))
    assert result["results_truncated"] is True
    assert result["global_count"] == 1


@pytest.mark.parametrize(
    "value", ["", "not-a-url", "https:///path", "https://example.com:bad/", "https://[broken/"]
)
@responses.activate
def test_malformed_url_never_triggers_a_broad_search(engine, value):
    assert engine.analyze(Observable(value=value, type=ObservableFlag.URL)) is None
    assert not responses.calls


@responses.activate
def test_graphql_errors_with_partial_data_are_not_silently_accepted(engine):
    data = page([])
    data["errors"] = [{"message": "Forbidden"}]
    responses.post(API, json=data)
    assert engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN)) is None


@responses.activate
def test_retries_transient_connection_failures_and_preserves_transport_settings(engine):
    responses.post(API, body=requests.Timeout("test timeout"))
    responses.post(API, json=page([]))
    result = engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN))
    assert result["global_count"] == 0
    assert len(responses.calls) == 2
    assert responses.calls[1].request.headers["Authorization"] == "Bearer test-key"
    assert responses.calls[1].request.req_kwargs["verify"] is False
    assert responses.calls[1].request.req_kwargs["proxies"]["https"] == "http://proxy.example"


@responses.activate
def test_preserves_opencti_deployment_path(engine):
    engine.secrets.opencti_url = "https://cti.example/opencti/"
    responses.post("https://cti.example/opencti/graphql", json=page([]))
    result = engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN))
    assert (
        result["search_link"]
        == "https://cti.example/opencti/dashboard/search/knowledge/example.com"
    )


@pytest.mark.parametrize("kind", [ObservableFlag.FQDN, ObservableFlag.IPV4])
@responses.activate
def test_empty_observable_never_matches_empty_attributes(engine, kind):
    assert engine.analyze(Observable(value="", type=kind)) is None
    assert not responses.calls


@responses.activate
def test_invalid_configuration_does_not_send_a_request(engine):
    engine.secrets.opencti_url = "https://cti.example?invalid=true"
    assert engine.analyze(Observable(value="example.com", type=ObservableFlag.FQDN)) is None
    assert not responses.calls
