import json
import logging
from pathlib import Path

import pytest
import requests
import responses

from engines.internetdata import InternetDataEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

API = "https://api.internetdata.io"
RESPONSES = Path("tests/api_responses/internetdata")


def saved_response(name: str) -> dict:
    """An answer saved from the live keyless API."""
    return json.loads((RESPONSES / f"{name}_api_response.json").read_text(encoding="utf-8"))


@pytest.fixture
def engine() -> InternetDataEngine:
    return InternetDataEngine(Secrets(), proxies={}, ssl_verify=True)


@pytest.fixture
def ipv4_observable() -> Observable:
    return Observable(value="8.8.8.8", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable() -> Observable:
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


@responses.activate
def test_analyze_ipv4(engine, ipv4_observable):
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=saved_response("ipv4"))

    result = engine.analyze(ipv4_observable)

    assert result == {
        "ip": "8.8.8.8",
        "country_code": "US",
        "country_name": "United States",
        "asn": "AS15169",
        "as_name": "Google LLC",
        "company_name": "Google LLC",
        "company_domain": "google.com",
        "hostname": "dns.google",
        "abuse_email": "network-abuse@google.com",
        "is_tor": False,
        "is_relay": False,
        "relay_provider": None,
        "is_anycast": True,
        "is_bogon": False,
        "link": "https://internetdata.io/8.8.8.8",
    }


@responses.activate
def test_analyze_ipv6(engine, ipv6_observable):
    responses.add(responses.GET, f"{API}/{ipv6_observable.value}", json=saved_response("ipv6"))

    result = engine.analyze(ipv6_observable)

    assert result is not None
    assert result["ip"] == ipv6_observable.value
    assert result["asn"] == "AS15169"
    assert result["is_anycast"] is False
    assert result["link"] == f"https://internetdata.io/{ipv6_observable.value}"


@responses.activate
def test_analyze_tor(engine, ipv4_observable):
    data = saved_response("tor")
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=data)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["ip"] == data["ip"]
    assert result["is_tor"] is True
    assert result["is_relay"] is False
    assert result["relay_provider"] is None


@responses.activate
def test_analyze_relay_names_provider(engine, ipv4_observable):
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=saved_response("relay"))

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_relay"] is True
    assert result["is_tor"] is False
    assert result["relay_provider"] == "Apple iCloud Private Relay"


@responses.activate
def test_analyze_relay_provider_without_name(engine, ipv4_observable):
    data = saved_response("relay")
    data["relay"] = {"provider": "apple_private_relay"}
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=data)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["relay_provider"] == "apple_private_relay"


@responses.activate
def test_analyze_bogon(engine, ipv4_observable):
    """A private address: every string is empty and falls back."""
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=saved_response("bogon"))

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_bogon"] is True
    assert result["country_code"] == "Unknown"
    assert result["country_name"] == "Unknown"
    assert result["asn"] == "Unknown"
    assert result["as_name"] == "Unknown"
    assert result["company_name"] is None
    assert result["company_domain"] is None
    assert result["hostname"] is None
    assert result["abuse_email"] is None


@responses.activate
def test_analyze_minimal_response(engine, ipv4_observable):
    """Only the address: every field falls back."""
    responses.add(
        responses.GET,
        f"{API}/{ipv4_observable.value}",
        json={"ip": ipv4_observable.value, "location": None, "asn": None, "company": None},
    )

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_tor"] is False
    assert result["is_relay"] is False
    assert result["is_anycast"] is False
    assert result["is_bogon"] is False
    assert result["country_name"] == "Unknown"
    assert result["asn"] == "Unknown"
    assert result["abuse_email"] is None


@pytest.mark.parametrize("status_code", [400, 429, 500, 503])
@responses.activate
def test_analyze_http_error(engine, ipv4_observable, status_code, caplog):
    responses.add(
        responses.GET, f"{API}/{ipv4_observable.value}", json={"error": "x"}, status=status_code
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Error querying InternetData" in caplog.text


@responses.activate
def test_analyze_missing_ip_key(engine, ipv4_observable):
    responses.add(
        responses.GET,
        f"{API}/{ipv4_observable.value}",
        json={"error": "not a valid IP address, AS number or domain"},
    )

    assert engine.analyze(ipv4_observable) is None


@responses.activate
def test_analyze_timeout(engine, ipv4_observable, caplog):
    responses.add(
        responses.GET,
        f"{API}/{ipv4_observable.value}",
        body=requests.exceptions.Timeout("timed out"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Error querying InternetData" in caplog.text


@responses.activate
def test_analyze_invalid_json(engine, ipv4_observable, caplog):
    responses.add(
        responses.GET, f"{API}/{ipv4_observable.value}", body="<html>gateway</html>", status=200
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result is None


@responses.activate
def test_analyze_sends_no_credentials(engine, ipv4_observable):
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=saved_response("ipv4"))

    engine.analyze(ipv4_observable)

    assert "Authorization" not in responses.calls[0].request.headers


def test_create_export_row(engine):
    row = engine.create_export_row(
        {
            "country_code": "US",
            "country_name": "United States",
            "asn": "AS15169",
            "as_name": "Google LLC",
            "company_name": "Google LLC",
            "company_domain": "google.com",
            "hostname": "dns.google",
            "abuse_email": "network-abuse@google.com",
            "is_tor": False,
            "is_relay": True,
            "relay_provider": "Apple iCloud Private Relay",
            "is_anycast": True,
        }
    )

    assert row == {
        "inetd_cn": "US",
        "inetd_country": "United States",
        "inetd_asn": "AS15169",
        "inetd_as_name": "Google LLC",
        "inetd_company": "Google LLC",
        "inetd_company_domain": "google.com",
        "inetd_hostname": "dns.google",
        "inetd_abuse": "network-abuse@google.com",
        "inetd_tor": False,
        "inetd_relay": "Apple iCloud Private Relay",
        "inetd_anycast": True,
    }


def test_create_export_row_none(engine):
    row = engine.create_export_row(None)

    assert set(row) == {
        "inetd_cn",
        "inetd_country",
        "inetd_asn",
        "inetd_as_name",
        "inetd_company",
        "inetd_company_domain",
        "inetd_hostname",
        "inetd_abuse",
        "inetd_tor",
        "inetd_relay",
        "inetd_anycast",
    }
    assert all(v is None for v in row.values())


def test_engine_properties(engine):
    assert engine.name == "internetdata"
    assert engine.supported_types == ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
