import logging

import pytest
import requests
import responses

from engines.vpndetection import VPNDetectionEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

API = "https://api.vpndetection.io"


@pytest.fixture
def engine() -> VPNDetectionEngine:
    return VPNDetectionEngine(Secrets(), proxies={}, ssl_verify=True)


@pytest.fixture
def ipv4_observable() -> Observable:
    return Observable(value="146.70.116.130", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable() -> Observable:
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


def full_response(ip: str) -> dict:
    """A keyless answer, as the API returns it."""
    return {
        "ip": ip,
        "is_vpn": True,
        "is_relay": False,
        "is_tor": False,
        "relay": {},
        "tor": {},
        "location": {
            "continent": "EU",
            "continent_name": "Europe",
            "country": "AT",
            "country_name": "Austria",
            "timezone": "Europe/Vienna",
        },
        "asn": {
            "asn": 9009,
            "name": "M247 Europe SRL",
            "domain": "m247global.com",
            "type": "hosting",
            "prefix": "146.70.116.0/24",
        },
    }


@responses.activate
def test_analyze_vpn(engine, ipv4_observable):
    responses.add(
        responses.GET, f"{API}/{ipv4_observable.value}", json=full_response(ipv4_observable.value)
    )

    result = engine.analyze(ipv4_observable)

    assert result == {
        "ip": "146.70.116.130",
        "is_vpn": True,
        "is_tor": False,
        "is_relay": False,
        "relay_provider": None,
        "country_code": "AT",
        "country_name": "Austria",
        "asn": "AS9009",
        "as_name": "M247 Europe SRL",
        "link": "https://vpndetection.io/146.70.116.130",
    }


@responses.activate
def test_analyze_relay_names_provider(engine, ipv4_observable):
    data = full_response(ipv4_observable.value)
    data.update(
        {
            "is_vpn": False,
            "is_relay": True,
            "relay": {
                "provider": "apple_private_relay",
                "confidence": "high",
                "last_seen": "2026-11-12",
            },
        }
    )
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=data)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_relay"] is True
    assert result["relay_provider"] == "apple_private_relay"


@responses.activate
def test_analyze_tor(engine, ipv4_observable):
    data = full_response(ipv4_observable.value)
    data.update({"is_vpn": False, "is_tor": True, "tor": {"provider": "", "confidence": "high"}})
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json=data)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_tor"] is True
    assert result["relay_provider"] is None


@responses.activate
def test_analyze_ipv6(engine, ipv6_observable):
    responses.add(
        responses.GET, f"{API}/{ipv6_observable.value}", json=full_response(ipv6_observable.value)
    )

    result = engine.analyze(ipv6_observable)

    assert result is not None
    assert result["ip"] == ipv6_observable.value
    assert result["link"] == f"https://vpndetection.io/{ipv6_observable.value}"


@responses.activate
def test_analyze_minimal_response(engine, ipv4_observable):
    """No location or ASN (an unannounced address): every field falls back."""
    responses.add(
        responses.GET,
        f"{API}/{ipv4_observable.value}",
        json={"ip": ipv4_observable.value, "location": None, "asn": {"asn": 0}},
    )

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["is_vpn"] is False
    assert result["is_tor"] is False
    assert result["is_relay"] is False
    assert result["country_code"] == "Unknown"
    assert result["country_name"] == "Unknown"
    assert result["asn"] == "Unknown"
    assert result["as_name"] == "Unknown"


@pytest.mark.parametrize("status_code", [400, 429, 500, 503])
@responses.activate
def test_analyze_http_error(engine, ipv4_observable, status_code, caplog):
    responses.add(
        responses.GET, f"{API}/{ipv4_observable.value}", json={"error": "x"}, status=status_code
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Error querying VPNDetection" in caplog.text


@responses.activate
def test_analyze_missing_ip_key(engine, ipv4_observable):
    responses.add(responses.GET, f"{API}/{ipv4_observable.value}", json={"error": "invalid ip"})

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
    assert "Error querying VPNDetection" in caplog.text


@responses.activate
def test_analyze_invalid_json(engine, ipv4_observable, caplog):
    responses.add(
        responses.GET, f"{API}/{ipv4_observable.value}", body="<html>gateway</html>", status=200
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable)

    assert result is None


def test_create_export_row(engine):
    row = engine.create_export_row(
        {
            "country_code": "AT",
            "country_name": "Austria",
            "asn": "AS9009",
            "as_name": "M247 Europe SRL",
            "is_vpn": True,
            "is_tor": False,
            "is_relay": True,
            "relay_provider": "apple_private_relay",
        }
    )

    assert row == {
        "vpnd_cn": "AT",
        "vpnd_country": "Austria",
        "vpnd_asn": "AS9009",
        "vpnd_as_name": "M247 Europe SRL",
        "vpnd_vpn": True,
        "vpnd_tor": False,
        "vpnd_relay": "apple_private_relay",
    }


def test_create_export_row_none(engine):
    row = engine.create_export_row(None)

    assert set(row) == {
        "vpnd_cn",
        "vpnd_country",
        "vpnd_asn",
        "vpnd_as_name",
        "vpnd_vpn",
        "vpnd_tor",
        "vpnd_relay",
    }
    assert all(v is None for v in row.values())


def test_engine_properties(engine):
    assert engine.name == "vpndetection"
    assert engine.supported_types == ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
