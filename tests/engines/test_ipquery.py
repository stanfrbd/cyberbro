import logging

import pytest
import requests
import responses

from engines.ipquery import IPQueryEngine
from models.observable import ObservableType

from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    return Secrets()


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


# ============================================================================
# High Priority: Success Tests
# ============================================================================


@responses.activate
def test_analyze_success_complete(ipv4_observable):
    """Test successful API response with all data fields."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": {
            "city": "Los Angeles",
            "state": "California",
            "country": "United States",
            "country_code": "US",
        },
        "isp": {
            "isp": "Google LLC",
            "asn": "15169",
        },
        "risk": {
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False,
            "risk_score": 0,
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["geolocation"] == "Los Angeles, California"
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"
    assert result["isp"] == "Google LLC"
    assert result["asn"] == "15169"
    assert result["is_vpn"] is False
    assert result["is_tor"] is False
    assert result["is_proxy"] is False
    assert result["risk_score"] == 0
    assert result["link"] == f"https://api.ipquery.io/{ipv4_observable}"


@responses.activate
def test_analyze_success_minimal(ipv4_observable):
    """Test minimal response with only ip field, rest defaults."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {"ip": ipv4_observable}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["geolocation"] == "Unknown, Unknown"
    assert result["country_code"] == "Unknown"
    assert result["country_name"] == "Unknown"
    assert result["isp"] == "Unknown"
    assert result["asn"] == "Unknown"
    assert result["is_vpn"] is False
    assert result["is_tor"] is False
    assert result["is_proxy"] is False
    assert result["risk_score"] == "Unknown"


@responses.activate
def test_analyze_success_country_only(ipv4_observable):
    """Test response with only country in location dict."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": {
            "country": "United Kingdom",
            "country_code": "GB",
        },
        "isp": {},
        "risk": {},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["geolocation"] == "Unknown, Unknown"
    assert result["country_code"] == "GB"
    assert result["country_name"] == "United Kingdom"
    assert result["isp"] == "Unknown"
    assert result["asn"] == "Unknown"


@responses.activate
def test_analyze_success_risk_true(ipv4_observable):
    """Test response with risk flags set to true."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": {
            "city": "Moscow",
            "state": "Moscow",
            "country": "Russia",
            "country_code": "RU",
        },
        "isp": {
            "isp": "Suspicious ISP",
            "asn": "64512",
        },
        "risk": {
            "is_vpn": True,
            "is_tor": True,
            "is_proxy": True,
            "risk_score": 95,
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["is_vpn"] is True
    assert result["is_tor"] is True
    assert result["is_proxy"] is True
    assert result["risk_score"] == 95


# ============================================================================
# Observable Type Routing Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv6_observable}"

    mock_resp = {
        "ip": ipv6_observable,
        "location": {
            "city": "Mountain View",
            "state": "California",
            "country": "United States",
            "country_code": "US",
        },
        "isp": {
            "isp": "Google LLC",
            "asn": "15169",
        },
        "risk": {
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False,
            "risk_score": 0,
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, ObservableType.IPV6)

    assert result is not None
    assert result["ip"] == ipv6_observable
    assert result["country_code"] == "US"


# ============================================================================
# HTTP Error & Network Handling Tests
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying ipquery" in caplog.text


@responses.activate
def test_analyze_missing_ip_key(ipv4_observable, caplog):
    """Test handling of valid 200 response missing 'ip' key."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "location": {
            "city": "Los Angeles",
            "state": "California",
            "country": "United States",
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


@responses.activate
def test_analyze_request_timeout(ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying ipquery" in caplog.text


@responses.activate
def test_analyze_request_connection_error(ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying ipquery" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying ipquery" in caplog.text


# ============================================================================
# Response Variation Tests
# ============================================================================


@responses.activate
def test_analyze_nested_dict_none_values(ipv4_observable):
    """Test handling of nested dicts that are None instead of empty."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": None,
        "isp": None,
        "risk": None,
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    # This should raise an exception because .get() on None will fail
    # Exception is caught and returns None
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


@responses.activate
def test_analyze_nested_dict_partial(ipv4_observable):
    """Test response with partial nested dict data."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": {
            "city": "Boston",
            # missing state
            "country": "United States",
            "country_code": "US",
        },
        "isp": {
            "isp": "Verizon",
            # missing asn
        },
        "risk": {
            "is_vpn": False,
            # missing other risk fields
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["geolocation"] == "Boston, Unknown"
    assert result["isp"] == "Verizon"
    assert result["asn"] == "Unknown"
    assert result["is_vpn"] is False
    assert result["is_tor"] is False
    assert result["risk_score"] == "Unknown"


@responses.activate
def test_analyze_empty_risk_dict(ipv4_observable):
    """Test response with empty risk dict."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://api.ipquery.io/{ipv4_observable}"

    mock_resp = {
        "ip": ipv4_observable,
        "location": {
            "city": "Paris",
            "state": "Ile-de-France",
            "country": "France",
            "country_code": "FR",
        },
        "isp": {
            "isp": "Orange",
            "asn": "3352",
        },
        "risk": {},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["is_vpn"] is False
    assert result["is_tor"] is False
    assert result["is_proxy"] is False
    assert result["risk_score"] == "Unknown"


# ============================================================================
# Export Row Formatting Tests
# ============================================================================


def test_create_export_row_complete():
    """Test export row with complete analysis result."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Los Angeles, California",
        "country_code": "US",
        "country_name": "United States",
        "isp": "Google LLC",
        "asn": "15169",
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "risk_score": 0,
        "link": "https://api.ipquery.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipq_cn"] == "US"
    assert row["ipq_country"] == "United States"
    assert row["ipq_geo"] == "Los Angeles, California"
    assert row["ipq_asn"] == "15169"
    assert row["ipq_isp"] == "Google LLC"
    assert row["ipq_vpn"] is False
    assert row["ipq_tor"] is False
    assert row["ipq_proxy"] is False


def test_create_export_row_none():
    """Test export row with None result."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["ipq_cn"] is None
    assert row["ipq_country"] is None
    assert row["ipq_geo"] is None
    assert row["ipq_asn"] is None
    assert row["ipq_isp"] is None
    assert row["ipq_vpn"] is None
    assert row["ipq_tor"] is None
    assert row["ipq_proxy"] is None


def test_create_export_row_with_risk_flags_true():
    """Test export row with risk flags set to true."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Moscow, Moscow",
        "country_code": "RU",
        "country_name": "Russia",
        "isp": "Suspicious ISP",
        "asn": "64512",
        "is_vpn": True,
        "is_tor": True,
        "is_proxy": True,
        "risk_score": 95,
        "link": "https://api.ipquery.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipq_vpn"] is True
    assert row["ipq_tor"] is True
    assert row["ipq_proxy"] is True


def test_create_export_row_unknown_values():
    """Test export row with 'Unknown' string values."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Unknown, Unknown",
        "country_code": "Unknown",
        "country_name": "Unknown",
        "isp": "Unknown",
        "asn": "Unknown",
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "risk_score": "Unknown",
        "link": "https://api.ipquery.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipq_cn"] == "Unknown"
    assert row["ipq_country"] == "Unknown"
    assert row["ipq_geo"] == "Unknown, Unknown"
    assert row["ipq_asn"] == "Unknown"
    assert row["ipq_isp"] == "Unknown"


# ============================================================================
# Property & Inheritance Tests
# ============================================================================


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = IPQueryEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "ipquery"
    assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
