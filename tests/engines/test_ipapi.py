import logging

import pytest
import requests
import responses

from engines.ipapi import IPAPIEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.ipapi = "K" * 20
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.ipapi = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
        "asn": {"asn": "15169", "org": "Google LLC"},
        "vpn": {"service": "TestVPN", "url": "https://testvpn.example"},
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["asn"]["asn"] == "AS15169"


@responses.activate
def test_analyze_minimal_and_asn_missing(secrets_without_key, ipv4_observable):
    engine = IPAPIEngine(secrets_without_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"ip": ipv4_observable}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"]["asn"] == "Unknown"


@responses.activate
def test_analyze_missing_credentials_error(secrets_with_key, ipv4_observable):
    """Test handling of API response indicating missing/invalid credentials."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"error": "invalid API key"}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    # When 'ip' key is missing from response, analyze returns None
    assert result is None


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    responses.add(responses.POST, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipapi" in caplog.text


@responses.activate
def test_create_export_row_full():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "is_vpn": True,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
        "asn": {"asn": "AS15169", "org": "Google LLC"},
        "vpn": {"service": "TestVPN", "url": "https://testvpn.example"},
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_city"] == "LA"


def test_create_export_row_none():
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)

    assert all(v is None for v in row.values())


# ============================================================================
# Medium Priority: Other Critical Paths Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(secrets_with_key, ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv6_observable,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_abuser": False,
        "location": {
            "city": "Mountain View",
            "state": "CA",
            "country": "United States",
            "country_code": "US",
        },
        "asn": {"asn": "15169", "org": "Google LLC"},
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    assert result["ip"] == ipv6_observable
    assert result["asn"]["asn"] == "AS15169"


@responses.activate
def test_analyze_asn_without_asn_subfield(secrets_with_key, ipv4_observable):
    """Test handling of ASN dict without 'asn' subfield."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {
        "ip": ipv4_observable,
        "asn": {"org": "Google LLC"},  # Missing 'asn' subfield
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    # Should handle gracefully - either keep structure or default
    assert result is not None
    assert result["ip"] == ipv4_observable


@responses.activate
def test_analyze_asn_with_empty_asn_value(secrets_with_key, ipv4_observable):
    """Test handling of ASN dict that is falsy (e.g., empty or None)."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    # Test with empty/falsy asn dict
    mock_resp = {
        "ip": ipv4_observable,
        "asn": {},  # Empty dict is falsy
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Empty asn dict should trigger default per line 50-51 logic
    assert result["asn"]["asn"] == "Unknown"


@responses.activate
def test_analyze_response_missing_ip_key(secrets_with_key, ipv4_observable, caplog):
    """Test handling of valid 200 response missing 'ip' key."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    mock_resp = {"asn": {"asn": "15169", "org": "Google LLC"}}  # Missing 'ip' key

    responses.add(responses.POST, url, json=mock_resp, status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    # Should return None silently when 'ip' is missing
    assert result is None


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipapi" in caplog.text


@responses.activate
def test_analyze_request_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = IPAPIEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.ipapi.is"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.POST, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipapi" in caplog.text


# ============================================================================
# Low Priority: Edge Cases Tests
# ============================================================================


def test_create_export_row_missing_nested_keys():
    """Test export row when nested dicts have missing keys."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "is_vpn": False,
        "location": {"city": "LA"},  # Missing state, country, country_code
        "asn": {"asn": "AS15169"},  # Missing org
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] == "LA"
    assert row["ipapi_state"] is None
    assert row["ipapi_country"] is None
    assert row["ipapi_country_code"] is None
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_org"] is None


def test_create_export_row_missing_location_dict():
    """Test export row when location dict is missing entirely."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "is_vpn": False,
        "asn": {"asn": "AS15169", "org": "Google LLC"},
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] is None
    assert row["ipapi_state"] is None
    assert row["ipapi_country"] is None
    assert row["ipapi_country_code"] is None
    assert row["ipapi_asn"] == "AS15169"
    assert row["ipapi_org"] == "Google LLC"


def test_create_export_row_missing_asn_dict():
    """Test export row when ASN dict is missing entirely."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "is_vpn": False,
        "location": {"city": "LA", "state": "CA", "country": "United States", "country_code": "US"},
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipapi_ip"] == "1.1.1.1"
    assert row["ipapi_city"] == "LA"
    assert row["ipapi_asn"] is None
    assert row["ipapi_org"] is None


def test_create_export_row_empty_dict():
    """Test export row with empty result dict."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row({})

    assert all(v is None for v in row.values())


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = IPAPIEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "ipapi"
    assert engine.supported_types == ["IPv4", "IPv6"]
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
