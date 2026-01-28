import logging

import pytest
import requests
import responses

from engines.ipinfo import IPInfoEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.ipinfo = "test_ipinfo_token_12345"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.ipinfo = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


# ============================================================================
# High Priority: Success Tests & Credentials
# ============================================================================


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    """Test successful API response with all data fields."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv4_observable,
        "city": "Los Angeles",
        "region": "California",
        "country": "US",
        "hostname": "one.one.one.one",
        "org": "15169 Google LLC",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["geolocation"] == "Los Angeles, California"
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"
    assert result["hostname"] == "one.one.one.one"
    assert result["asn"] == "15169 Google LLC"
    assert result["link"] == f"https://ipinfo.io/{ipv4_observable}"


@responses.activate
def test_analyze_success_bogon(secrets_with_key):
    """Test successful response for bogon/private IP."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    bogon_ip = "10.0.0.1"
    url = f"https://ipinfo.io/{bogon_ip}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": bogon_ip,
        "bogon": True,
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(bogon_ip, "IPv4")

    assert result is not None
    assert result["ip"] == bogon_ip
    assert result["geolocation"] == ""
    assert result["country_code"] == ""
    assert result["country_name"] == "Bogon"
    assert result["hostname"] == "Private IP"
    assert result["asn"] == "BOGON"
    assert result["link"] == f"https://ipinfo.io/{bogon_ip}"


@responses.activate
def test_analyze_success_country_resolution(secrets_with_key, ipv4_observable):
    """Test successful country code resolution via pycountry."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv4_observable,
        "city": "London",
        "region": "England",
        "country": "GB",
        "hostname": "cloudflare.com",
        "org": "15169 Google",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["country_code"] == "GB"
    assert result["country_name"] == "United Kingdom"


@responses.activate
def test_analyze_success_unknown_country(secrets_with_key, ipv4_observable):
    """Test handling of invalid/unknown country code."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv4_observable,
        "city": "Unknown City",
        "region": "Unknown Region",
        "country": "XX",
        "hostname": "unknown.host",
        "org": "15169",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["country_code"] == "XX"
    assert result["country_name"] == "Unknown"


# ============================================================================
# Observable Type Routing Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(secrets_with_key, ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv6_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv6_observable,
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "hostname": "google.com",
        "org": "15169 Google LLC",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    assert result["ip"] == ipv6_observable
    assert result["geolocation"] == "Mountain View, California"
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"


# ============================================================================
# HTTP Error & Network Handling Tests
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipinfo" in caplog.text


@responses.activate
def test_analyze_missing_ip_key(secrets_with_key, ipv4_observable, caplog):
    """Test handling of valid 200 response missing 'ip' key."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "city": "Los Angeles",
        "region": "California",
        "country": "US",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_no_bogon_and_no_ip(secrets_with_key, ipv4_observable):
    """Test response with neither bogon nor ip key."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {"error": "Invalid IP address"}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipinfo" in caplog.text


@responses.activate
def test_analyze_request_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipinfo" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying ipinfo" in caplog.text


# ============================================================================
# Response Variation Tests
# ============================================================================


@responses.activate
def test_analyze_missing_optional_fields(secrets_with_key, ipv4_observable):
    """Test handling of minimal response with missing optional fields."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {"ip": ipv4_observable}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["geolocation"] == "Unknown, Unknown"
    assert result["country_code"] == "Unknown"
    assert result["country_name"] == "Unknown"
    assert result["hostname"] == "Unknown"
    assert result["asn"] == "Unknown"


@responses.activate
def test_analyze_missing_hostname(secrets_with_key, ipv4_observable):
    """Test handling of response missing hostname field."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv4_observable,
        "city": "San Francisco",
        "region": "California",
        "country": "US",
        "org": "15169 Google",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["hostname"] == "Unknown"
    assert result["geolocation"] == "San Francisco, California"


@responses.activate
def test_analyze_asn_parsing(secrets_with_key, ipv4_observable):
    """Test ASN extraction and formatting for export parsing."""
    engine = IPInfoEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://ipinfo.io/{ipv4_observable}/json?token={secrets_with_key.ipinfo}"

    mock_resp = {
        "ip": ipv4_observable,
        "city": "Boston",
        "region": "Massachusetts",
        "country": "US",
        "org": "15169 Google LLC",
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"] == "15169 Google LLC"


# ============================================================================
# Export Row Formatting Tests
# ============================================================================


def test_create_export_row_complete():
    """Test export row with complete analysis result."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Los Angeles, California",
        "country_code": "US",
        "country_name": "United States",
        "hostname": "one.one.one.one",
        "asn": "15169 Google LLC",
        "link": "https://ipinfo.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipinfo_cn"] == "US"
    assert row["ipinfo_country"] == "United States"
    assert row["ipinfo_geo"] == "Los Angeles, California"
    assert row["ipinfo_asn"] == "15169"
    assert row["ipinfo_org"] == "Google LLC"


def test_create_export_row_none():
    """Test export row with None result."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["ipinfo_cn"] is None
    assert row["ipinfo_country"] is None
    assert row["ipinfo_geo"] is None
    assert row["ipinfo_asn"] is None
    assert row["ipinfo_org"] is None


def test_create_export_row_asn_number_only():
    """Test export row with ASN number but no organization."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Los Angeles, California",
        "country_code": "US",
        "country_name": "United States",
        "hostname": "one.one.one.one",
        "asn": "15169",
        "link": "https://ipinfo.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipinfo_asn"] == "15169"
    assert row["ipinfo_org"] is None


def test_create_export_row_asn_unknown():
    """Test export row with 'Unknown' ASN value."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "1.1.1.1",
        "geolocation": "Los Angeles, California",
        "country_code": "US",
        "country_name": "United States",
        "hostname": "one.one.one.one",
        "asn": "Unknown",
        "link": "https://ipinfo.io/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipinfo_asn"] == "Unknown"
    assert row["ipinfo_org"] is None


def test_create_export_row_bogon():
    """Test export row from bogon analysis result."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ip": "10.0.0.1",
        "geolocation": "",
        "country_code": "",
        "country_name": "Bogon",
        "hostname": "Private IP",
        "asn": "BOGON",
        "link": "https://ipinfo.io/10.0.0.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ipinfo_cn"] == ""
    assert row["ipinfo_country"] == "Bogon"
    assert row["ipinfo_geo"] == ""
    assert row["ipinfo_asn"] == "BOGON"
    assert row["ipinfo_org"] is None


# ============================================================================
# Property & Inheritance Tests
# ============================================================================


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = IPInfoEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "ipinfo"
    assert engine.supported_types == ["IPv4", "IPv6"]
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
