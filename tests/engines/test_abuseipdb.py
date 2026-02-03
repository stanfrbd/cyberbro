import logging

import pytest
import requests
import responses

from engines.abuseipdb import AbuseIPDBEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.abuseipdb = "test_api_key_value"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.abuseipdb = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


# ============================================================================
# High Priority: Rewritten + Credentials Tests
# ============================================================================


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    """Test successful API response with all data fields."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {
        "data": {
            "ipAddress": ipv4_observable,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 25,
            "countryCode": "AU",
            "usageType": "Content Delivery Network",
            "isp": "APNIC and Cloudflare DNS Resolver project",
            "domain": "cloudflare.com",
            "hostnames": ["one.one.one.one"],
            "isTor": False,
            "totalReports": 24,
            "numDistinctUsers": 8,
            "lastReportedAt": "2025-04-22T13:01:09+00:00",
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["reports"] == 24
    assert result["risk_score"] == 25
    assert result["link"] == f"https://www.abuseipdb.com/check/{ipv4_observable}"


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying AbuseIPDB" in caplog.text


@responses.activate
def test_analyze_response_missing_data_key(secrets_with_key, ipv4_observable):
    """Test handling of valid 200 response missing 'data' key."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {"error": "No data"}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


# ============================================================================
# Medium Priority: Critical Paths Tests
# ============================================================================


@responses.activate
def test_analyze_ipv6_success(secrets_with_key, ipv6_observable):
    """Test successful analysis of IPv6 address."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    mock_resp = {
        "data": {
            "ipAddress": ipv6_observable,
            "abuseConfidenceScore": 50,
            "totalReports": 5,
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    assert result["reports"] == 5
    assert result["risk_score"] == 50
    assert result["link"] == f"https://www.abuseipdb.com/check/{ipv6_observable}"


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying AbuseIPDB" in caplog.text


@responses.activate
def test_analyze_request_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying AbuseIPDB" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = AbuseIPDBEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.abuseipdb.com/api/v2/check"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying AbuseIPDB" in caplog.text


# ============================================================================
# Low Priority: Export Row & Property Tests
# ============================================================================


def test_create_export_row_with_data():
    """Test export row with non-zero reports and risk_score."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "reports": 42,
        "risk_score": 75,
        "link": "https://www.abuseipdb.com/check/1.1.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["a_ipdb_reports"] == 42
    assert row["a_ipdb_risk"] == 75


def test_create_export_row_none():
    """Test export row with None result."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["a_ipdb_reports"] is None
    assert row["a_ipdb_risk"] is None


def test_create_export_row_missing_fields():
    """Test export row with missing optional fields."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "reports": 10,
        # Missing risk_score
    }

    row = engine.create_export_row(analysis_result)

    assert row["a_ipdb_reports"] == 10
    assert row["a_ipdb_risk"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = AbuseIPDBEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "abuseipdb"
    assert engine.supported_types == ["IPv4", "IPv6"]
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False
