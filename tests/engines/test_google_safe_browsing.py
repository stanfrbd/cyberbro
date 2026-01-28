import logging

import pytest
import requests
import responses

from engines.google_safe_browsing import GoogleSafeBrowsingEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.google_safe_browsing = "AIzaSy_test_api_key_12345678"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.google_safe_browsing = ""
    return s


@pytest.fixture
def url_observable():
    return "http://malicious-site.com"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def ipv4_observable():
    return "192.168.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


# ============================================================================
# High Priority: Credentials & Response Parsing Tests
# ============================================================================


@responses.activate
def test_analyze_threat_found_complete(secrets_with_key, url_observable):
    """Test successful API response with threat found and complete data."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ALL",
                "threat": {"url": url_observable},
                "cacheDuration": "300s",
            }
        ]
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert result["threat_found"] == "Threat found"
    assert result["details"] is not None
    assert len(result["details"]) == 1
    assert result["details"][0]["threatType"] == "MALWARE"


@responses.activate
def test_analyze_no_threat_found(secrets_with_key, url_observable):
    """Test successful API response with no threat detected."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert result["threat_found"] == "No threat found"
    assert result["details"] is None


@responses.activate
def test_analyze_minimal_threat_match(secrets_with_key, url_observable):
    """Test with minimal threat match structure (only required fields)."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ALL",
                "threat": {"url": url_observable},
            }
        ]
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert result["threat_found"] == "Threat found"
    assert isinstance(result["details"], list)


@responses.activate
def test_analyze_unauthorized_response(secrets_with_key, url_observable, caplog):
    """Test handling of 401 Unauthorized response (missing/invalid API key)."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    responses.add(responses.POST, url, json={"error": "unauthorized"}, status=401)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_forbidden_response(secrets_with_key, url_observable, caplog):
    """Test handling of 403 Forbidden response (insufficient permissions)."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    responses.add(responses.POST, url, json={"error": "forbidden"}, status=403)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_server_error_500(secrets_with_key, url_observable, caplog):
    """Test handling of HTTP 500 server error."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    responses.add(responses.POST, url, json={"error": "server error"}, status=500)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_bad_request_400(secrets_with_key, url_observable, caplog):
    """Test handling of HTTP 400 bad request."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    responses.add(responses.POST, url, json={"error": "bad request"}, status=400)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_request_timeout(secrets_with_key, url_observable, caplog):
    """Test handling of request timeout."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_request_connection_error(secrets_with_key, url_observable, caplog):
    """Test handling of connection error."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.POST, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, url_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    responses.add(responses.POST, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable, "URL")

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


# ============================================================================
# Medium Priority: Observable Type Handling Tests
# ============================================================================


@pytest.mark.parametrize(
    "observable_value,observable_type,threat_type",
    [
        ("http://malicious-site.com", "URL", "MALWARE"),
        ("example.com", "FQDN", "SOCIAL_ENGINEERING"),
        ("192.168.1.1", "IPv4", "UNWANTED_SOFTWARE"),
        ("2001:4860:4860::8888", "IPv6", "THREAT_TYPE_UNSPECIFIED"),
    ],
)
@responses.activate
def test_analyze_observable_types_success(
    secrets_with_key, observable_value, observable_type, threat_type
):
    """Test various observable types wrapped and analyzed successfully."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {"matches": [{"threatType": threat_type}]}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["threat_found"] == "Threat found"


def test_analyze_invalid_observable_type(secrets_with_key):
    """Test handling of unsupported observable types."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    result = engine.analyze("some_value", "INVALID_TYPE")

    assert result is None


@responses.activate
def test_analyze_empty_url_observable(secrets_with_key, caplog):
    """Test with empty string URL observable."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze("", "URL")

    assert result is not None
    assert result["threat_found"] == "No threat found"


@responses.activate
def test_analyze_url_with_query_parameters(secrets_with_key):
    """Test URL with query parameters preserved."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    url_with_params = "http://site.com?param=value&other=123"

    mock_resp = {"matches": [{"threatType": "MALWARE"}]}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_with_params, "URL")

    assert result is not None
    assert result["threat_found"] == "Threat found"


@responses.activate
def test_analyze_url_with_fragment_identifier(secrets_with_key):
    """Test URL with fragment identifier preserved."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    url_with_fragment = "http://site.com#section"

    mock_resp = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_with_fragment, "URL")

    assert result is not None
    assert result["threat_found"] == "Threat found"


# ============================================================================
# Medium Priority: Request Formation & API Details Tests
# ============================================================================


@responses.activate
def test_analyze_request_contains_threat_types(secrets_with_key, url_observable):
    """Test that request body contains all required threat types."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {}

    responses.add(responses.POST, api_url, json=mock_resp, status=200)

    engine.analyze(url_observable, "URL")

    # Verify request was made
    assert len(responses.calls) == 1
    request = responses.calls[0].request

    # Verify request body contains threatTypes
    assert b"threatTypes" in request.body


@responses.activate
def test_analyze_request_uses_post_method(secrets_with_key, url_observable):
    """Test that request uses POST HTTP method."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {}

    responses.add(responses.POST, api_url, json=mock_resp, status=200)

    engine.analyze(url_observable, "URL")

    assert len(responses.calls) == 1
    assert responses.calls[0].request.method == "POST"


@responses.activate
def test_analyze_api_key_in_url_query_params(secrets_with_key, url_observable):
    """Test that API key is passed as query parameter in URL."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {}

    responses.add(responses.POST, api_url, json=mock_resp, status=200)

    engine.analyze(url_observable, "URL")

    assert len(responses.calls) == 1
    request_url = responses.calls[0].request.url
    assert f"key={secrets_with_key.google_safe_browsing}" in request_url


@responses.activate
def test_analyze_response_parsing_with_json(secrets_with_key, url_observable):
    """Test that response JSON is parsed correctly."""
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    mock_resp = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "WINDOWS",
                "threat": {"url": url_observable},
            }
        ]
    }

    responses.add(responses.POST, api_url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    # Verify JSON was parsed and included in result
    assert result["details"] == mock_resp["matches"]
    assert result["details"][0]["platformType"] == "WINDOWS"


# ============================================================================
# Low Priority: Export Formatting & Property Tests
# ============================================================================


def test_create_export_row_with_threat_found():
    """Test export row with threat detected."""
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "threat_found": "Threat found",
        "details": [{"threatType": "MALWARE"}],
    }

    row = engine.create_export_row(analysis_result)

    assert row["gsb_threat"] == "Threat found"


def test_create_export_row_with_no_threat():
    """Test export row with no threat detected."""
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "threat_found": "No threat found",
        "details": None,
    }

    row = engine.create_export_row(analysis_result)

    assert row["gsb_threat"] == "No threat found"


def test_create_export_row_with_none_result():
    """Test export row with None analysis result."""
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["gsb_threat"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "google_safe_browsing"
    assert engine.supported_types == ["FQDN", "IPv4", "IPv6", "URL"]
    assert engine.is_pivot_engine is False
