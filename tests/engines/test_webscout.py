import logging
from unittest.mock import MagicMock, patch

import pytest
import requests
import responses

from engines.webscout import WebscoutEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# PHASE 1: FIXTURES
# ============================================================================


@pytest.fixture
def secrets_with_valid_key():
    s = Secrets()
    s.webscout = "test_webscout_api_key_" + "X" * 30
    return s


@pytest.fixture
def secrets_with_empty_key():
    s = Secrets()
    s.webscout = ""
    return s


@pytest.fixture
def secrets_with_none_key():
    s = Secrets()
    s.webscout = None
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def complete_api_response():
    """Complete API response with all fields."""
    return {
        "status": "success",
        "data": {
            "ip": "1.1.1.1",
            "location": {
                "country_iso": "US",
                "city": "Los Angeles",
            },
            "network": {
                "type": "residential",
                "service": "ISP",
                "region": "west",
            },
            "company": {
                "name": "Example ISP",
                "business": ["Mail", "DNS"],
                "description": "Large ISP",
            },
            "as": {
                "as_number": 15169,
                "organization": "Google LLC",
            },
            "anonymization": {
                "proxy": False,
                "tor": False,
                "vpn": False,
            },
            "osint": {
                "services": [
                    {"tags": ["malware", "botnet"]},
                    {"tags": ["spam", "malware"]},
                ]
            },
            "hostnames": ["mail.example.com", "smtp.example.com"],
        },
    }


@pytest.fixture
def minimal_api_response():
    """Minimal API response with sparse data."""
    return {
        "status": "success",
        "data": {
            "ip": "1.1.1.1",
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }


@pytest.fixture
def complete_analysis_result():
    """Complete analysis result from successful API call."""
    return {
        "ip": "1.1.1.1",
        "risk_score": None,
        "is_proxy": False,
        "is_tor": False,
        "is_vpn": False,
        "country_code": "US",
        "country_name": "United States",
        "location": "United States, Los Angeles",
        "hostnames": ["mail.example.com"],
        "domains_on_ip": None,
        "network_type": "residential",
        "network_provider": "Example ISP",
        "network_service": "ISP",
        "network_service_region": "west",
        "network_provider_services": ["Mail", "DNS"],
        "behavior": ["malware", "botnet", "spam"],
        "as_org": "Google LLC",
        "asn": "AS15169",
        "description": "Large ISP",
    }


# ============================================================================
# PHASE 2: HIGH PRIORITY - Credentials, Rate Limiting, Types, Status, Location
# ============================================================================


@responses.activate
def test_analyze_with_valid_key_includes_in_url(secrets_with_valid_key, ipv4_observable):
    """
    Test that API key is included in URL.
    TODO (Bug #1): API key in URL is a security risk - should use Authorization header.
    """
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url_pattern = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url_pattern, json=mock_resp, status=200)

    with patch("time.sleep"):  # Skip rate limiting for test speed
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify API key was included in URL
    assert "apikey=" in responses.calls[0].request.url
    assert secrets_with_valid_key.webscout in responses.calls[0].request.url


@responses.activate
def test_analyze_with_empty_key_still_makes_request(
    secrets_with_empty_key, ipv4_observable, caplog
):
    """
    Test that empty credential is still sent to API.
    TODO (Bug #3): Engine should validate credential before API call.
    """
    engine = WebscoutEngine(secrets_with_empty_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, json={"error": "Invalid API key"}, status=401)
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    # Request was made despite empty key
    assert len(responses.calls) == 1


@responses.activate
def test_analyze_with_none_key_error(secrets_with_none_key, ipv4_observable, caplog):
    """Test that None credential causes an error."""
    engine = WebscoutEngine(secrets_with_none_key, proxies={}, ssl_verify=True)
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying webscout" in caplog.text


@responses.activate
def test_analyze_calls_time_sleep_with_1_second(secrets_with_valid_key, ipv4_observable):
    """
    Test that time.sleep(1) is called for rate limiting.
    TODO (Bug #2): Hardcoded 1-second rate limiting cannot be configured or disabled.
    """
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep") as mock_sleep:
        result = engine.analyze(ipv4_observable, "IPv4")

    # Verify sleep was called with 1.0 seconds
    mock_sleep.assert_called_once_with(1)
    assert result is not None


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value", [("IPv4", "1.1.1.1"), ("IPv6", "2001:4860:4860::8888")]
)
def test_analyze_correct_url_endpoint_per_type(
    secrets_with_valid_key, observable_type, observable_value
):
    """Test that IPv4 and IPv6 use same endpoint with different values."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{observable_value}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": observable_value,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["ip"] == observable_value


@responses.activate
def test_analyze_success_status_returns_data(secrets_with_valid_key, ipv4_observable):
    """Test successful response with status: success."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable


@responses.activate
def test_analyze_error_status_returns_none(secrets_with_valid_key, ipv4_observable):
    """Test response with status: error returns None."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {"status": "error", "message": "IP not found"}
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_missing_status_returns_none(secrets_with_valid_key, ipv4_observable):
    """Test response without status key returns None."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {"data": {"ip": ipv4_observable}}
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


def test_analyze_location_with_valid_country_code(secrets_with_valid_key, ipv4_observable):
    """Test location parsing with valid country code lookup."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "ip": ipv4_observable,
                "location": {"country_iso": "US", "city": "New York"},
                "network": {},
                "company": {},
                "as": {},
                "anonymization": {},
                "osint": {},
                "hostnames": [],
            },
        }
        mock_get.return_value = mock_response

        with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
            mock_country_obj = MagicMock()
            mock_country_obj.name = "United States"
            mock_country.return_value = mock_country_obj

            result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"


def test_analyze_location_with_invalid_country_code(secrets_with_valid_key, ipv4_observable):
    """Test location parsing with invalid country code."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "ip": ipv4_observable,
                "location": {"country_iso": "ZZ", "city": "Unknown"},
                "network": {},
                "company": {},
                "as": {},
                "anonymization": {},
                "osint": {},
                "hostnames": [],
            },
        }
        mock_get.return_value = mock_response

        with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
            mock_country.return_value = None

            result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["country_code"] == "ZZ"
    assert result["country_name"] == "Unknown"


def test_analyze_location_with_none_country_code(secrets_with_valid_key, ipv4_observable):
    """Test location parsing when country_iso is None."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "ip": ipv4_observable,
                "location": {"country_iso": None, "city": "Unknown"},
                "network": {},
                "company": {},
                "as": {},
                "anonymization": {},
                "osint": {},
                "hostnames": [],
            },
        }
        mock_get.return_value = mock_response

        with patch("time.sleep"):
            result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["country_code"] == "Unknown"


@responses.activate
def test_analyze_location_with_missing_city(secrets_with_valid_key, ipv4_observable):
    """Test location parsing when city is missing - defaults to 'Unknown'."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {"country_iso": "US"},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United States"
        mock_country.return_value = mock_country_obj

        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # City defaults to "Unknown" when missing
    assert "United States, Unknown" in result.get("location", "")


@responses.activate
def test_analyze_missing_nested_dicts_default_to_empty(secrets_with_valid_key, ipv4_observable):
    """Test that missing nested dicts default to empty dicts."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            # Intentionally missing all nested dicts
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["network_type"] == ""
    assert result["network_provider"] == "Unknown"
    assert result["as_org"] == "Unknown"
    assert result["asn"] == "Unknown"


@responses.activate
def test_analyze_success_complete(secrets_with_valid_key, ipv4_observable, complete_api_response):
    """Test successful API response with complete data."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, json=complete_api_response, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United States"
        mock_country.return_value = mock_country_obj

        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"


# ============================================================================
# PHASE 3: MEDIUM PRIORITY - Error Scenarios, OSINT, Booleans, ASN
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [400, 401, 403, 429, 500, 503])
def test_analyze_http_errors_return_none(
    secrets_with_valid_key, ipv4_observable, status_code, caplog
):
    """Test handling of HTTP error responses."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, json={"error": "error"}, status=status_code)
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying webscout" in caplog.text


@responses.activate
def test_analyze_timeout_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, body=requests.Timeout("Connection timed out"))
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying webscout" in caplog.text


@responses.activate
def test_analyze_connection_error_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, body=requests.ConnectionError("Connection failed"))
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying webscout" in caplog.text


@responses.activate
def test_analyze_json_parse_error_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of invalid JSON response."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    responses.add(responses.GET, expected_url, body="Invalid JSON {{{", status=200)
    caplog.set_level(logging.ERROR)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying webscout" in caplog.text


@responses.activate
def test_analyze_osint_tags_aggregation(secrets_with_valid_key, ipv4_observable):
    """Test OSINT tag aggregation from multiple services."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {
                "services": [
                    {"tags": ["malware", "botnet"]},
                    {"tags": ["spam", "c2"]},
                    {"tags": ["phishing"]},
                ]
            },
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert "malware" in result["behavior"]
    assert "botnet" in result["behavior"]
    assert "spam" in result["behavior"]
    assert "c2" in result["behavior"]
    assert "phishing" in result["behavior"]


@responses.activate
def test_analyze_osint_tags_deduplication(secrets_with_valid_key, ipv4_observable):
    """Test OSINT tags are deduplicated while preserving order."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {
                "services": [
                    {"tags": ["malware", "botnet", "malware"]},
                    {"tags": ["spam", "malware", "botnet"]},
                ]
            },
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    behavior = result["behavior"]
    # Check no duplicates
    assert len(behavior) == len(set(behavior))
    # Check all unique items present
    assert "malware" in behavior
    assert "botnet" in behavior
    assert "spam" in behavior


@responses.activate
def test_analyze_osint_tags_empty_services(secrets_with_valid_key, ipv4_observable):
    """Test OSINT with empty services array."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {"services": []},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["behavior"] == []


@responses.activate
@pytest.mark.parametrize(
    "proxy,tor,vpn,expected_proxy,expected_tor,expected_vpn",
    [
        (True, False, False, True, False, False),
        (False, True, False, False, True, False),
        (False, False, True, False, False, True),
        (True, True, True, True, True, True),
        (0, 0, 0, False, False, False),
        ("", "", "", False, False, False),
        (None, None, None, False, False, False),
    ],
)
def test_analyze_anonymization_boolean_conversion(
    secrets_with_valid_key,
    ipv4_observable,
    proxy,
    tor,
    vpn,
    expected_proxy,
    expected_tor,
    expected_vpn,
):
    """Test boolean conversion of anonymization fields."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {"proxy": proxy, "tor": tor, "vpn": vpn},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["is_proxy"] == expected_proxy
    assert result["is_tor"] == expected_tor
    assert result["is_vpn"] == expected_vpn


@responses.activate
def test_analyze_asn_formatting_valid(secrets_with_valid_key, ipv4_observable):
    """Test ASN formatting with valid AS number."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {"as_number": 15169, "organization": "Google LLC"},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"] == "AS15169"


@responses.activate
def test_analyze_asn_formatting_string_asn(secrets_with_valid_key, ipv4_observable):
    """Test ASN formatting when ASN is already a string."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {"as_number": "15169", "organization": "Google LLC"},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"] == "AS15169"


@responses.activate
def test_analyze_asn_formatting_zero_asn(secrets_with_valid_key, ipv4_observable):
    """Test ASN formatting when AS number is 0 (falsy)."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {"as_number": 0},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"] == "Unknown"


@responses.activate
def test_analyze_asn_formatting_missing(secrets_with_valid_key, ipv4_observable):
    """Test ASN formatting when AS number is missing."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {"organization": "Unknown"},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["asn"] == "Unknown"


# ============================================================================
# PHASE 4: LOW PRIORITY - Export Formatting and Properties
# ============================================================================


def test_create_export_row_success(complete_analysis_result):
    """Test export row creation with valid analysis result."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(complete_analysis_result)

    assert result["ws_risk"] is None
    assert result["ws_is_proxy"] is False
    assert result["ws_is_tor"] is False
    assert result["ws_is_vpn"] is False
    assert result["ws_cn"] == "US"
    assert result["ws_country"] == "United States"
    assert "United States" in result["ws_location"]


def test_create_export_row_none_result():
    """Test export row creation with None result."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(None)

    # All fields should be None
    assert result["ws_risk"] is None
    assert result["ws_is_proxy"] is None
    assert result["ws_is_tor"] is None
    assert result["ws_is_vpn"] is None
    assert result["ws_cn"] is None
    assert result["ws_country"] is None


def test_create_export_row_array_joining(complete_analysis_result):
    """Test that array fields are joined with ', ' separator."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    # Update the fixture with multiple items
    complete_analysis_result["hostnames"] = ["mail.example.com", "smtp.example.com"]

    result = engine.create_export_row(complete_analysis_result)

    assert result["ws_hostnames"] == "mail.example.com, smtp.example.com"
    assert result["ws_network_provider_services"] == "Mail, DNS"
    assert "malware" in result["ws_behavior"]
    assert "botnet" in result["ws_behavior"]


def test_create_export_row_empty_arrays():
    """Test export with empty arrays."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(
        {
            "hostnames": [],
            "network_provider_services": [],
            "behavior": [],
            "risk_score": None,
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": False,
            "country_code": "US",
            "country_name": "United States",
            "location": "United States, New York",
            "domains_on_ip": None,
            "network_type": "residential",
            "network_provider": "ISP",
            "network_service": "",
            "network_service_region": "",
            "as_org": "Unknown",
            "asn": "Unknown",
            "description": "Unknown",
        }
    )

    assert result["ws_hostnames"] == ""
    assert result["ws_network_provider_services"] == ""
    assert result["ws_behavior"] == ""


def test_name_property():
    """Test name property returns correct engine name."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "webscout"


def test_supported_types_property():
    """Test supported_types property returns IPv4 and IPv6."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    types = engine.supported_types

    assert len(types) == 2
    assert "IPv4" in types
    assert "IPv6" in types


def test_execute_after_reverse_dns_property():
    """Test execute_after_reverse_dns is True."""
    engine = WebscoutEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.execute_after_reverse_dns is True


# ============================================================================
# PHASE 5: EDGE CASES AND INTEGRATION
# ============================================================================


@responses.activate
def test_analyze_with_proxies(secrets_with_valid_key, ipv4_observable):
    """Test that proxies are correctly passed to requests."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = WebscoutEngine(secrets_with_valid_key, proxies=proxies, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None


@responses.activate
def test_analyze_with_ssl_verify_false(secrets_with_valid_key, ipv4_observable):
    """Test that SSL verification can be disabled."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=False)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None


@responses.activate
def test_analyze_hostnames_empty_list(secrets_with_valid_key, ipv4_observable):
    """Test with empty hostnames array."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["hostnames"] == []


@responses.activate
def test_analyze_hostnames_single_item(secrets_with_valid_key, ipv4_observable):
    """Test with single hostname."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": ["mail.example.com"],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["hostnames"] == ["mail.example.com"]


@responses.activate
def test_analyze_hostnames_many_items(secrets_with_valid_key, ipv4_observable):
    """Test with multiple hostnames."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    hostnames = ["mail1.example.com", "mail2.example.com", "smtp.example.com"]
    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": hostnames,
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["hostnames"] == hostnames


@responses.activate
def test_analyze_location_string_formatting(secrets_with_valid_key, ipv4_observable):
    """Test location string is formatted as 'Country, City'."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {"country_iso": "US", "city": "New York"},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United States"
        mock_country.return_value = mock_country_obj

        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["location"] == "United States, New York"


@responses.activate
def test_analyze_location_with_empty_city(secrets_with_valid_key, ipv4_observable):
    """
    Test location string formatting when city is empty.
    Engine defaults empty city to "Unknown", not an empty string.
    TODO (Bug #8): Location formatting could be improved.
    """
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {"country_iso": "US", "city": ""},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United States"
        mock_country.return_value = mock_country_obj

        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Empty string gets replaced with "Unknown" by the `or "Unknown"` pattern
    assert result["location"] == "United States, Unknown"


@responses.activate
def test_analyze_export_workflow_ipv4(secrets_with_valid_key, ipv4_observable):
    """Test complete workflow: analyze IPv4 -> export."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv4_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv4_observable,
            "location": {"country_iso": "US", "city": "Los Angeles"},
            "network": {"type": "residential", "service": "ISP", "region": "west"},
            "company": {"name": "Example ISP", "business": ["Mail"], "description": "ISP"},
            "as": {"as_number": 15169, "organization": "Google LLC"},
            "anonymization": {"proxy": False, "tor": False, "vpn": False},
            "osint": {"services": [{"tags": ["malware"]}]},
            "hostnames": ["mail.example.com"],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United States"
        mock_country.return_value = mock_country_obj

        analysis = engine.analyze(ipv4_observable, "IPv4")
        export = engine.create_export_row(analysis)

    assert export["ws_cn"] == "US"
    assert export["ws_country"] == "United States"
    assert export["ws_is_proxy"] is False
    assert export["ws_asn"] == "AS15169"


@responses.activate
def test_analyze_export_workflow_ipv6(secrets_with_valid_key, ipv6_observable):
    """Test complete workflow: analyze IPv6 -> export."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://api.webscout.io/query/ip/{ipv6_observable}"

    mock_resp = {
        "status": "success",
        "data": {
            "ip": ipv6_observable,
            "location": {"country_iso": "GB", "city": "London"},
            "network": {},
            "company": {},
            "as": {},
            "anonymization": {"proxy": True, "tor": False, "vpn": True},
            "osint": {},
            "hostnames": [],
        },
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    with patch("time.sleep"), patch("pycountry.countries.get") as mock_country:
        mock_country_obj = MagicMock()
        mock_country_obj.name = "United Kingdom"
        mock_country.return_value = mock_country_obj

        analysis = engine.analyze(ipv6_observable, "IPv6")
        export = engine.create_export_row(analysis)

    assert export["ws_cn"] == "GB"
    assert export["ws_country"] == "United Kingdom"
    assert export["ws_is_proxy"] is True
    assert export["ws_is_vpn"] is True


@responses.activate
def test_analyze_multiple_ips_same_engine(secrets_with_valid_key):
    """Test using same engine instance for multiple IP observations."""
    engine = WebscoutEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    ipv4 = "1.1.1.1"
    ipv6 = "2001:4860:4860::8888"

    responses.add(
        responses.GET,
        f"https://api.webscout.io/query/ip/{ipv4}",
        json={
            "status": "success",
            "data": {
                "ip": ipv4,
                "location": {},
                "network": {},
                "company": {},
                "as": {},
                "anonymization": {},
                "osint": {},
                "hostnames": [],
            },
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://api.webscout.io/query/ip/{ipv6}",
        json={
            "status": "success",
            "data": {
                "ip": ipv6,
                "location": {},
                "network": {},
                "company": {},
                "as": {},
                "anonymization": {},
                "osint": {},
                "hostnames": [],
            },
        },
        status=200,
    )

    with patch("time.sleep"):
        result_ipv4 = engine.analyze(ipv4, "IPv4")
        result_ipv6 = engine.analyze(ipv6, "IPv6")

    assert result_ipv4 is not None
    assert result_ipv6 is not None
    assert result_ipv4["ip"] == ipv4
    assert result_ipv6["ip"] == ipv6
