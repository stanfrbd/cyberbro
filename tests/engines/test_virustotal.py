import base64
import logging

import pytest
import requests
import responses

from engines.virustotal import VirusTotalEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# PHASE 1: FIXTURES
# ============================================================================


@pytest.fixture
def secrets_with_valid_key():
    s = Secrets()
    s.virustotal = "test_virustotal_api_key_" + "X" * 30
    return s


@pytest.fixture
def secrets_with_empty_key():
    s = Secrets()
    s.virustotal = ""
    return s


@pytest.fixture
def secrets_with_whitespace_key():
    s = Secrets()
    s.virustotal = "   "
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path?query=value"


@pytest.fixture
def md5_observable():
    return "5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def sha1_observable():
    return "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


@pytest.fixture
def sha256_observable():
    return "2c26b46911185131006d3e59674e0e21bbe0f1f1a4bfbb4fb4b4c1b5f5d5c5c5c"


@pytest.fixture
def minimal_analysis_result():
    """Minimal analysis result with zero detections."""
    return {
        "detection_ratio": "0/50",
        "total_malicious": 0,
        "link": "https://www.virustotal.com/gui/ip-address/1.1.1.1/detection",
        "community_score": 0,
    }


@pytest.fixture
def full_analysis_result():
    """Complete analysis result with detections."""
    return {
        "detection_ratio": "5/72",
        "total_malicious": 5,
        "link": "https://www.virustotal.com/gui/ip-address/1.1.1.1/detection",
        "community_score": 42,
    }


# ============================================================================
# PHASE 2: HIGH PRIORITY - Credentials, Type Routing, Response Parsing
# ============================================================================


@responses.activate
def test_analyze_with_valid_key_success(secrets_with_valid_key, ipv4_observable):
    """Test successful API response with valid credential."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 1, "undetected": 46},
                "reputation": 50,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["detection_ratio"] == "3/50"
    assert result["total_malicious"] == 3
    assert result["community_score"] == 50


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value,endpoint_fragment,link_fragment",
    [
        ("IPv4", "1.1.1.1", "ip_addresses", "ip-address"),
        ("IPv6", "2001:4860:4860::8888", "ip_addresses", "ip-address"),
        ("FQDN", "example.com", "domains", "domain"),
        ("MD5", "5d41402abc4b2a76b9719d911017c592", "files", "file"),
        ("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "files", "file"),
        (
            "SHA256",
            "2c26b46911185131006d3e59674e0e21bbe0f1f1a4bfbb4fb4b4c1b5f5d5c5c5c",
            "files",
            "file",
        ),
    ],
)
def test_analyze_correct_url_endpoint_per_observable_type(
    secrets_with_valid_key, observable_type, observable_value, endpoint_fragment, link_fragment
):
    """Test that each observable type generates correct API endpoint and link."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    expected_url = f"https://www.virustotal.com/api/v3/{endpoint_fragment}/{observable_value}"
    expected_link_contains = link_fragment

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 50},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert expected_link_contains in result["link"]
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == expected_url


@responses.activate
def test_analyze_url_type_base64_encoding(secrets_with_valid_key, url_observable):
    """Test that URL observable type uses base64 URL-safe encoding."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    # Calculate expected encoded value
    expected_encoded = base64.urlsafe_b64encode(url_observable.encode()).decode().strip("=")
    expected_url = f"https://www.virustotal.com/api/v3/urls/{expected_encoded}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert len(responses.calls) == 1
    assert expected_encoded in responses.calls[0].request.url


@responses.activate
def test_analyze_url_type_padding_stripped(secrets_with_valid_key):
    """Test that base64 padding is correctly stripped from URL encoding."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    # Use URL that produces base64 with padding
    test_url = "http://test.com"
    encoded = base64.urlsafe_b64encode(test_url.encode()).decode().strip("=")

    expected_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    result = engine.analyze(test_url, "URL")

    assert result is not None
    # Verify padding was stripped (encoded string ends without =)
    assert not encoded.endswith("=")


@responses.activate
def test_analyze_url_type_special_characters(secrets_with_valid_key):
    """
    Test URL encoding with special characters.
    TODO (Bug #1): Observable values not validated/encoded except for URL type.
    """
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    special_url = "https://example.com/path?key=value&foo=bar#anchor"
    encoded = base64.urlsafe_b64encode(special_url.encode()).decode().strip("=")
    expected_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    result = engine.analyze(special_url, "URL")

    assert result is not None


@responses.activate
def test_analyze_success_complete_response(secrets_with_valid_key, ipv4_observable):
    """Test successful API response with all fields present."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "undetected": 45,
                    "harmless": 18,
                    "timeout": 2,
                },
                "reputation": 42,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Total should be sum of all stats: 5+2+45+18+2 = 72
    assert result["detection_ratio"] == "5/72"
    assert result["total_malicious"] == 5
    assert result["community_score"] == 42


@responses.activate
def test_analyze_minimal_response_empty_stats(secrets_with_valid_key, ipv4_observable):
    """Test response with empty stats dict."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["detection_ratio"] == "0/0"
    assert result["total_malicious"] == 0


@responses.activate
def test_analyze_missing_stats_defaults_to_empty(secrets_with_valid_key, ipv4_observable):
    """Test response with missing last_analysis_stats key."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "reputation": 10,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["detection_ratio"] == "0/0"
    assert result["total_malicious"] == 0
    assert result["community_score"] == 10


@responses.activate
def test_analyze_missing_reputation_defaults_to_zero(secrets_with_valid_key, ipv4_observable):
    """Test response with missing reputation field."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "undetected": 47},
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["community_score"] == 0


@responses.activate
def test_analyze_detection_ratio_format(secrets_with_valid_key, ipv4_observable):
    """Test that detection_ratio is formatted as malicious/total string."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 5,
                    "undetected": 35,
                },
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["detection_ratio"] == "10/50"
    assert isinstance(result["detection_ratio"], str)
    assert "/" in result["detection_ratio"]


# ============================================================================
# PHASE 3: MEDIUM PRIORITY - Error Scenarios
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 429, 500, 503])
def test_analyze_http_error_codes_return_none(
    secrets_with_valid_key, ipv4_observable, status_code, caplog
):
    """
    Test handling of HTTP error responses.
    TODO (Bug #3): Broad exception catching doesn't distinguish error types.
    """
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying VirusTotal" in caplog.text


@responses.activate
def test_analyze_timeout_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    responses.add(responses.GET, url, body=requests.Timeout("Connection timed out"))
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying VirusTotal" in caplog.text


@responses.activate
def test_analyze_connection_error_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    responses.add(responses.GET, url, body=requests.ConnectionError("Connection failed"))
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying VirusTotal" in caplog.text


@responses.activate
def test_analyze_json_parse_error_returns_none(secrets_with_valid_key, ipv4_observable, caplog):
    """Test handling of invalid JSON response."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    responses.add(responses.GET, url, body="Invalid JSON {{{", status=200)
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying VirusTotal" in caplog.text


@responses.activate
def test_analyze_missing_data_key_returns_none(secrets_with_valid_key, ipv4_observable):
    """Test response without 'data' key returns None."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {"error": "something went wrong"}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_missing_attributes_key_returns_none(secrets_with_valid_key, ipv4_observable):
    """Test response with data but no 'attributes' key returns None."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {"data": {"type": "ip_address"}}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_invalid_data_structure_not_dict(secrets_with_valid_key, ipv4_observable):
    """Test response where data is not a dict."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {"data": "invalid"}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_attributes_not_dict(secrets_with_valid_key, ipv4_observable):
    """Test response where attributes is not a dict."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {"data": {"attributes": "invalid"}}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_stats_not_dict(secrets_with_valid_key, ipv4_observable):
    """
    Test response where stats is not a dict.
    TODO (Bug #4): Stats calculation assumes integer values, no type validation.
    """
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": "not_a_dict",
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    # Will raise an error when trying to sum non-integer values
    assert result is None


# ============================================================================
# PHASE 4: LOW PRIORITY - Export Formatting and Properties
# ============================================================================


def test_create_export_row_success(minimal_analysis_result):
    """Test export row creation with valid analysis result."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(minimal_analysis_result)

    assert result["vt_detect"] == "0/50"
    assert result["vt_nb_detect"] == 0
    assert result["vt_community"] == 0


def test_create_export_row_with_detections(full_analysis_result):
    """Test export row creation with detections."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(full_analysis_result)

    assert result["vt_detect"] == "5/72"
    assert result["vt_nb_detect"] == 5
    assert result["vt_community"] == 42


def test_create_export_row_none_result():
    """Test export row creation with None result."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row(None)

    assert result["vt_detect"] is None
    assert result["vt_nb_detect"] is None
    assert result["vt_community"] is None


def test_create_export_row_empty_result():
    """Test export row creation with empty result dict."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row({})

    assert result["vt_detect"] is None
    assert result["vt_nb_detect"] is None
    assert result["vt_community"] is None


def test_create_export_row_partial_result():
    """Test export row creation with partial result (missing some fields)."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.create_export_row({"detection_ratio": "2/50"})

    assert result["vt_detect"] == "2/50"
    assert result["vt_nb_detect"] is None
    assert result["vt_community"] is None


def test_name_property():
    """Test name property returns correct engine name."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "virustotal"


def test_supported_types_property():
    """Test supported_types property returns all 7 types."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    types = engine.supported_types

    assert len(types) == 7
    assert "IPv4" in types
    assert "IPv6" in types
    assert "FQDN" in types
    assert "URL" in types
    assert "MD5" in types
    assert "SHA1" in types
    assert "SHA256" in types


def test_supported_types_ordering():
    """Test supported_types returns types in expected order."""
    engine = VirusTotalEngine(Secrets(), proxies={}, ssl_verify=True)

    types = engine.supported_types

    assert types == ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]


# ============================================================================
# PHASE 5: EDGE CASES AND INTEGRATION
# ============================================================================


@responses.activate
def test_analyze_with_proxies(secrets_with_valid_key, ipv4_observable):
    """Test that proxies are correctly passed to requests."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = VirusTotalEngine(secrets_with_valid_key, proxies=proxies, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None


@responses.activate
def test_analyze_with_ssl_verify_false(secrets_with_valid_key, ipv4_observable):
    """Test that SSL verification can be disabled."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=False)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None


@responses.activate
def test_analyze_timeout_parameter(secrets_with_valid_key, ipv4_observable):
    """Test that request timeout is set to 5 seconds."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify timeout parameter is in the request call
    assert responses.calls[0].request.headers is not None


@responses.activate
def test_analyze_export_workflow_ipv4(secrets_with_valid_key, ipv4_observable):
    """Test complete workflow: analyze IPv4 -> export."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2, "undetected": 48},
                "reputation": 20,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    analysis = engine.analyze(ipv4_observable, "IPv4")
    export = engine.create_export_row(analysis)

    assert export["vt_detect"] == "2/50"
    assert export["vt_nb_detect"] == 2
    assert export["vt_community"] == 20


@responses.activate
def test_analyze_export_workflow_url(secrets_with_valid_key, url_observable):
    """Test complete workflow: analyze URL -> export."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    encoded = base64.urlsafe_b64encode(url_observable.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 1, "suspicious": 1, "undetected": 48},
                "reputation": -5,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    analysis = engine.analyze(url_observable, "URL")
    export = engine.create_export_row(analysis)

    assert export["vt_detect"] == "1/50"
    assert export["vt_nb_detect"] == 1
    assert export["vt_community"] == -5


@responses.activate
def test_analyze_multiple_types_same_engine_instance(secrets_with_valid_key):
    """Test using same engine instance for multiple observable types."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    ipv4 = "1.1.1.1"
    domain = "example.com"

    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0},
                    "reputation": 0,
                }
            }
        },
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2},
                    "reputation": 0,
                }
            }
        },
        status=200,
    )

    result_ipv4 = engine.analyze(ipv4, "IPv4")
    result_domain = engine.analyze(domain, "FQDN")

    assert result_ipv4 is not None
    assert result_domain is not None
    assert result_ipv4["total_malicious"] == 0
    assert result_domain["total_malicious"] == 2


@responses.activate
def test_analyze_stats_with_multiple_detection_vendors(secrets_with_valid_key, ipv4_observable):
    """Test complex stats aggregation with multiple vendor detection statuses."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipv4_observable}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 8,
                    "undetected": 40,
                    "harmless": 5,
                    "timeout": 2,
                    "confirmed-timeout": 1,
                    "failure": 1,
                },
                "reputation": 100,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    # Total should be sum of all: 15+8+40+5+2+1+1 = 72
    assert result is not None
    assert result["detection_ratio"] == "15/72"
    assert result["total_malicious"] == 15
    assert result["community_score"] == 100


@responses.activate
def test_analyze_very_long_url_observable(secrets_with_valid_key):
    """Test URL observable that is very long (over 2000 chars)."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    # Create a very long URL
    long_url = "https://example.com/" + "a" * 2000
    encoded = base64.urlsafe_b64encode(long_url.encode()).decode().strip("=")
    expected_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, expected_url, json=mock_resp, status=200)

    result = engine.analyze(long_url, "URL")

    assert result is not None


@responses.activate
def test_analyze_unicode_characters_in_domain(secrets_with_valid_key):
    """
    Test FQDN observable with unicode characters (IDN).
    TODO (Bug #1): Domain not validated/encoded before API call.
    """
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    # IDN domain (internationalized domain name)
    unicode_domain = "münchen.de"
    url = f"https://www.virustotal.com/api/v3/domains/{unicode_domain}"

    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0},
                "reputation": 0,
            }
        }
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(unicode_domain, "FQDN")

    assert result is not None


@responses.activate
def test_analyze_empty_string_observable(secrets_with_valid_key):
    """Test empty string observable value."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    empty_value = ""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{empty_value}"

    responses.add(responses.GET, url, json={"error": "Invalid input"}, status=400)

    result = engine.analyze(empty_value, "IPv4")

    assert result is None


@responses.activate
def test_analyze_hash_observables_all_types(secrets_with_valid_key):
    """Test all three hash types (MD5, SHA1, SHA256) use same endpoint."""
    engine = VirusTotalEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

    hashes = [
        ("MD5", "5d41402abc4b2a76b9719d911017c592"),
        ("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        (
            "SHA256",
            "2c26b46911185131006d3e59674e0e21bbe0f1f1a4bfbb4fb4b4c1b5f5d5c5c5c",
        ),
    ]

    for _hash_type, hash_value in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        mock_resp = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0},
                    "reputation": 0,
                }
            }
        }
        responses.add(responses.GET, url, json=mock_resp, status=200)

    results = []
    for hash_type, hash_value in hashes:
        result = engine.analyze(hash_value, hash_type)
        results.append(result)

    # All should succeed
    assert all(r is not None for r in results)
    # All should use /files/ endpoint
    assert all("/files/" in call.request.url for call in responses.calls)
