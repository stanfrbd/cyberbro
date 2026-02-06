import logging

import pytest
import requests
import responses

from engines.shodan import ShodanEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# Phase 1: Fixtures & Setup
# ============================================================================


@pytest.fixture
def secrets_with_key():
    """Fixture with valid Shodan API key."""
    s = Secrets()
    s.shodan = "test_shodan_api_key_12345"
    return s


@pytest.fixture
def secrets_without_key():
    """Fixture with empty Shodan API key."""
    s = Secrets()
    s.shodan = ""
    return s


@pytest.fixture
def ipv4_observable():
    """IPv4 address for testing."""
    return "192.168.1.1"


@pytest.fixture
def ipv6_observable():
    """IPv6 address for testing."""
    return "2001:db8::1"


# ============================================================================
# Phase 2: High Priority Tests - Credentials & Core API
# ============================================================================


@responses.activate
def test_analyze_success_ipv4_complete(secrets_with_key, ipv4_observable):
    """Test successful API response for IPv4 with complete data."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {
        "ports": [80, 443, 8080],
        "tags": ["http", "https", "service"],
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == [80, 443, 8080]
    assert result["tags"] == ["http", "https", "service"]
    assert result["link"] == f"https://www.shodan.io/host/{ipv4_observable}"


@responses.activate
def test_analyze_success_ipv6_complete(secrets_with_key, ipv6_observable):
    """Test successful API response for IPv6 with complete data."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv6_observable}"

    mock_resp = {
        "ports": [22, 443],
        "tags": ["ssh", "https"],
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, ObservableType.IPV6)

    assert result is not None
    assert result["ports"] == [22, 443]
    assert result["tags"] == ["ssh", "https"]
    assert result["link"] == f"https://www.shodan.io/host/{ipv6_observable}"


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        (ObservableType.IPV4, "192.168.1.1"),
        (ObservableType.IPV6, "2001:db8::1"),
    ],
)
def test_analyze_both_observable_types(secrets_with_key, observable_type, observable_value):
    """Test analysis works for both IPv4 and IPv6 observable types."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{observable_value}"

    mock_resp = {"ports": [80], "tags": ["http"]}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["ports"] == [80]


@responses.activate
def test_analyze_empty_api_key_still_makes_call(secrets_without_key, ipv4_observable, caplog):
    """Test that empty API key still makes API call (current behavior - BUG #1)."""
    engine = ShodanEngine(secrets_without_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    # Empty key will likely result in 401/403
    responses.add(responses.GET, url, json={"error": "Unauthorized"}, status=401)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Currently returns None for any error
    assert result is None
    # Verify the API call was attempted (inefficient but current behavior)
    assert len(responses.calls) == 1
    # TODO: BUG #1 - Should validate credentials client-side before making call


@responses.activate
def test_analyze_404_returns_none(secrets_with_key, ipv4_observable):
    """Test that 404 status returns None (not treated as error - special behavior)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={}, status=404)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


@responses.activate
@pytest.mark.parametrize("status_code", [400, 401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (except 404)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying Shodan" in caplog.text


@responses.activate
def test_analyze_response_missing_ports_field(secrets_with_key, ipv4_observable):
    """Test handling when ports field is missing (should default to empty list)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"tags": ["http", "https"]}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == []
    assert result["tags"] == ["http", "https"]


@responses.activate
def test_analyze_response_missing_tags_field(secrets_with_key, ipv4_observable):
    """Test handling when tags field is missing (should default to empty list)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"ports": [80, 443]}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == [80, 443]
    assert result["tags"] == []


@responses.activate
def test_analyze_correct_api_headers_and_params(secrets_with_key, ipv4_observable):
    """Verify correct HTTP headers and query parameters are sent."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={"ports": [], "tags": []}, status=200)

    engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.headers["Accept"] == "application/json"
    assert f"key={secrets_with_key.shodan}" in request.url


# ============================================================================
# Phase 3: Medium Priority Tests - Critical Paths & Error Scenarios
# ============================================================================


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying Shodan" in caplog.text


@responses.activate
def test_analyze_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying Shodan" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying Shodan" in caplog.text


@responses.activate
@pytest.mark.parametrize(
    "ports,tags",
    [
        ([80, 443], ["http", "https"]),
        ([80], []),
        ([], ["http"]),
        ([], []),
    ],
)
def test_analyze_response_field_variations(secrets_with_key, ipv4_observable, ports, tags):
    """Test various combinations of ports and tags in response."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"ports": ports, "tags": tags}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == ports
    assert result["tags"] == tags


@responses.activate
def test_analyze_link_generation(secrets_with_key, ipv4_observable):
    """Test that link is correctly generated with observable value."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"ports": [80], "tags": []}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["link"] == f"https://www.shodan.io/host/{ipv4_observable}"


@responses.activate
def test_analyze_empty_response(secrets_with_key, ipv4_observable):
    """Test handling of empty response (no ports or tags)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == []
    assert result["tags"] == []
    assert result["link"] == f"https://www.shodan.io/host/{ipv4_observable}"


@responses.activate
def test_analyze_with_proxies(secrets_with_key, ipv4_observable):
    """Test analyze respects proxy configuration."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = ShodanEngine(secrets_with_key, proxies=proxies, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={"ports": [], "tags": []}, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None


@responses.activate
def test_analyze_with_ssl_verify_false(secrets_with_key, ipv4_observable):
    """Test analyze respects ssl_verify=False configuration."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={"ports": [], "tags": []}, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None


# ============================================================================
# Phase 4: Low Priority Tests - Export & Properties
# ============================================================================


def test_create_export_row_with_complete_data():
    """Test export row with complete ports data."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ports": [80, 443, 8080],
        "tags": ["http", "https", "service"],
        "link": "https://www.shodan.io/host/192.168.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["shodan_ports"] == [80, 443, 8080]


def test_create_export_row_with_empty_ports():
    """Test export row with empty ports list."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "ports": [],
        "tags": ["http"],
        "link": "https://www.shodan.io/host/192.168.1.1",
    }

    row = engine.create_export_row(analysis_result)

    assert row["shodan_ports"] == []


def test_create_export_row_none_result():
    """Test export row with None result."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["shodan_ports"] is None


def test_create_export_row_missing_ports_field():
    """Test export row when ports field is missing."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {"tags": ["http"], "link": "https://www.shodan.io/host/192.168.1.1"}

    row = engine.create_export_row(analysis_result)

    assert row["shodan_ports"] is None


def test_create_export_row_single_port():
    """Test export row with single port."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {"ports": [80]}

    row = engine.create_export_row(analysis_result)

    assert row["shodan_ports"] == [80]


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "shodan"
    assert engine.supported_types == ObservableType.IPV4 | ObservableType.IPV6
    assert engine.execute_after_reverse_dns is True
    assert engine.is_pivot_engine is False


def test_engine_supported_types_count():
    """Verify Shodan only supports 2 observable types (IP-only)."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    assert len(engine.supported_types) == 2
    assert ObservableType.IPV4 in engine.supported_types
    assert ObservableType.IPV6 in engine.supported_types


def test_engine_execute_after_reverse_dns_true():
    """Verify Shodan is a pivot engine (executes after reverse DNS)."""
    engine = ShodanEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.execute_after_reverse_dns is True


# ============================================================================
# Phase 5: Edge Cases & Integration Tests
# ============================================================================


@responses.activate
def test_analyze_boundary_port_values(secrets_with_key, ipv4_observable):
    """Test response with boundary port values (0 and 65535)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"ports": [0, 1, 65534, 65535], "tags": []}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == [0, 1, 65534, 65535]


@responses.activate
def test_analyze_many_ports(secrets_with_key, ipv4_observable):
    """Test response with large number of ports."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    ports = list(range(80, 8100))  # 8020 ports
    mock_resp = {"ports": ports, "tags": []}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert len(result["ports"]) == 8020
    assert result["ports"] == ports


@responses.activate
def test_analyze_many_tags(secrets_with_key, ipv4_observable):
    """Test response with large number of tags."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    tags = [f"tag_{i}" for i in range(100)]
    mock_resp = {"ports": [80], "tags": tags}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert len(result["tags"]) == 100


@responses.activate
def test_analyze_ipv4_and_ipv6_consistency(secrets_with_key, ipv4_observable, ipv6_observable):
    """Test that IPv4 and IPv6 are handled consistently."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url_ipv4 = f"https://api.shodan.io/shodan/host/{ipv4_observable}"
    url_ipv6 = f"https://api.shodan.io/shodan/host/{ipv6_observable}"

    mock_resp = {"ports": [80, 443], "tags": ["http", "https"]}
    responses.add(responses.GET, url_ipv4, json=mock_resp, status=200)
    responses.add(responses.GET, url_ipv6, json=mock_resp, status=200)

    result_ipv4 = engine.analyze(ipv4_observable, ObservableType.IPV4)
    result_ipv6 = engine.analyze(ipv6_observable, ObservableType.IPV6)

    # Both should return identical structure
    assert result_ipv4["ports"] == result_ipv6["ports"]
    assert result_ipv4["tags"] == result_ipv6["tags"]
    # Only observable values in links should differ
    assert ipv4_observable in result_ipv4["link"]
    assert ipv6_observable in result_ipv6["link"]


@responses.activate
def test_analyze_create_export_row_integration(secrets_with_key, ipv4_observable):
    """Test integration between analyze and create_export_row."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {"ports": [80, 443, 8080], "tags": ["http", "https", "service"]}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None

    row = engine.create_export_row(result)

    assert row["shodan_ports"] == [80, 443, 8080]


@responses.activate
def test_analyze_404_vs_error_distinction(secrets_with_key, ipv4_observable, caplog):
    """Test that 404 is handled differently from other errors (no error log)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    responses.add(responses.GET, url, json={}, status=404)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # 404 should return None without logging error
    assert result is None
    assert "Error querying Shodan" not in caplog.text


@responses.activate
def test_analyze_response_with_extra_fields(secrets_with_key, ipv4_observable):
    """Test response with extra unexpected fields (should ignore them)."""
    engine = ShodanEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://api.shodan.io/shodan/host/{ipv4_observable}"

    mock_resp = {
        "ports": [80, 443],
        "tags": ["http", "https"],
        "extra_field_1": "ignored",
        "extra_field_2": {"nested": "data"},
        "extra_field_3": [1, 2, 3],
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["ports"] == [80, 443]
    assert result["tags"] == ["http", "https"]
    assert "extra_field_1" not in result
    # Only expected fields should be returned
    assert len(result) == 3  # ports, tags, link
