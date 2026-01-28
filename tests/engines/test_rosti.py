import logging

import pytest
import requests
import responses

from engines.rosti import RostiEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# Phase 1: Fixtures & Setup
# ============================================================================


@pytest.fixture
def secrets_with_key():
    """Fixture with valid Rosti API key."""
    s = Secrets()
    s.rosti_api_key = "test_rosti_api_key_12345"
    return s


@pytest.fixture
def secrets_without_key():
    """Fixture with empty Rosti API key."""
    s = Secrets()
    s.rosti_api_key = ""
    return s


@pytest.fixture
def ipv4_observable():
    """IPv4 address for testing."""
    return "192.168.1.1"


@pytest.fixture
def ipv6_observable():
    """IPv6 address for testing."""
    return "2001:db8::1"


@pytest.fixture
def fqdn_observable():
    """FQDN for testing."""
    return "example.com"


@pytest.fixture
def url_observable():
    """URL for testing."""
    return "https://example.com/path"


@pytest.fixture
def email_observable():
    """Email address for testing."""
    return "test@example.com"


@pytest.fixture
def md5_observable():
    """MD5 hash for testing."""
    return "5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def sha1_observable():
    """SHA1 hash for testing."""
    return "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


@pytest.fixture
def sha256_observable():
    """SHA256 hash for testing."""
    return "2c26b46911185131006745196ee8cbf7d0ec70a2"


# ============================================================================
# Phase 2: High Priority Tests - Credentials & Core API
# ============================================================================


def test_analyze_missing_api_key(secrets_without_key, ipv4_observable):
    """Test that analyze returns None when API key is not configured."""
    engine = RostiEngine(secrets_without_key, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None


@responses.activate
def test_analyze_success_complete(secrets_with_key, ipv4_observable):
    """Test successful API response with complete data structure."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": "192.168.1.5",
                "type": "IPv4",
                "category": "malware",
                "date": "2025-01-15",
                "comment": "Suspicious activity detected",
                "ids": ["id1", "id2"],
                "report": "report123",
                "timestamp": "2025-01-15T10:00:00Z",
                "risk": "high",
                "id": "ioc_001",
            }
        ],
        "meta": {"total": 1, "has_more": False},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 1
    assert result["total"] == 1
    assert result["has_more"] is False
    assert len(result["results"]) == 1
    assert result["results"][0]["value"] == "192.168.1.5"
    assert result["results"][0]["type"] == "IPv4"
    assert result["results"][0]["link"] == "https://rosti.bin.re/reports/report123"


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 404, 500)."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Rösti" in caplog.text


@responses.activate
def test_analyze_response_missing_data_key(secrets_with_key, ipv4_observable):
    """Test handling of valid 200 response missing 'data' key."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {"error": "No data", "meta": {}}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 0
    assert result["results"] == []


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Rösti" in caplog.text


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        ("IPv4", "192.168.1.1"),
        ("IPv6", "2001:db8::1"),
        ("FQDN", "example.com"),
        ("URL", "https://example.com/path"),
        ("Email", "test@example.com"),
        ("MD5", "5d41402abc4b2a76b9719d911017c592"),
        ("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
        ("SHA256", "2c26b46911185131006745196ee8cbf7d0ec70a2"),
    ],
)
def test_analyze_all_supported_types(secrets_with_key, observable_type, observable_value):
    """Test successful analysis for all supported observable types."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": observable_value,
                "type": observable_type,
                "category": "malware",
                "date": "2025-01-15",
                "report": "report123",
            }
        ],
        "meta": {"total": 1, "has_more": False},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["count"] == 1
    assert result["results"][0]["type"] == observable_type


@responses.activate
def test_analyze_correct_api_headers_and_params(secrets_with_key, ipv4_observable):
    """Verify correct HTTP headers and query parameters are sent."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    responses.add(responses.GET, url, json={"data": [], "meta": {}}, status=200)

    engine.analyze(ipv4_observable, "IPv4")

    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert request.headers["X-API-Key"] == "test_rosti_api_key_12345"
    assert f"q={ipv4_observable}" in request.url
    assert "pattern=true" in request.url


# ============================================================================
# Phase 3: Medium Priority Tests - Critical Paths & Error Scenarios
# ============================================================================


@responses.activate
def test_analyze_request_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Rösti" in caplog.text


@responses.activate
def test_analyze_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Rösti" in caplog.text


@responses.activate
def test_analyze_empty_results(secrets_with_key, ipv4_observable):
    """Test response with empty results list."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {"data": [], "meta": {"total": 0, "has_more": False}}
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 0
    assert result["results"] == []
    assert result["total"] == 0
    assert result["has_more"] is False


@responses.activate
def test_analyze_non_dict_items_in_results(secrets_with_key, ipv4_observable):
    """Test graceful handling of non-dict items in results (should be skipped)."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            "invalid_string",
            None,
            {"value": "192.168.1.5", "type": "IPv4", "category": "malware"},
            12345,
        ],
        "meta": {"total": 4, "has_more": False},
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 1  # Only the valid dict is counted
    assert len(result["results"]) == 1
    assert result["results"][0]["value"] == "192.168.1.5"


@responses.activate
def test_analyze_pagination_metadata(secrets_with_key, ipv4_observable):
    """Test pagination metadata (has_more, total) is properly handled."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [{"value": "192.168.1.5", "type": "IPv4"}],
        "meta": {"total": 50, "has_more": True},
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 50
    assert result["has_more"] is True


@responses.activate
def test_analyze_report_link_generation(secrets_with_key, ipv4_observable):
    """Test report link is correctly generated from report ID."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": "192.168.1.5",
                "type": "IPv4",
                "report": "abc123def456",
            }
        ],
        "meta": {},
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["results"][0]["link"] == "https://rosti.bin.re/reports/abc123def456"


@responses.activate
def test_analyze_report_link_none_when_no_report_id(secrets_with_key, ipv4_observable):
    """Test link is None when report ID is not present."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": "192.168.1.5",
                "type": "IPv4",
            }
        ],
        "meta": {},
    }
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["results"][0]["link"] is None


# ============================================================================
# Phase 4: Low Priority Tests - Export & Properties
# ============================================================================


def test_create_export_row_with_complete_data():
    """Test export row with complete analysis result."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "count": 3,
        "results": [
            {"value": "192.168.1.5", "type": "IPv4"},
            {"value": "192.168.1.6", "type": "IPv4"},
            {"value": "192.168.1.7", "type": "IPv4"},
        ],
        "total": 3,
        "has_more": False,
    }

    row = engine.create_export_row(analysis_result)

    assert row["rosti_count"] == 3
    assert row["rosti_values"] == "192.168.1.5, 192.168.1.6, 192.168.1.7"
    assert row["rosti_types"] == "IPv4, IPv4, IPv4"


def test_create_export_row_none_result():
    """Test export row with None result."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["rosti_count"] == 0
    assert row["rosti_values"] is None
    assert row["rosti_types"] is None


def test_create_export_row_empty_results():
    """Test export row with empty results list."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "count": 0,
        "results": [],
        "total": 0,
        "has_more": False,
    }

    row = engine.create_export_row(analysis_result)

    assert row["rosti_count"] == 0
    assert row["rosti_values"] is None
    assert row["rosti_types"] is None


def test_create_export_row_values_preview_truncation():
    """Test values preview is truncated to 5 items."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "count": 10,
        "results": [{"value": f"192.168.1.{i}", "type": "IPv4"} for i in range(10)],
        "total": 10,
        "has_more": True,
    }

    row = engine.create_export_row(analysis_result)

    assert row["rosti_count"] == 10
    values_list = row["rosti_values"].split(", ")
    assert len(values_list) == 5


def test_create_export_row_types_preview_truncation():
    """Test types preview is truncated to 5 items."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    types_list = ["IPv4", "IPv6", "FQDN", "URL", "Email", "MD5", "SHA1", "SHA256"]
    analysis_result = {
        "count": len(types_list),
        "results": [{"value": f"obs_{i}", "type": types_list[i]} for i in range(len(types_list))],
        "total": len(types_list),
        "has_more": False,
    }

    row = engine.create_export_row(analysis_result)

    types_preview = row["rosti_types"].split(", ")
    assert len(types_preview) == 5


def test_create_export_row_missing_fields():
    """Test export row handles missing optional fields gracefully."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "count": 2,
        "results": [
            {"value": "192.168.1.5"},  # Missing type
            {"type": "IPv4"},  # Missing value
        ],
        "total": 2,
        "has_more": False,
    }

    row = engine.create_export_row(analysis_result)

    assert row["rosti_count"] == 2
    # Only first result has a value
    assert row["rosti_values"] == "192.168.1.5"
    # Only second result has a type
    assert row["rosti_types"] == "IPv4"


# ============================================================================
# Phase 5: Edge Cases & Additional Coverage
# ============================================================================


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = RostiEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "rosti"
    assert engine.supported_types == [
        "IPv4",
        "IPv6",
        "FQDN",
        "URL",
        "Email",
        "MD5",
        "SHA1",
        "SHA256",
    ]
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False


@responses.activate
def test_analyze_all_optional_fields_present(secrets_with_key, ipv4_observable):
    """Test result with all optional fields populated."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": "192.168.1.5",
                "type": "IPv4",
                "category": "malware",
                "date": "2025-01-15",
                "comment": "Test comment",
                "ids": ["id1", "id2"],
                "report": "report123",
                "timestamp": "2025-01-15T10:00:00Z",
                "risk": "high",
                "id": "ioc_001",
            }
        ],
        "meta": {"total": 1, "has_more": False},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    item = result["results"][0]
    assert item["value"] == "192.168.1.5"
    assert item["type"] == "IPv4"
    assert item["category"] == "malware"
    assert item["date"] == "2025-01-15"
    assert item["comment"] == "Test comment"
    assert item["ids"] == ["id1", "id2"]
    assert item["report"] == "report123"
    assert item["timestamp"] == "2025-01-15T10:00:00Z"
    assert item["risk"] == "high"
    assert item["id"] == "ioc_001"


@responses.activate
def test_analyze_minimal_result_fields(secrets_with_key, ipv4_observable):
    """Test result with minimal fields (only required fields)."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {
                "value": "192.168.1.5",
                "type": "IPv4",
            }
        ],
        "meta": {},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    item = result["results"][0]
    assert item["value"] == "192.168.1.5"
    assert item["type"] == "IPv4"
    assert item["category"] is None
    assert item["date"] is None


@responses.activate
def test_analyze_meta_missing_total(secrets_with_key, ipv4_observable):
    """Test metadata without 'total' field."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [{"value": "192.168.1.5", "type": "IPv4"}],
        "meta": {"has_more": False},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] is None
    assert result["has_more"] is False


@responses.activate
def test_analyze_data_is_not_list(secrets_with_key, ipv4_observable):
    """Test handling when 'data' field is not a list."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": {"invalid": "structure"},
        "meta": {},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 0
    assert result["results"] == []


@responses.activate
def test_analyze_multiple_results_mixed_validity(secrets_with_key, ipv4_observable):
    """Test handling of multiple results with some invalid items."""
    engine = RostiEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://api.rosti.bin.re/v2/iocs"

    mock_resp = {
        "data": [
            {"value": "192.168.1.5", "type": "IPv4"},
            {"value": "192.168.1.6"},  # Missing type but still valid dict
            "invalid_string",
            None,
            {"value": "192.168.1.7", "type": "IPv6", "category": "malware"},
        ],
        "meta": {"total": 5, "has_more": False},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["count"] == 3  # Three valid dicts
    assert len(result["results"]) == 3
