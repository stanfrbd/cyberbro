import logging
from datetime import datetime, timezone

import pytest
import requests
import responses

from engines.misp import MISPEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    """Secrets object with MISP API credentials."""
    s = Secrets()
    s.misp_api_key = "test_api_key_12345"
    s.misp_url = "https://misp.example.com"
    return s


@pytest.fixture
def secrets_without_key():
    """Secrets object with missing MISP credentials."""
    s = Secrets()
    s.misp_api_key = ""
    s.misp_url = ""
    return s


@pytest.fixture
def misp_engine(secrets_with_key):
    """MISPEngine instance with mocked secrets."""
    return MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)


@pytest.fixture
def ipv4_observable():
    """IPv4 observable for testing."""
    return "8.8.8.8"


@pytest.fixture
def ipv6_observable():
    """IPv6 observable for testing."""
    return "2001:4860:4860::8888"


@pytest.fixture
def fqdn_observable():
    """FQDN observable for testing."""
    return "example.com"


@pytest.fixture
def url_observable():
    """URL observable for testing."""
    return "https://example.com/path"


@pytest.fixture
def md5_hash():
    """MD5 hash observable for testing."""
    return "5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def sha1_hash():
    """SHA1 hash observable for testing."""
    return "356a192b7913b04c54574d18c28d46e6395428ab"


@pytest.fixture
def sha256_hash():
    """SHA256 hash observable for testing."""
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def create_misp_attribute(timestamp: str, event_id: int, event_info: str) -> dict:
    """Create a realistic MISP attribute response."""
    return {
        "id": 123,
        "type": "ip-dst",
        "value": "8.8.8.8",
        "timestamp": timestamp,
        "Event": {
            "id": event_id,
            "info": event_info,
        },
    }


def create_misp_response(attributes: list) -> dict:
    """Create a realistic MISP API response."""
    return {
        "response": {
            "Attribute": attributes,
        },
    }


# ============================================================================
# Priority 1: Credential Validation (3 tests)
# ============================================================================


@responses.activate
def test_analyze_missing_api_key(secrets_without_key, ipv4_observable, caplog):
    """Test analyze returns None when API key is missing."""
    secrets_without_key.misp_api_key = ""
    secrets_without_key.misp_url = "https://misp.example.com"
    engine = MISPEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "MISP API key or URL is required" in caplog.text


@responses.activate
def test_analyze_missing_misp_url(secrets_without_key, ipv4_observable, caplog):
    """Test analyze returns None when MISP URL is missing."""
    secrets_without_key.misp_api_key = "test_key"
    secrets_without_key.misp_url = ""
    engine = MISPEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "MISP API key or URL is required" in caplog.text


@responses.activate
def test_analyze_missing_both_credentials(secrets_without_key, ipv4_observable, caplog):
    """Test analyze returns None when both API key and URL are missing."""
    engine = MISPEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "MISP API key or URL is required" in caplog.text


# ============================================================================
# Priority 2: Observable Type Routing (Parametrized - 7 cases + unsupported)
# ============================================================================


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        ("URL", "https://example.com"),
        ("IPv4", "8.8.8.8"),
        ("IPv6", "2001:4860:4860::8888"),
        ("FQDN", "example.com"),
        ("SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("SHA1", "356a192b7913b04c54574d18c28d46e6395428ab"),
        ("MD5", "5d41402abc4b2a76b9719d911017c592"),
    ],
)
def test_analyze_observable_type_routing(secrets_with_key, observable_type, observable_value):
    """Test analyze routes to correct MISP type for all observable types."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [create_misp_attribute("1704067200", 1, "Test Event")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(observable_value, observable_type)
    assert result is not None
    assert len(responses.calls) == 1


@responses.activate
def test_analyze_unsupported_observable_type(secrets_with_key, caplog):
    """Test analyze returns None for unsupported observable types."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze("test@example.com", "Email")
    assert result is None
    assert "Unsupported observable type for MISP" in caplog.text


# ============================================================================
# Priority 3: URL Encoding & Link Generation (4 tests)
# ============================================================================


@responses.activate
def test_link_generation_simple_observable(secrets_with_key, fqdn_observable):
    """Test link generation with simple observable."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [create_misp_attribute("1704067200", 1, "Test Event")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")
    assert result is not None
    assert result["link"] == f"https://misp.example.com/attributes/index?value={fqdn_observable}"


@responses.activate
def test_link_generation_with_special_characters(secrets_with_key):
    """Test link generation properly URL-encodes special characters."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"
    observable = "test@example.com"

    attributes = [create_misp_attribute("1704067200", 1, "Test Event")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(observable, "FQDN")
    assert result is not None
    assert "test%40example.com" in result["link"]


@responses.activate
def test_link_generation_with_url_special_chars(secrets_with_key):
    """Test link generation with URL-specific special characters."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"
    observable = "example.com/path?param=value"

    attributes = [create_misp_attribute("1704067200", 1, "Test Event")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(observable, "FQDN")
    assert result is not None
    assert "%3F" in result["link"]  # "?" encoded as %3F
    assert "%3D" in result["link"]  # "=" encoded as %3D


@responses.activate
def test_url_preprocessing_trailing_slash_removal(secrets_with_key, fqdn_observable):
    """Test MISP URL preprocessing removes trailing slash."""
    secrets_with_key.misp_url = "https://misp.example.com/"
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [create_misp_attribute("1704067200", 1, "Test Event")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")
    assert result is not None
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == url


# ============================================================================
# Priority 4: Credential-Related API Errors (2 tests)
# ============================================================================


@responses.activate
def test_analyze_invalid_credentials_401(secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None on 401 Unauthorized response."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json={"error": "Unauthorized"},
        status=401,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


@responses.activate
def test_analyze_invalid_credentials_403(secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None on 403 Forbidden response."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json={"error": "Forbidden"},
        status=403,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


# ============================================================================
# Priority 5: Event Processing & Sorting (6 tests)
# ============================================================================


@responses.activate
def test_analyze_event_limiting_less_than_5(secrets_with_key, ipv4_observable):
    """Test analyze returns all events when less than 5 are present."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("1000", 1, "Event 1"),
        create_misp_attribute("2000", 2, "Event 2"),
        create_misp_attribute("3000", 3, "Event 3"),
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 3


@responses.activate
def test_analyze_event_limiting_exactly_5(secrets_with_key, ipv4_observable):
    """Test analyze returns all events when exactly 5 are present."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [create_misp_attribute(str(i * 1000), i, f"Event {i}") for i in range(1, 6)]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 5


@responses.activate
def test_analyze_event_limiting_more_than_5(secrets_with_key, ipv4_observable):
    """Test analyze returns only 5 most recent events when more are present."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [create_misp_attribute(str(i * 1000), i, f"Event {i}") for i in range(1, 13)]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 5
    assert result["count"] == 12


@responses.activate
def test_analyze_event_sorting_descending_by_timestamp(secrets_with_key, ipv4_observable):
    """Test events are sorted by timestamp in descending order."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("100", 1, "Event 1"),
        create_misp_attribute("500", 5, "Event 5"),
        create_misp_attribute("200", 2, "Event 2"),
        create_misp_attribute("400", 4, "Event 4"),
        create_misp_attribute("300", 3, "Event 3"),
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 5
    timestamps = [int(e["timestamp"]) for e in result["events"]]
    assert timestamps == sorted(timestamps, reverse=True)


@responses.activate
def test_analyze_event_deduplication_by_event_id(secrets_with_key, ipv4_observable):
    """Test events are deduplicated by event_id."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("1000", 1, "Event 1"),
        create_misp_attribute("2000", 1, "Event 1"),  # Same event_id
        create_misp_attribute("3000", 2, "Event 2"),
        create_misp_attribute("4000", 2, "Event 2"),  # Same event_id
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 2
    assert result["count"] == 4


@responses.activate
def test_analyze_event_missing_event_info(secrets_with_key, ipv4_observable):
    """Test event without info field defaults to 'Unknown'."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attribute = {
        "id": 123,
        "type": "ip-dst",
        "value": "8.8.8.8",
        "timestamp": "1704067200",
        "Event": {
            "id": 1,
            # Missing "info" field
        },
    }
    responses.add(
        responses.POST,
        url,
        json=create_misp_response([attribute]),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert len(result["events"]) == 1
    assert result["events"][0]["title"] == "Unknown"


# ============================================================================
# Priority 6: Timestamp Processing (7 tests)
# ============================================================================


@responses.activate
def test_analyze_timestamp_conversion_recent_date(secrets_with_key, ipv4_observable):
    """Test timestamp conversion for recent date."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    timestamp = "1704067200"  # 2024-01-01 00:00:00 UTC
    attributes = [create_misp_attribute(timestamp, 1, "Event 1")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["first_seen"] == "2024-01-01"
    assert result["last_seen"] == "2024-01-01"


@responses.activate
def test_analyze_timestamp_conversion_epoch(secrets_with_key, ipv4_observable):
    """Test timestamp conversion for epoch (1970-01-01)."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    timestamp = "0"  # 1970-01-01 00:00:00 UTC
    attributes = [create_misp_attribute(timestamp, 1, "Event 1")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["first_seen"] == "1970-01-01"
    assert result["last_seen"] == "1970-01-01"


@responses.activate
def test_analyze_timestamp_year_boundary(secrets_with_key, ipv4_observable):
    """Test timestamp at year boundary."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    timestamp = "1672531199"  # 2022-12-31 23:59:59 UTC
    attributes = [create_misp_attribute(timestamp, 1, "Event 1")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["first_seen"] == "2022-12-31"


@responses.activate
def test_analyze_first_seen_last_seen_tracking(secrets_with_key, ipv4_observable):
    """Test first_seen and last_seen track min and max timestamps."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("100", 1, "Event 1"),
        create_misp_attribute("500", 2, "Event 2"),
        create_misp_attribute("200", 3, "Event 3"),
        create_misp_attribute("400", 4, "Event 4"),
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    dt_100 = datetime.fromtimestamp(100, tz=timezone.utc).strftime("%Y-%m-%d")
    dt_500 = datetime.fromtimestamp(500, tz=timezone.utc).strftime("%Y-%m-%d")
    assert result["first_seen"] == dt_100
    assert result["last_seen"] == dt_500


@responses.activate
def test_analyze_missing_timestamps_partial(secrets_with_key, ipv4_observable):
    """Test handling of mix of attributes with and without timestamps."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("1000", 1, "Event 1"),
        create_misp_attribute("2000", 2, "Event 2"),
        create_misp_attribute("3000", 3, "Event 3"),
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    dt_1000 = datetime.fromtimestamp(1000, tz=timezone.utc).strftime("%Y-%m-%d")
    dt_3000 = datetime.fromtimestamp(3000, tz=timezone.utc).strftime("%Y-%m-%d")
    assert result["first_seen"] == dt_1000
    assert result["last_seen"] == dt_3000


@responses.activate
def test_analyze_all_timestamps_missing(secrets_with_key, ipv4_observable):
    """Test when all attributes are missing timestamps."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attribute = {
        "id": 123,
        "type": "ip-dst",
        "value": "8.8.8.8",
        # Missing timestamp
        "Event": {
            "id": 1,
            "info": "Event 1",
        },
    }
    responses.add(
        responses.POST,
        url,
        json=create_misp_response([attribute]),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["first_seen"] is None
    assert result["last_seen"] is None


@responses.activate
def test_analyze_timestamp_utc_conversion(secrets_with_key, ipv4_observable):
    """Test timestamp uses UTC conversion regardless of system timezone."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    timestamp = "1704067200"  # 2024-01-01 00:00:00 UTC
    attributes = [create_misp_attribute(timestamp, 1, "Event 1")]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    dt_utc = datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime("%Y-%m-%d")
    assert result["first_seen"] == dt_utc


# ============================================================================
# Priority 7: Response Variations (5 tests)
# ============================================================================


@responses.activate
def test_analyze_empty_attributes_list(secrets_with_key, ipv4_observable):
    """Test handling of empty attributes list."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json=create_misp_response([]),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["count"] == 0
    assert result["events"] == []
    assert result["first_seen"] is None
    assert result["last_seen"] is None


@responses.activate
def test_analyze_complete_response_success(secrets_with_key, ipv4_observable):
    """Test successful analysis with realistic complete response."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("1000", 1, "Event 1"),
        create_misp_attribute("2000", 1, "Event 1"),
        create_misp_attribute("3000", 2, "Event 2"),
        create_misp_attribute("4000", 3, "Event 3"),
        create_misp_attribute("5000", 4, "Event 4"),
        create_misp_attribute("6000", 5, "Event 5"),
        create_misp_attribute("7000", 6, "Event 6"),
        create_misp_attribute("8000", 7, "Event 7"),
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["count"] == 8
    assert len(result["events"]) == 5
    assert result["link"] == f"https://misp.example.com/attributes/index?value={ipv4_observable}"
    assert result["first_seen"] is not None
    assert result["last_seen"] is not None


@responses.activate
def test_analyze_missing_response_key(secrets_with_key, ipv4_observable):
    """Test handling of response missing response key."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json={},
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["count"] == 0
    assert result["events"] == []


@responses.activate
def test_analyze_attribute_not_list(secrets_with_key, ipv4_observable):
    """Test handling when Attribute is not a list."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json={
            "response": {
                "Attribute": {
                    "id": 123,
                    "value": "test",
                },
            },
        },
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["count"] == 0
    assert result["events"] == []


@responses.activate
def test_analyze_missing_event_data(secrets_with_key, ipv4_observable):
    """Test handling of attributes missing Event object."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    attributes = [
        create_misp_attribute("1000", 1, "Event 1"),
        {
            "id": 124,
            "type": "ip-dst",
            "value": "8.8.8.9",
            "timestamp": "2000",
            # Missing Event object
        },
    ]
    responses.add(
        responses.POST,
        url,
        json=create_misp_response(attributes),
        status=200,
    )

    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is not None
    assert result["count"] == 2


# ============================================================================
# Priority 8: HTTP Errors & Network Issues (Parametrized - 8 tests)
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500, 502, 503])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, status_code, caplog):
    """Test analyze returns None for various HTTP error codes."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        json={"error": "Server Error"},
        status=status_code,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


@responses.activate
def test_analyze_connection_timeout(secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when connection times out."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        body=requests.exceptions.Timeout(),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


@responses.activate
def test_analyze_connection_error(secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when connection fails."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        body=requests.exceptions.ConnectionError(),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when response JSON is invalid."""
    engine = MISPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = "https://misp.example.com/attributes/restSearch"

    responses.add(
        responses.POST,
        url,
        body="not valid json",
        status=200,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")
    assert result is None
    assert "Error querying MISP" in caplog.text


# ============================================================================
# Priority 9: Export Row Creation (4 tests)
# ============================================================================


def test_create_export_row_all_fields(misp_engine):
    """Test create_export_row with all fields present."""
    analysis_result = {
        "count": 10,
        "first_seen": "2024-01-01",
        "last_seen": "2024-01-10",
        "events": [],
        "link": "http://example.com",
    }
    export = misp_engine.create_export_row(analysis_result)
    assert export["misp_count"] == 10
    assert export["misp_first_seen"] == "2024-01-01"
    assert export["misp_last_seen"] == "2024-01-10"


def test_create_export_row_partial_fields(misp_engine):
    """Test create_export_row with missing last_seen."""
    analysis_result = {
        "count": 5,
        "first_seen": "2024-01-01",
        # Missing last_seen
        "events": [],
        "link": "http://example.com",
    }
    export = misp_engine.create_export_row(analysis_result)
    assert export["misp_count"] == 5
    assert export["misp_first_seen"] == "2024-01-01"
    assert export["misp_last_seen"] is None


def test_create_export_row_none_input(misp_engine):
    """Test create_export_row with None input."""
    export = misp_engine.create_export_row(None)
    assert export["misp_count"] is None
    assert export["misp_first_seen"] is None
    assert export["misp_last_seen"] is None


def test_create_export_row_field_names(misp_engine):
    """Test create_export_row returns correct field names."""
    analysis_result = {
        "count": 1,
        "first_seen": "2024-01-01",
        "last_seen": "2024-01-01",
        "events": [],
        "link": "http://example.com",
    }
    export = misp_engine.create_export_row(analysis_result)
    expected_keys = {"misp_count", "misp_first_seen", "misp_last_seen"}
    assert set(export.keys()) == expected_keys


# ============================================================================
# Priority 10: Engine Properties (2 tests)
# ============================================================================


def test_engine_name(misp_engine):
    """Test engine name property."""
    assert misp_engine.name == "misp"


def test_supported_types(misp_engine):
    """Test supported observable types."""
    expected_types = ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]
    assert misp_engine.supported_types == expected_types
