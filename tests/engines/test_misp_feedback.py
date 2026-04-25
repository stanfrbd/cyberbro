import logging

import pytest
import requests
import responses

from engines.misp_feedback import MispFeedbackEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def ipv4_observable():
    return Observable(value="1.1.1.1", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable():
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


@pytest.fixture
def md5_hash_observable():
    return Observable(value="5d41402abc4b2a76b9719d911017c592", type=ObservableType.MD5)


@pytest.fixture
def sha1_hash_observable():
    return Observable(value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", type=ObservableType.SHA1)


@pytest.fixture
def sha256_hash_observable():
    return Observable(
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        type=ObservableType.SHA256,
    )


@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def secrets_with_misp_feedback():
    s = Secrets()
    s.misp_feedback_server_url = "http://localhost:3000"
    s.misp_feedback_token = ""
    return s


@pytest.fixture
def secrets_with_misp_feedback_auth():
    s = Secrets()
    s.misp_feedback_server_url = "http://localhost:3000"
    s.misp_feedback_token = "test-token"
    return s


# ============================================================================
# High Priority: Critical Paths - HIT/CLEAN Analysis
# ============================================================================


@responses.activate
def test_analyze_ipv4_hit_with_matches(ipv4_observable, secrets_with_misp_feedback):
    """Test successful analysis of IPv4 with HIT (matches found)."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "1.1.1.1",
        "matched": True,
        "matches": [
            {"name": "List of known IPv4 public DNS resolvers"},
            {"name": "Cloudflare public DNS"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["status"] == "HIT"
    assert len(result["warninglists"]) == 2
    assert "List of known IPv4 public DNS resolvers" in result["warninglists"]
    assert "Cloudflare public DNS" in result["warninglists"]


@responses.activate
def test_analyze_ipv4_clean_no_matches(ipv4_observable, secrets_with_misp_feedback):
    """Test successful analysis of IPv4 with CLEAN result (no matches)."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {"value": "1.2.3.4", "matched": False, "matches": []}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["status"] == "CLEAN"
    assert result["warninglists"] == []


@responses.activate
def test_analyze_sha256_hit(sha256_hash_observable, secrets_with_misp_feedback):
    """Test successful analysis of SHA256 hash with HIT."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "matched": True,
        "matches": [
            {"name": "Legitimate software list"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(sha256_hash_observable)

    assert result is not None
    assert result["status"] == "HIT"
    assert result["warninglists"] == ["Legitimate software list"]


@responses.activate
def test_analyze_fqdn_clean(fqdn_observable, secrets_with_misp_feedback):
    """Test successful analysis of FQDN with CLEAN result."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {"value": "example.com", "matched": False, "matches": []}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["status"] == "CLEAN"
    assert result["warninglists"] == []


# ============================================================================
# Medium Priority: Authentication & Configuration
# ============================================================================


@responses.activate
def test_analyze_with_basic_auth(ipv4_observable, secrets_with_misp_feedback_auth):
    """Test request includes Basic Auth header when token is provided."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback_auth, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {"value": "1.1.1.1", "matched": False, "matches": []}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert "Authorization" in request.headers
    assert request.headers["Authorization"].startswith("Basic ")


@responses.activate
def test_analyze_without_auth_header(ipv4_observable, secrets_with_misp_feedback):
    """Test request does not include Basic Auth when token is empty."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {"value": "1.1.1.1", "matched": False, "matches": []}

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert len(responses.calls) == 1
    request = responses.calls[0].request
    assert "Authorization" not in request.headers


def test_analyze_missing_server_url(ipv4_observable):
    """Test analysis returns None when server URL is not configured."""
    s = Secrets()
    s.misp_feedback_server_url = ""
    engine = MispFeedbackEngine(s, proxies={}, ssl_verify=True)

    result = engine.analyze(ipv4_observable)

    assert result is None


# ============================================================================
# Medium Priority: Response Edge Cases & Error Handling
# ============================================================================


@responses.activate
def test_analyze_ipv6_with_matches(ipv6_observable, secrets_with_misp_feedback):
    """Test successful analysis of IPv6."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "2001:4860:4860::8888",
        "matched": True,
        "matches": [
            {"name": "IPv6 public DNS"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable)

    assert result is not None
    assert result["status"] == "HIT"
    assert result["warninglists"] == ["IPv6 public DNS"]


@responses.activate
def test_analyze_md5_hash(md5_hash_observable, secrets_with_misp_feedback):
    """Test successful analysis of MD5 hash."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "5d41402abc4b2a76b9719d911017c592",
        "matched": True,
        "matches": [
            {"name": "Known good hash"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(md5_hash_observable)

    assert result is not None
    assert result["status"] == "HIT"


@responses.activate
def test_analyze_sha1_hash(sha1_hash_observable, secrets_with_misp_feedback):
    """Test successful analysis of SHA1 hash."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "matched": False,
        "matches": [],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(sha1_hash_observable)

    assert result is not None
    assert result["status"] == "CLEAN"


@responses.activate
@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500, 502, 503])
def test_analyze_http_error_codes(ipv4_observable, secrets_with_misp_feedback, status_code, caplog):
    """Test handling of HTTP error responses."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    responses.add(responses.POST, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Error querying MISP-feedback" in caplog.text


@responses.activate
def test_analyze_connection_timeout(ipv4_observable, secrets_with_misp_feedback, caplog):
    """Test handling of connection timeout."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.INFO)
    result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Timeout occurred while querying MISP-feedback" in caplog.text


@responses.activate
def test_analyze_read_timeout(ipv4_observable, secrets_with_misp_feedback, caplog):
    """Test handling of read timeout."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    timeout_error = requests.exceptions.ReadTimeout("Read timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.INFO)
    result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Timeout occurred while querying MISP-feedback" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(ipv4_observable, secrets_with_misp_feedback, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    responses.add(responses.POST, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable)

    assert result is None
    assert "Unexpected error while parsing response from MISP-feedback" in caplog.text


@responses.activate
def test_analyze_multiple_matches(ipv4_observable, secrets_with_misp_feedback):
    """Test analysis with multiple matches in response."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "1.1.1.1",
        "matched": True,
        "matches": [
            {"name": "Public DNS"},
            {"name": "CDN IPs"},
            {"name": "Legitimate IPs"},
            {"name": "ISP ranges"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["status"] == "HIT"
    assert len(result["warninglists"]) == 4
    assert all(
        name in result["warninglists"]
        for name in [
            "Public DNS",
            "CDN IPs",
            "Legitimate IPs",
            "ISP ranges",
        ]
    )


@responses.activate
def test_analyze_match_with_missing_name(ipv4_observable, secrets_with_misp_feedback):
    """Test handling of match object without name field."""
    engine = MispFeedbackEngine(secrets_with_misp_feedback, proxies={}, ssl_verify=True)
    url = "http://localhost:3000/lookup"

    mock_resp = {
        "value": "1.1.1.1",
        "matched": True,
        "matches": [
            {"name": "Known good"},
            {"slug": "no-name-field"},
        ],
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable)

    assert result is not None
    assert result["status"] == "HIT"
    assert "Unknown" in result["warninglists"]


# ============================================================================
# Low Priority: Export Row Formatting & Properties
# ============================================================================


def test_create_export_row_with_hit():
    """Test export row formatting for HIT result."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "status": "HIT",
        "warninglists": ["Public DNS", "CDN IPs", "ISP ranges"],
    }

    row = engine.create_export_row(analysis_result)

    assert row["misp_feedback_status"] == "HIT"
    assert row["misp_feedback_warninglists"] == "Public DNS, CDN IPs, ISP ranges"


def test_create_export_row_with_clean():
    """Test export row formatting for CLEAN result."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "status": "CLEAN",
        "warninglists": [],
    }

    row = engine.create_export_row(analysis_result)

    assert row["misp_feedback_status"] == "CLEAN"
    assert row["misp_feedback_warninglists"] is None


def test_create_export_row_with_none():
    """Test export row with None analysis result."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["misp_feedback_status"] is None
    assert row["misp_feedback_warninglists"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "misp_feedback"
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False


def test_engine_supported_types():
    """Test that engine supports correct observable types."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    supported = engine.supported_types
    assert supported & ObservableType.MD5
    assert supported & ObservableType.SHA1
    assert supported & ObservableType.SHA256
    assert supported & ObservableType.IPV4
    assert supported & ObservableType.IPV6
    assert supported & ObservableType.FQDN


def test_create_export_row_single_warning():
    """Test export row formatting with single warning."""
    engine = MispFeedbackEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "status": "HIT",
        "warninglists": ["Single Warning"],
    }

    row = engine.create_export_row(analysis_result)

    assert row["misp_feedback_status"] == "HIT"
    assert row["misp_feedback_warninglists"] == "Single Warning"
