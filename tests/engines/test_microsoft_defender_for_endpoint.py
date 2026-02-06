import logging
import time
from unittest.mock import patch

import jwt
import pytest
import requests
import responses

from engines.microsoft_defender_for_endpoint import MDEEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    """Secrets object with all required MDE credentials."""
    s = Secrets()
    s.mde_tenant_id = "test_tenant_id"
    s.mde_client_id = "test_client_id"
    s.mde_client_secret = "test_client_secret"
    return s


@pytest.fixture
def secrets_without_key():
    """Secrets object with missing MDE credentials."""
    s = Secrets()
    s.mde_tenant_id = ""
    s.mde_client_id = ""
    s.mde_client_secret = ""
    return s


@pytest.fixture
def mde_engine(secrets_with_key):
    """MDEEngine instance with mocked secrets."""
    return MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)


@pytest.fixture
def ipv4_observable():
    """IPv4 observable for testing."""
    return "8.8.8.8"


@pytest.fixture
def ipv6_observable():
    """IPv6 observable for testing."""
    return "2001:4860:4860::8888"


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


def create_valid_jwt_token(exp_offset: int = 3600) -> str:
    """Create a valid JWT token with specified expiration offset."""
    payload = {"exp": int(time.time()) + exp_offset, "iat": int(time.time())}
    return jwt.encode(payload, "secret", algorithm="HS256")


def create_expired_jwt_token() -> str:
    """Create an expired JWT token."""
    payload = {"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}
    return jwt.encode(payload, "secret", algorithm="HS256")


def create_jwt_no_exp() -> str:
    """Create a JWT token without exp claim."""
    payload = {"iat": int(time.time())}
    return jwt.encode(payload, "secret", algorithm="HS256")


def mock_mde_stats_response(observable_value: str) -> dict:
    """Create a realistic Microsoft Defender stats API response."""
    return {
        "id": f"ip-{observable_value}",
        "objectType": "Ip",
        "indicatorValue": observable_value,
        "indicatorType": "IpAddress",
        "countByThreatType": {
            "Ransomware": 0,
            "Phishing": 0,
            "PUA": 0,
            "Malware": 5,
            "Unwanted Software": 2,
            "Trojan": 1,
            "CredentialTheft": 0,
            "CommandAndControl": 0,
            "Cryptomining": 0,
        },
        "countByLocation": {
            "US": 3,
            "CN": 2,
            "RU": 1,
        },
        "countBySeverity": {
            "Critical": 2,
            "High": 3,
            "Medium": 1,
            "Low": 2,
            "Informational": 0,
        },
        "firstSeen": "2023-01-10T08:15:00Z",
        "lastSeen": "2024-01-20T14:30:00Z",
        "orgFirstSeen": "2023-01-10T08:15:00Z",
        "orgLastSeen": "2024-01-20T14:30:00Z",
        "orgPrevalence": 150,
    }


def mock_mde_file_info_response() -> dict:
    """Create a realistic Microsoft Defender file info API response."""
    return {
        "id": "file-id-xyz",
        "sha1": "356a192b7913b04c54574d18c28d46e6395428ab",
        "issuer": "Microsoft Corporation",
        "signer": "Microsoft Windows",
        "isValidCertificate": True,
        "filePublisher": "Microsoft Corporation",
        "fileProductName": "Windows Explorer",
        "determinationType": "Clean",
        "determinationValue": "Good",
    }


# ============================================================================
# Priority 1: Token Management & Initialization (14 tests)
# ============================================================================


def test_check_token_validity_valid_token(mde_engine):
    """Test _check_token_validity returns True for valid, non-expired token."""
    valid_token = create_valid_jwt_token()
    assert mde_engine._check_token_validity(valid_token) is True


def test_check_token_validity_expired_token(mde_engine, caplog):
    """Test _check_token_validity returns False for expired token."""
    expired_token = create_expired_jwt_token()
    caplog.set_level(logging.WARNING)
    assert mde_engine._check_token_validity(expired_token) is False
    assert "MDE Token has expired" in caplog.text


def test_check_token_validity_missing_exp_claim(mde_engine, caplog):
    """Test _check_token_validity returns False when exp claim is missing."""
    token_no_exp = create_jwt_no_exp()
    caplog.set_level(logging.WARNING)
    assert mde_engine._check_token_validity(token_no_exp) is False
    assert "MDE Token has no expiration claim" in caplog.text


def test_check_token_validity_malformed_jwt(mde_engine, caplog):
    """Test _check_token_validity returns False for malformed JWT."""
    caplog.set_level(logging.ERROR)
    assert mde_engine._check_token_validity("not_a_valid_jwt") is False
    assert "Failed to decode MDE token" in caplog.text


@patch("pathlib.Path.read_text")
def test_read_token_success(mock_read_text, mde_engine):
    """Test _read_token returns token when file exists and token is valid."""
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = f"{valid_token}\n"
    result = mde_engine._read_token()
    assert result == valid_token


@patch("pathlib.Path.read_text")
def test_read_token_invalid_token(mock_read_text, mde_engine, caplog):
    """Test _read_token returns None when token validation fails."""
    mock_read_text.return_value = "invalid_token"
    caplog.set_level(logging.ERROR)
    result = mde_engine._read_token()
    assert result is None


@patch("pathlib.Path.read_text")
def test_read_token_file_not_found(mock_read_text, mde_engine, caplog):
    """Test _read_token returns None when file cannot be read."""
    mock_read_text.side_effect = FileNotFoundError()
    caplog.set_level(logging.ERROR)
    result = mde_engine._read_token()
    assert result is None
    assert "Failed to read token from file" in caplog.text


@patch("pathlib.Path.read_text")
def test_read_token_strip_whitespace(mock_read_text, mde_engine):
    """Test _read_token strips whitespace from token."""
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = f"  {valid_token}  \n"
    result = mde_engine._read_token()
    assert result == valid_token


@responses.activate
@patch("pathlib.Path.write_text")
def test_get_token_success(mock_write_text, secrets_with_key):
    """Test _get_token successfully fetches and caches token."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"
    access_token = create_valid_jwt_token()

    responses.add(
        responses.POST,
        url,
        json={"access_token": access_token},
        status=200,
    )

    result = engine._get_token()
    assert result == access_token
    mock_write_text.assert_called_once_with(access_token)


@responses.activate
def test_get_token_missing_access_token_key(secrets_with_key, caplog):
    """Test _get_token returns 'invalid' when access_token key is missing."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"

    responses.add(
        responses.POST,
        url,
        json={"error": "invalid_client", "error_description": "Invalid client"},
        status=200,
    )

    caplog.set_level(logging.ERROR)
    result = engine._get_token()
    assert result == "invalid"
    assert "Unable to retrieve token from JSON response" in caplog.text


@responses.activate
def test_get_token_request_failure(secrets_with_key, caplog):
    """Test _get_token returns 'invalid' when request fails."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"

    responses.add(
        responses.POST,
        url,
        status=500,
    )

    caplog.set_level(logging.ERROR)
    result = engine._get_token()
    assert result == "invalid"
    assert "Error fetching token from Microsoft" in caplog.text


@responses.activate
def test_get_token_missing_client_id(secrets_with_key, caplog):
    """Test _get_token behavior when mde_client_id is missing."""
    secrets_with_key.mde_client_id = ""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"

    responses.add(
        responses.POST,
        url,
        json={"error": "invalid_client"},
        status=400,
    )

    caplog.set_level(logging.ERROR)
    result = engine._get_token()
    assert result == "invalid"


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_token_fallback_logic(mock_read_text, secrets_with_key, ipv4_observable):
    """Test analyze uses fallback token from _get_token when _read_token returns None."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_read_text.return_value = "invalid_token"
    valid_token = create_valid_jwt_token()
    oauth_url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"
    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"

    responses.add(
        responses.POST,
        oauth_url,
        json={"access_token": valid_token},
        status=200,
    )
    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(ipv4_observable),
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert result["link"] == f"https://security.microsoft.com/ip/{ipv4_observable}/overview"


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_invalid_token_returns_none(
    mock_read_text, secrets_with_key, ipv4_observable, caplog
):
    """Test analyze returns None when no valid token is available."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_read_text.return_value = "invalid"
    oauth_url = f"https://login.microsoftonline.com/{secrets_with_key.mde_tenant_id}/oauth2/token"

    responses.add(
        responses.POST,
        oauth_url,
        json={"error": "invalid_client"},
        status=400,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is None
    assert "No valid token available for Microsoft Defender for Endpoint" in caplog.text


# ============================================================================
# Priority 2: Observable Type Routing (Parametrized - 9 test cases)
# ============================================================================


@responses.activate
@patch("pathlib.Path.read_text")
@pytest.mark.parametrize(
    "observable_type,observable_value,expected_endpoint",
    [
        (ObservableType.IPV4, "8.8.8.8", "/api/ips/8.8.8.8/stats"),
        (ObservableType.IPV6, "2001:4860:4860::8888", "/api/ips/2001:4860:4860::8888/stats"),
        (ObservableType.BOGON, "10.0.0.1", "/api/ips/10.0.0.1/stats"),
        (ObservableType.FQDN, "example.com", "/api/domains/example.com/stats"),
        (
            ObservableType.MD5,
            "5d41402abc4b2a76b9719d911017c592",
            "/api/files/5d41402abc4b2a76b9719d911017c592/stats",
        ),
        (
            ObservableType.SHA1,
            "356a192b7913b04c54574d18c28d46e6395428ab",
            "/api/files/356a192b7913b04c54574d18c28d46e6395428ab/stats",
        ),
        (
            ObservableType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "/api/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/stats",
        ),
        (ObservableType.URL, "https://example.com:8080/path", "/api/domains/example.com/stats"),
    ],
)
def test_analyze_observable_routing(
    mock_read_text, secrets_with_key, observable_type, observable_value, expected_endpoint
):
    """Test analyze routes to correct API endpoint for all observable types."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    base_url = "https://api.securitycenter.microsoft.com"
    stats_url = base_url + expected_endpoint
    file_info_url = base_url + expected_endpoint.replace("/stats", "")

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(observable_value),
        status=200,
    )

    if observable_type in [ObservableType.MD5, ObservableType.SHA1, ObservableType.SHA256]:
        responses.add(
            responses.GET,
            file_info_url,
            json=mock_mde_file_info_response(),
            status=200,
        )

    result = engine.analyze(observable_value, observable_type)
    assert result is not None
    assert len(responses.calls) >= 1


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_unsupported_observable_type(mock_read_text, secrets_with_key):
    """Test analyze returns None for unsupported observable types."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    result = engine.analyze("test@example.com", ObservableType.EMAIL)
    assert result is None
    assert len(responses.calls) == 0


# ============================================================================
# Priority 3: URL Parsing with Edge Cases (7 tests)
# ============================================================================


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_domain_extraction_simple(mock_read_text, secrets_with_key):
    """Test URL domain extraction with simple URL."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    url_observable = "https://example.com/path"
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/domains/example.com/stats",
        json=mock_mde_stats_response("example.com"),
        status=200,
    )

    result = engine.analyze(url_observable, ObservableType.URL)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_domain_extraction_with_port(mock_read_text, secrets_with_key):
    """Test URL domain extraction correctly removes port."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    url_observable = "https://example.com:8443/path"
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/domains/example.com/stats",
        json=mock_mde_stats_response("example.com"),
        status=200,
    )

    result = engine.analyze(url_observable, ObservableType.URL)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_domain_extraction_with_subdomain(mock_read_text, secrets_with_key):
    """Test URL domain extraction preserves subdomains."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    url_observable = "https://api.example.com/v1/path"
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/domains/api.example.com/stats",
        json=mock_mde_stats_response("api.example.com"),
        status=200,
    )

    result = engine.analyze(url_observable, ObservableType.URL)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_domain_extraction_with_query_string(mock_read_text, secrets_with_key):
    """Test URL domain extraction removes query parameters."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    url_observable = "https://example.com/path?id=123&name=test"
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/domains/example.com/stats",
        json=mock_mde_stats_response("example.com"),
        status=200,
    )

    result = engine.analyze(url_observable, ObservableType.URL)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_domain_extraction_with_fragment(mock_read_text, secrets_with_key):
    """Test URL domain extraction removes fragment identifiers."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    url_observable = "https://example.com/path#section"
    responses.add(
        responses.GET,
        "https://api.securitycenter.microsoft.com/api/domains/example.com/stats",
        json=mock_mde_stats_response("example.com"),
        status=200,
    )

    result = engine.analyze(url_observable, ObservableType.URL)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_parsing_malformed_no_protocol(mock_read_text, secrets_with_key, caplog):
    """Test URL parsing with malformed URL (no protocol)."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    caplog.set_level(logging.ERROR)
    result = engine.analyze("example.com/path", ObservableType.URL)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_url_parsing_malformed_no_path(mock_read_text, secrets_with_key, caplog):
    """Test URL parsing with malformed URL (no path after domain)."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    caplog.set_level(logging.ERROR)
    result = engine.analyze("https://example.com", ObservableType.URL)
    assert result is None


# ============================================================================
# Priority 4: API Response Processing (5-6 tests)
# ============================================================================


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_success_complete_response(mock_read_text, secrets_with_key, ipv4_observable):
    """Test successful API response with all data fields."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(ipv4_observable),
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert result["link"] == f"https://security.microsoft.com/ip/{ipv4_observable}/overview"
    assert result["orgPrevalence"] == 150


@responses.activate
@patch("pathlib.Path.read_text")
@pytest.mark.parametrize(
    "datetime_str,expected_date",
    [
        ("2024-01-15T10:30:45.123Z", "2024-01-15"),
        ("2024-01-15T10:30:45Z", "2024-01-15"),
        ("2024-01-15T10:30:45+00:00", "2024-01-15"),
        ("2024-01-15T23:59:59", "2024-01-15"),
    ],
)
def test_analyze_date_simplification_various_formats(
    mock_read_text, secrets_with_key, ipv4_observable, datetime_str, expected_date
):
    """Test date simplification with various ISO datetime formats."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    mock_response = mock_mde_stats_response(ipv4_observable)
    mock_response["orgFirstSeen"] = datetime_str
    mock_response["orgLastSeen"] = datetime_str

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_response,
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert result["orgFirstSeen"] == expected_date
    assert result["orgLastSeen"] == expected_date


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_missing_date_fields(mock_read_text, secrets_with_key, ipv4_observable):
    """Test analyze handles missing date fields gracefully."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    mock_response = mock_mde_stats_response(ipv4_observable)
    del mock_response["orgFirstSeen"]
    del mock_response["orgLastSeen"]

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_response,
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert "orgFirstSeen" not in result
    assert "orgLastSeen" not in result


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_null_date_fields(mock_read_text, secrets_with_key, ipv4_observable):
    """Test analyze handles null date fields."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    mock_response = mock_mde_stats_response(ipv4_observable)
    mock_response["orgFirstSeen"] = None
    mock_response["orgLastSeen"] = None

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_response,
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_empty_string_date_fields(mock_read_text, secrets_with_key, ipv4_observable):
    """Test analyze handles empty string date fields."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    mock_response = mock_mde_stats_response(ipv4_observable)
    mock_response["orgFirstSeen"] = ""
    mock_response["orgLastSeen"] = ""

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_response,
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None


# ============================================================================
# Priority 5: Extended File Info for Hashes (8 tests)
# ============================================================================


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_md5_triggers_file_info(mock_read_text, secrets_with_key, md5_hash):
    """Test analyze makes secondary file info call for MD5 hash."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(md5_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json=mock_mde_file_info_response(),
        status=200,
    )

    result = engine.analyze(md5_hash, ObservableType.MD5)
    assert result is not None
    assert len(responses.calls) == 2


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_sha1_triggers_file_info(mock_read_text, secrets_with_key, sha1_hash):
    """Test analyze makes secondary file info call for SHA1 hash."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{sha1_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{sha1_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(sha1_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json=mock_mde_file_info_response(),
        status=200,
    )

    result = engine.analyze(sha1_hash, ObservableType.SHA1)
    assert result is not None
    assert len(responses.calls) == 2


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_sha256_triggers_file_info(mock_read_text, secrets_with_key, sha256_hash):
    """Test analyze makes secondary file info call for SHA256 hash."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{sha256_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{sha256_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(sha256_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json=mock_mde_file_info_response(),
        status=200,
    )

    result = engine.analyze(sha256_hash, ObservableType.SHA256)
    assert result is not None
    assert len(responses.calls) == 2


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_file_info_all_fields_present(mock_read_text, secrets_with_key, md5_hash):
    """Test analyze includes all file info fields in result."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(md5_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json=mock_mde_file_info_response(),
        status=200,
    )

    result = engine.analyze(md5_hash, ObservableType.MD5)
    assert result is not None
    assert result["issuer"] == "Microsoft Corporation"
    assert result["signer"] == "Microsoft Windows"
    assert result["isValidCertificate"] is True
    assert result["filePublisher"] == "Microsoft Corporation"
    assert result["fileProductName"] == "Windows Explorer"
    assert result["determinationType"] == "Clean"
    assert result["determinationValue"] == "Good"


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_file_info_missing_fields(mock_read_text, secrets_with_key, md5_hash):
    """Test analyze sets missing file info fields to 'Unknown'."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(md5_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json={},
        status=200,
    )

    result = engine.analyze(md5_hash, ObservableType.MD5)
    assert result is not None
    assert result["issuer"] == "Unknown"
    assert result["signer"] == "Unknown"
    assert result["isValidCertificate"] == "Unknown"
    assert result["filePublisher"] == "Unknown"
    assert result["fileProductName"] == "Unknown"
    assert result["determinationType"] == "Unknown"
    assert result["determinationValue"] == "Unknown"


@responses.activate
@patch("pathlib.Path.read_text")
@pytest.mark.parametrize(
    "field_name",
    [
        "issuer",
        "signer",
        "isValidCertificate",
        "filePublisher",
        "fileProductName",
        "determinationType",
        "determinationValue",
    ],
)
def test_analyze_file_info_partial_fields(mock_read_text, secrets_with_key, md5_hash, field_name):
    """Test analyze handles missing individual file info fields."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}"

    file_info = mock_mde_file_info_response()
    del file_info[field_name]

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(md5_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        json=file_info,
        status=200,
    )

    result = engine.analyze(md5_hash, ObservableType.MD5)
    assert result is not None
    assert result[field_name] == "Unknown"


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_file_info_request_failure(mock_read_text, secrets_with_key, md5_hash, caplog):
    """Test analyze returns None when file info request fails."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}/stats"
    file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{md5_hash}"

    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(md5_hash),
        status=200,
    )
    responses.add(
        responses.GET,
        file_info_url,
        status=500,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(md5_hash, ObservableType.MD5)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_ipv4_no_file_info_call(mock_read_text, secrets_with_key, ipv4_observable):
    """Test analyze does not make file info call for non-hash observables."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json=mock_mde_stats_response(ipv4_observable),
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert len(responses.calls) == 1


# ============================================================================
# Priority 6: HTTP Errors & Network Issues (Parametrized - 10 test cases)
# ============================================================================


@responses.activate
@patch("pathlib.Path.read_text")
@pytest.mark.parametrize("status_code", [401, 403, 500, 502, 503])
def test_analyze_http_error_codes(
    mock_read_text, secrets_with_key, ipv4_observable, status_code, caplog
):
    """Test analyze returns None for various HTTP error codes."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        status=status_code,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_connection_timeout(mock_read_text, secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when request times out."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        body=requests.exceptions.Timeout(),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_connection_error(mock_read_text, secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when connection fails."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        body=requests.exceptions.ConnectionError(),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_invalid_json_response(mock_read_text, secrets_with_key, ipv4_observable, caplog):
    """Test analyze returns None when response JSON is invalid."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        body="not valid json",
        status=200,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is None
    assert "Error querying Microsoft Defender for Endpoint" in caplog.text


@responses.activate
@patch("pathlib.Path.read_text")
def test_analyze_response_missing_expected_fields(
    mock_read_text, secrets_with_key, ipv4_observable
):
    """Test analyze handles response with missing expected fields."""
    engine = MDEEngine(secrets_with_key, proxies={}, ssl_verify=True)
    valid_token = create_valid_jwt_token()
    mock_read_text.return_value = valid_token

    stats_url = f"https://api.securitycenter.microsoft.com/api/ips/{ipv4_observable}/stats"
    responses.add(
        responses.GET,
        stats_url,
        json={"status": "ok"},
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None
    assert result["link"] == f"https://security.microsoft.com/ip/{ipv4_observable}/overview"


# ============================================================================
# Priority 7: Export Row Creation (4 tests)
# ============================================================================


def test_create_export_row_all_fields(mde_engine):
    """Test create_export_row with all fields present."""
    analysis_result = {
        "orgFirstSeen": "2024-01-10",
        "orgLastSeen": "2024-01-20",
        "orgPrevalence": 150,
    }
    export = mde_engine.create_export_row(analysis_result)
    assert export["mde_first_seen"] == "2024-01-10"
    assert export["mde_last_seen"] == "2024-01-20"
    assert export["mde_org_prevalence"] == 150


def test_create_export_row_partial_fields(mde_engine):
    """Test create_export_row with some fields missing."""
    analysis_result = {
        "orgFirstSeen": "2024-01-10",
        "orgLastSeen": "2024-01-20",
    }
    export = mde_engine.create_export_row(analysis_result)
    assert export["mde_first_seen"] == "2024-01-10"
    assert export["mde_last_seen"] == "2024-01-20"
    assert export["mde_org_prevalence"] is None


def test_create_export_row_none_input(mde_engine):
    """Test create_export_row with None input."""
    export = mde_engine.create_export_row(None)
    assert export["mde_first_seen"] is None
    assert export["mde_last_seen"] is None
    assert export["mde_org_prevalence"] is None


def test_create_export_row_field_names(mde_engine):
    """Test create_export_row returns correct field names."""
    analysis_result = {
        "orgFirstSeen": "2024-01-10",
        "orgLastSeen": "2024-01-20",
        "orgPrevalence": 150,
    }
    export = mde_engine.create_export_row(analysis_result)
    expected_keys = {"mde_first_seen", "mde_last_seen", "mde_org_prevalence"}
    assert set(export.keys()) == expected_keys


# ============================================================================
# Priority 8: Engine Properties (2 tests)
# ============================================================================


def test_engine_name(mde_engine):
    """Test engine name property."""
    assert mde_engine.name == "mde"


def test_supported_types(mde_engine):
    """Test supported observable types."""
    expected_types = (
        ObservableType.BOGON
        | ObservableType.FQDN
        | ObservableType.IPV4
        | ObservableType.IPV6
        | ObservableType.MD5
        | ObservableType.SHA1
        | ObservableType.SHA256
        | ObservableType.URL
    )
    assert mde_engine.supported_types is expected_types
